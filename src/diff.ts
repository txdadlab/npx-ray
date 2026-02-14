/**
 * Source-vs-npm diff comparison for npx-ray.
 *
 * Downloads the GitHub source and compares it against the published npm
 * package to detect unexpected files, injected code, or modified sources
 * that don't match the repository.
 */

import { createHash } from 'node:crypto';
import { readFile, readdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, extname } from 'node:path';
import { Readable } from 'node:stream';

import * as tar from 'tar';

import type { DiffResult } from './types.js';

const GITHUB_API = 'https://api.github.com';
const USER_AGENT = 'npx-ray/1.0.0';

/** Directories whose contents are expected build artifacts in npm packages. */
const BUILD_DIR_PREFIXES = [
  'dist/', 'lib/', 'build/', '.next/', 'out/',
  'prebuilds/', 'compiled/', 'esm/', 'cjs/',
];

/**
 * Files that commonly differ between source and published package
 * and should be skipped during content comparison.
 */
const SKIP_CONTENT_COMPARE = new Set([
  'package.json',
  '.npmignore',
  '.gitignore',
  'npm-shrinkwrap.json',
]);

/**
 * Parse a GitHub repository URL into an owner/repo pair.
 *
 * Handles the same formats as github.ts:
 *   - https://github.com/owner/repo
 *   - https://github.com/owner/repo.git
 *   - git+https://github.com/owner/repo.git
 *   - git://github.com/owner/repo.git
 *   - github:owner/repo
 */
function parseGitHubUrl(repoUrl: string): { owner: string; repo: string } | null {
  let url = repoUrl.trim().replace(/\/+$/, '');

  if (url.startsWith('github:')) {
    const path = url.slice('github:'.length);
    const parts = path.split('/');
    if (parts.length >= 2) {
      return { owner: parts[0], repo: parts[1].replace(/\.git$/, '') };
    }
    return null;
  }

  if (url.startsWith('git+')) {
    url = url.slice(4);
  }

  if (url.startsWith('git://')) {
    url = 'https://' + url.slice(6);
  }

  try {
    const parsed = new URL(url);
    if (parsed.hostname !== 'github.com') {
      return null;
    }

    const segments = parsed.pathname.split('/').filter(Boolean);
    if (segments.length < 2) {
      return null;
    }

    return {
      owner: segments[0],
      repo: segments[1].replace(/\.git$/, ''),
    };
  } catch {
    return null;
  }
}

/**
 * Recursively collect all file paths under a directory.
 *
 * @returns Array of relative file paths (forward-slash separated).
 */
async function collectFiles(dir: string): Promise<string[]> {
  const results: string[] = [];

  async function walk(current: string): Promise<void> {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        // Skip hidden dirs (e.g., .git) and node_modules
        if (entry.name.startsWith('.') || entry.name === 'node_modules') {
          continue;
        }
        await walk(fullPath);
      } else if (entry.isFile()) {
        const rel = relative(dir, fullPath).replace(/\\/g, '/');
        results.push(rel);
      }
    }
  }

  await walk(dir);
  return results;
}

/**
 * Compute the SHA-256 hash of a file.
 */
async function hashFile(filePath: string): Promise<string> {
  const content = await readFile(filePath);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Check whether a file is an expected build artifact.
 *
 * A file is considered an expected build artifact if:
 * - It resides under a known build directory (dist/, lib/, build/, .next/, out/)
 * - It's a .js file and a corresponding .ts file exists in the source
 */
function isExpectedBuildFile(
  filePath: string,
  repoFiles: Set<string>,
): boolean {
  // Check build directory prefixes
  for (const prefix of BUILD_DIR_PREFIXES) {
    if (filePath.startsWith(prefix)) {
      return true;
    }
  }

  // Check if it's a compiled JS/MJS/CJS file with a corresponding TS source
  const ext = extname(filePath);
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    const base = filePath.replace(/\.(js|mjs|cjs)$/, '');
    if (repoFiles.has(base + '.ts') || repoFiles.has(base + '.tsx') ||
        repoFiles.has(base + '.mts') || repoFiles.has(base + '.cts') ||
        repoFiles.has('src/' + base + '.ts') || repoFiles.has('src/' + base + '.tsx')) {
      return true;
    }
  }

  // TypeScript declaration files are always build artifacts
  if (filePath.endsWith('.d.ts') || filePath.endsWith('.d.mts') || filePath.endsWith('.d.cts')) {
    return true;
  }

  // Source maps are build artifacts
  if (filePath.endsWith('.map')) {
    return true;
  }

  // Native addon binaries (.node) are build artifacts
  if (filePath.endsWith('.node')) {
    return true;
  }

  return false;
}

/**
 * Find the root directory inside an extracted GitHub tarball.
 *
 * GitHub tarballs extract to a directory named `{owner}-{repo}-{sha}/`.
 * This function finds that top-level directory.
 */
async function findTarballRoot(extractDir: string): Promise<string> {
  const entries = await readdir(extractDir, { withFileTypes: true });
  const dirs = entries.filter(e => e.isDirectory());

  if (dirs.length === 1) {
    return join(extractDir, dirs[0].name);
  }

  // If there's no single root directory, use the extract dir itself
  return extractDir;
}

/**
 * Compare the published npm package against its GitHub source.
 *
 * Downloads the repository source as a tarball from GitHub, extracts it,
 * and compares file lists and content hashes against the npm package
 * directory.
 *
 * @param repoUrl - Repository URL from the npm package metadata.
 * @param pkgDir  - Path to the extracted npm package directory.
 * @returns Diff results including unexpected files, build files, and modified files.
 */
export async function diffSource(
  repoUrl: string,
  pkgDir: string,
): Promise<DiffResult> {
  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return {
      performed: false,
      unexpectedFiles: [],
      expectedBuildFiles: [],
      modifiedFiles: [],
      error: 'Could not parse GitHub URL',
    };
  }

  const { owner, repo } = parsed;
  let tmpDir: string | undefined;

  try {
    // Download the source tarball from GitHub
    const tarballUrl = `${GITHUB_API}/repos/${owner}/${repo}/tarball/HEAD`;
    const response = await fetch(tarballUrl, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/vnd.github.v3+json',
      },
      redirect: 'follow',
    });

    if (!response.ok) {
      return {
        performed: false,
        unexpectedFiles: [],
        expectedBuildFiles: [],
        modifiedFiles: [],
        error: `GitHub tarball download failed: ${response.status} ${response.statusText}`,
      };
    }

    if (!response.body) {
      return {
        performed: false,
        unexpectedFiles: [],
        expectedBuildFiles: [],
        modifiedFiles: [],
        error: 'Empty response body from GitHub',
      };
    }

    // Extract to a temp directory
    tmpDir = await mkdtemp(join(tmpdir(), 'npx-ray-diff-'));

    const nodeStream = Readable.fromWeb(
      response.body as import('node:stream/web').ReadableStream,
    );

    await new Promise<void>((resolve, reject) => {
      const extractor = tar.extract({ cwd: tmpDir! });

      nodeStream
        .pipe(extractor)
        .on('finish', () => resolve())
        .on('error', (err: Error) => reject(err));

      nodeStream.on('error', (err: Error) => reject(err));
    });

    // Find the root of the extracted source
    const repoDir = await findTarballRoot(tmpDir);

    // Collect file lists from both directories
    const [npmFiles, repoFilesList] = await Promise.all([
      collectFiles(pkgDir),
      collectFiles(repoDir),
    ]);

    const repoFilesSet = new Set(repoFilesList);
    const npmFilesSet = new Set(npmFiles);

    // Classify files in npm but not in repo
    const unexpectedFiles: string[] = [];
    const expectedBuildFiles: string[] = [];

    for (const file of npmFiles) {
      if (!repoFilesSet.has(file)) {
        if (isExpectedBuildFile(file, repoFilesSet)) {
          expectedBuildFiles.push(file);
        } else {
          unexpectedFiles.push(file);
        }
      }
    }

    // Compare content of files that exist in both
    const modifiedFiles: string[] = [];

    for (const file of npmFiles) {
      if (!repoFilesSet.has(file)) {
        continue;
      }

      // Skip files that are known to differ
      if (SKIP_CONTENT_COMPARE.has(file)) {
        continue;
      }

      const npmFilePath = join(pkgDir, file);
      const repoFilePath = join(repoDir, file);

      try {
        const [npmHash, repoHash] = await Promise.all([
          hashFile(npmFilePath),
          hashFile(repoFilePath),
        ]);

        if (npmHash !== repoHash) {
          modifiedFiles.push(file);
        }
      } catch {
        // If we can't read either file, skip it
      }
    }

    return {
      performed: true,
      unexpectedFiles,
      expectedBuildFiles,
      modifiedFiles,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      performed: false,
      unexpectedFiles: [],
      expectedBuildFiles: [],
      modifiedFiles: [],
      error: `Diff failed: ${message}`,
    };
  } finally {
    // Clean up temp directory
    if (tmpDir) {
      try {
        await rm(tmpDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup
      }
    }
  }
}
