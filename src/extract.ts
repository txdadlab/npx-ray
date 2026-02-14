/**
 * Tarball download and extraction for npx-ray.
 *
 * Downloads an npm package tarball and extracts it to a temporary directory.
 * Supports both remote URLs (https://) and local file paths (file:// or absolute).
 */

import { join, isAbsolute } from 'node:path';
import { Readable } from 'node:stream';

import * as tar from 'tar';

/**
 * Download a tarball and extract it to the destination directory.
 *
 * npm tarballs always contain files under a `package/` prefix, so the
 * extracted content will be at `<destDir>/package/`.
 *
 * @param tarballUrl - URL to fetch (https://) or local path (file:// or absolute).
 * @param destDir    - Directory to extract into.
 * @returns Absolute path to the extracted `package/` directory.
 */
export async function extractPackage(tarballUrl: string, destDir: string): Promise<string> {
  if (isLocalPath(tarballUrl)) {
    await extractFromLocal(tarballUrl, destDir);
  } else {
    await extractFromRemote(tarballUrl, destDir);
  }

  return join(destDir, 'package');
}

/**
 * Determine if the tarball URL points to a local file.
 */
function isLocalPath(tarballUrl: string): boolean {
  return (
    tarballUrl.startsWith('file://') ||
    isAbsolute(tarballUrl) ||
    tarballUrl.startsWith('./') ||
    tarballUrl.startsWith('../')
  );
}

/**
 * Resolve a local tarball path from various formats to an absolute path.
 */
function resolveLocalPath(tarballUrl: string): string {
  if (tarballUrl.startsWith('file://')) {
    // file:///absolute/path or file://relative/path
    return tarballUrl.slice(7);
  }
  return tarballUrl;
}

/**
 * Extract a tarball from a local file path.
 */
async function extractFromLocal(tarballUrl: string, destDir: string): Promise<void> {
  const filePath = resolveLocalPath(tarballUrl);

  await tar.extract({
    file: filePath,
    cwd: destDir,
  });
}

/**
 * Download and extract a tarball from a remote URL.
 */
async function extractFromRemote(tarballUrl: string, destDir: string): Promise<void> {
  const response = await fetch(tarballUrl);

  if (!response.ok) {
    throw new Error(
      `Failed to download tarball: ${response.status} ${response.statusText} from ${tarballUrl}`,
    );
  }

  if (!response.body) {
    throw new Error('Response body is empty');
  }

  // Convert the web ReadableStream to a Node.js Readable so tar can consume it.
  const nodeStream = Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);

  await new Promise<void>((resolve, reject) => {
    const extractor = tar.extract({ cwd: destDir });

    nodeStream
      .pipe(extractor)
      .on('finish', () => resolve())
      .on('error', (err: Error) => reject(err));

    nodeStream.on('error', (err: Error) => reject(err));
  });
}
