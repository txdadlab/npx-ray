/**
 * npm registry API client for npx-ray.
 *
 * Fetches package metadata from the npm registry, supporting:
 * - Unscoped packages: `chalk`
 * - Scoped packages: `@anthropic-ai/sdk`
 * - Pinned versions: `chalk@5.4.0`
 * - Local tarballs: `./my-package-1.0.0.tgz`
 */

import { createReadStream } from 'node:fs';
import { resolve } from 'node:path';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';

import type { PackageMetadata } from './types.js';

const NPM_REGISTRY = 'https://registry.npmjs.org';

/**
 * Parse a target string into a package name and optional version.
 *
 * Handles scoped packages correctly:
 *   `@scope/name`         -> { name: '@scope/name', version: undefined }
 *   `@scope/name@1.2.3`   -> { name: '@scope/name', version: '1.2.3' }
 *   `lodash`              -> { name: 'lodash', version: undefined }
 *   `lodash@4.17.21`      -> { name: 'lodash', version: '4.17.21' }
 */
function parseTarget(target: string): { name: string; version?: string; isLocal: boolean } {
  // Local tarball detection
  if (
    target.startsWith('./') ||
    target.startsWith('/') ||
    target.startsWith('../') ||
    target.endsWith('.tgz') ||
    target.endsWith('.tar.gz')
  ) {
    return { name: target, isLocal: true };
  }

  // Scoped package: @scope/name or @scope/name@version
  if (target.startsWith('@')) {
    const lastAt = target.lastIndexOf('@');
    // If the only '@' is at position 0, there's no version specifier
    if (lastAt === 0) {
      return { name: target, version: undefined, isLocal: false };
    }
    // '@scope/name@version' — lastAt points to the version separator
    const name = target.slice(0, lastAt);
    const version = target.slice(lastAt + 1);
    return { name, version, isLocal: false };
  }

  // Unscoped package: name or name@version
  const atIndex = target.indexOf('@');
  if (atIndex === -1) {
    return { name: target, version: undefined, isLocal: false };
  }
  const name = target.slice(0, atIndex);
  const version = target.slice(atIndex + 1);
  return { name, version, isLocal: false };
}

/**
 * Extract a package.json from a local .tgz tarball and build minimal metadata.
 *
 * npm tarballs contain files under a `package/` prefix, so the package.json
 * is at `package/package.json`.
 */
async function metadataFromLocalTarball(filePath: string): Promise<PackageMetadata> {
  const absPath = resolve(filePath);
  const chunks: Buffer[] = [];
  let foundPackageJson = false;

  // We'll manually parse the tar stream to find package/package.json.
  // tar v7 uses a stream-based API. We read the gzipped tarball and look for
  // the package.json entry.
  const { Parser } = await import('tar');

  const parser = new Parser({
    filter: (path: string) => {
      // npm tarballs have package/package.json
      return path === 'package/package.json' || path === './package/package.json';
    },
    onReadEntry: (entry) => {
      foundPackageJson = true;
      entry.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });
    },
  });

  const gunzip = createGunzip();
  const fileStream = createReadStream(absPath);

  await pipeline(fileStream, gunzip, parser);

  if (!foundPackageJson || chunks.length === 0) {
    throw new Error(`No package.json found in tarball: ${filePath}`);
  }

  const pkgJson = JSON.parse(Buffer.concat(chunks).toString('utf-8'));

  // Extract repository URL from package.json repository field
  let repositoryUrl = '';
  if (typeof pkgJson.repository === 'string') {
    repositoryUrl = pkgJson.repository;
  } else if (pkgJson.repository?.url) {
    repositoryUrl = pkgJson.repository.url
      .replace(/^git\+/, '')
      .replace(/\.git$/, '');
  }

  // Extract license
  let license = '';
  if (typeof pkgJson.license === 'string') {
    license = pkgJson.license;
  } else if (pkgJson.license?.type) {
    license = pkgJson.license.type;
  }

  return {
    name: pkgJson.name || 'unknown',
    version: pkgJson.version || '0.0.0',
    description: pkgJson.description || '',
    license,
    publisher: pkgJson.author
      ? typeof pkgJson.author === 'string'
        ? pkgJson.author
        : pkgJson.author.name || ''
      : '',
    publishedAt: '',
    tarballUrl: `file://${absPath}`,
    repositoryUrl,
    homepage: pkgJson.homepage || '',
    fileCount: 0,
    unpackedSize: 0,
    dependencies: pkgJson.dependencies || {},
    optionalDependencies: pkgJson.optionalDependencies || {},
    scripts: pkgJson.scripts || {},
    maintainers: pkgJson.maintainers || [],
  };
}

/**
 * Fetch full package metadata from the npm registry.
 *
 * @param target - Package specifier: `name`, `name@version`, or a local tarball path.
 * @returns Resolved package metadata.
 * @throws If the package is not found or the registry request fails.
 */
export async function fetchPackageMetadata(target: string): Promise<PackageMetadata> {
  const { name, version, isLocal } = parseTarget(target);

  // Handle local tarballs
  if (isLocal) {
    return metadataFromLocalTarball(name);
  }

  // Fetch the full packument from the registry.
  // Scoped packages need the scope URL-encoded (@ -> %40, / -> %2f),
  // but npm registry also accepts the raw form for scoped packages.
  const url = `${NPM_REGISTRY}/${encodeURIComponent(name).replace('%40', '@')}`;
  const response = await fetch(url, {
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Package not found: ${name}`);
    }
    throw new Error(
      `npm registry error: ${response.status} ${response.statusText} for ${name}`,
    );
  }

  const packument = (await response.json()) as Record<string, unknown>;

  // Resolve the version
  const distTags = packument['dist-tags'] as Record<string, string> | undefined;
  const resolvedVersion = version || distTags?.latest;

  if (!resolvedVersion) {
    throw new Error(`Cannot determine version for ${name}: no dist-tags.latest found`);
  }

  const versions = packument.versions as Record<string, Record<string, unknown>> | undefined;
  if (!versions) {
    throw new Error(`No versions found in packument for ${name}`);
  }

  const manifest = versions[resolvedVersion];
  if (!manifest) {
    const available = Object.keys(versions).slice(-5).join(', ');
    throw new Error(
      `Version ${resolvedVersion} not found for ${name}. Recent versions: ${available}`,
    );
  }

  // Extract dist info
  const dist = manifest.dist as Record<string, unknown> | undefined;
  const tarballUrl = (dist?.tarball as string) || '';
  const fileCount = (dist?.fileCount as number) || 0;
  const unpackedSize = (dist?.unpackedSize as number) || 0;

  // Extract repository URL
  let repositoryUrl = '';
  const repo = manifest.repository;
  if (typeof repo === 'string') {
    repositoryUrl = repo;
  } else if (repo && typeof repo === 'object') {
    const repoObj = repo as Record<string, unknown>;
    const rawUrl = (repoObj.url as string) || '';
    repositoryUrl = rawUrl
      .replace(/^git\+/, '')
      .replace(/\.git$/, '');
  }

  // Extract license
  let license = '';
  const lic = manifest.license;
  if (typeof lic === 'string') {
    license = lic;
  } else if (lic && typeof lic === 'object') {
    license = (lic as Record<string, unknown>).type as string || '';
  }

  // Extract publisher info and trusted publisher (provenance via OIDC)
  let publisher = '';
  let trustedPublisher: { id: string } | undefined;
  const npmUser = manifest._npmUser as Record<string, unknown> | undefined;
  if (npmUser?.name) {
    publisher = npmUser.name as string;
  }
  if (npmUser?.trustedPublisher && typeof npmUser.trustedPublisher === 'object') {
    const tp = npmUser.trustedPublisher as Record<string, unknown>;
    if (tp.id && typeof tp.id === 'string') {
      trustedPublisher = { id: tp.id };
    }
  }

  // Extract publish date from the time field
  const timeMap = packument.time as Record<string, string> | undefined;
  const publishedAt = timeMap?.[resolvedVersion] || '';

  // Extract maintainers — fall back to packument-level maintainers
  const maintainers =
    (manifest.maintainers as Array<{ name: string; email?: string }>) ||
    (packument.maintainers as Array<{ name: string; email?: string }>) ||
    [];

  return {
    name: (manifest.name as string) || name,
    version: (manifest.version as string) || resolvedVersion,
    description: (manifest.description as string) || '',
    license,
    publisher,
    publishedAt,
    tarballUrl,
    repositoryUrl,
    homepage: (manifest.homepage as string) || '',
    fileCount,
    unpackedSize,
    dependencies: (manifest.dependencies as Record<string, string>) || {},
    optionalDependencies: (manifest.optionalDependencies as Record<string, string>) || {},
    scripts: (manifest.scripts as Record<string, string>) || {},
    maintainers,
    trustedPublisher,
  };
}
