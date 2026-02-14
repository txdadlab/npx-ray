/**
 * Dependency analysis scanner.
 *
 * Analyzes package.json dependencies for:
 * - Dependency count (bloat detection)
 * - Git URL dependencies (not pinned to registry)
 * - Wildcard/unpinned version ranges
 */

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'dependencies';

/** Thresholds for dependency count. */
const DEPS_WARNING = 20;
const DEPS_CRITICAL = 50;

/** Patterns that indicate a git URL dependency. */
const GIT_URL_PATTERNS = [
  /^git(\+https?|ssh)?:\/\//,
  /^github:/,
  /^gitlab:/,
  /^bitbucket:/,
  /^https?:\/\/.*\.git$/,
  /^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+/,  // shorthand user/repo
];

/**
 * Scan package.json dependencies.
 */
export async function scanDependencies(pkgDir: string): Promise<ScannerResult> {
  const findings: Finding[] = [];
  const pkgJsonPath = join(pkgDir, 'package.json');

  let pkgJson: Record<string, unknown>;
  try {
    const raw = await fs.readFile(pkgJsonPath, 'utf-8');
    pkgJson = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'No package.json found',
    };
  }

  const deps = (pkgJson.dependencies || {}) as Record<string, string>;
  const optionalDeps = (pkgJson.optionalDependencies || {}) as Record<string, string>;

  const directCount = Object.keys(deps).length;
  const optionalCount = Object.keys(optionalDeps).length;
  const totalCount = directCount + optionalCount;

  // Check dependency count thresholds
  if (totalCount > DEPS_CRITICAL) {
    findings.push({
      scanner: SCANNER_NAME,
      severity: 'critical',
      message: `Extreme dependency count: ${totalCount} dependencies (threshold: ${DEPS_CRITICAL}) — dependency bloat`,
      file: 'package.json',
      evidence: `${directCount} direct + ${optionalCount} optional`,
    });
  } else if (totalCount > DEPS_WARNING) {
    findings.push({
      scanner: SCANNER_NAME,
      severity: 'warning',
      message: `High dependency count: ${totalCount} dependencies (threshold: ${DEPS_WARNING})`,
      file: 'package.json',
      evidence: `${directCount} direct + ${optionalCount} optional`,
    });
  }

  // Check each dependency for issues
  const allDeps = { ...deps, ...optionalDeps };

  for (const [name, version] of Object.entries(allDeps)) {
    if (typeof version !== 'string') continue;

    // Unpinned wildcard
    if (version === '*' || version === '' || version === 'latest') {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'critical',
        message: `Unpinned dependency: ${name}@"${version}" — accepts any version`,
        file: 'package.json',
        evidence: `"${name}": "${version}"`,
      });
      continue;
    }

    // Git URL dependencies
    const isGitUrl = GIT_URL_PATTERNS.some(pattern => pattern.test(version));
    if (isGitUrl) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'warning',
        message: `Git URL dependency: ${name} — not pinned to npm registry`,
        file: 'package.json',
        evidence: `"${name}": "${version}"`,
      });
    }
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const passed = criticalCount === 0 && warningCount === 0;

  let summary = `${directCount} direct, ${optionalCount} optional dependencies`;
  if (criticalCount > 0 || warningCount > 0) {
    const flags: string[] = [];
    if (criticalCount > 0) flags.push(`${criticalCount} critical`);
    if (warningCount > 0) flags.push(`${warningCount} warning`);
    summary += ` (${flags.join(', ')})`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
