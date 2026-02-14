/**
 * Binary file scanner.
 *
 * Detects binary and native addon files that cannot be source-reviewed:
 * .node, .so, .dll, .dylib, .exe, .bin, .wasm
 */

import { promises as fs } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'binaries';

/** Binary/native addon extensions to flag. */
const BINARY_EXTENSIONS = new Set([
  '.node',
  '.so',
  '.dll',
  '.dylib',
  '.exe',
  '.bin',
  '.wasm',
]);

/**
 * Scan for binary and native addon files.
 */
export async function scanBinaries(pkgDir: string): Promise<ScannerResult> {
  const findings: Finding[] = [];

  let entries: import('node:fs').Dirent[];
  try {
    entries = await fs.readdir(pkgDir, { withFileTypes: true, recursive: true }) as unknown as import('node:fs').Dirent[];
  } catch {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'Unable to read package directory',
    };
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;

    const ext = extname(entry.name).toLowerCase();
    if (!BINARY_EXTENSIONS.has(ext)) continue;

    const parentPath = (entry as any).parentPath ?? (entry as any).path ?? pkgDir;
    const fullPath = join(parentPath, entry.name);
    const relPath = relative(pkgDir, fullPath);

    // Skip node_modules
    if (relPath.includes('node_modules')) continue;

    findings.push({
      scanner: SCANNER_NAME,
      severity: 'warning',
      message: `Binary file found: ${ext} (cannot be source-reviewed)`,
      file: relPath,
      evidence: entry.name,
    });
  }

  const passed = findings.length === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = 'No binary files found';
  } else {
    const extCounts = new Map<string, number>();
    for (const f of findings) {
      const ext = extname(f.file || '').toLowerCase();
      extCounts.set(ext, (extCounts.get(ext) || 0) + 1);
    }
    const extSummary = [...extCounts.entries()]
      .map(([ext, count]) => `${count} ${ext}`)
      .join(', ');
    summary = `${findings.length} binary file(s): ${extSummary}`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
