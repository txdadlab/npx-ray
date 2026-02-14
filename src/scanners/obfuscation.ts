/**
 * Obfuscation detection scanner.
 *
 * Detects obfuscated code via Shannon entropy analysis, hex-encoded strings,
 * base64 blobs, string array rotation patterns, and suspiciously long lines.
 */

import { promises as fs } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'obfuscation';

/** Extensions to scan. */
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts']);

/** Shannon entropy thresholds. Normal JS: 4.0-5.5. */
const ENTROPY_WARNING = 5.8;
const ENTROPY_CRITICAL = 6.5;

/** Minimum file size to run entropy analysis (skip tiny files). */
const MIN_ENTROPY_SIZE = 256;

/** Consecutive hex escape sequences: \x41\x42\x43\x44 (4+ in a row). */
const HEX_PATTERN = /(\\x[0-9a-fA-F]{2}){4,}/;

/** Base64 string longer than 500 chars. */
const BASE64_PATTERN = /[A-Za-z0-9+/=]{500,}/;

/**
 * Detect large string arrays (>50 elements) — common obfuscation pattern.
 * Uses simple counting instead of regex to avoid catastrophic backtracking.
 */
function hasLargeStringArray(content: string): boolean {
  // Find array openings and count consecutive quoted string elements
  let i = 0;
  while (i < content.length) {
    if (content[i] === '[') {
      let count = 0;
      let j = i + 1;
      while (j < content.length && content[j] !== ']') {
        // Skip whitespace
        while (j < content.length && /\s/.test(content[j])) j++;
        // Check for quoted string
        const q = content[j];
        if (q === '"' || q === "'" || q === '`') {
          j++;
          while (j < content.length && content[j] !== q) {
            if (content[j] === '\\') j++; // skip escaped chars
            j++;
          }
          if (j < content.length) j++; // skip closing quote
          count++;
          // Skip whitespace and comma
          while (j < content.length && /[\s,]/.test(content[j])) j++;
        } else {
          break; // not a string element, stop counting
        }
        if (count > 50) return true;
      }
    }
    i++;
  }
  return false;
}

/** Lines >1000 characters. */
const LONG_LINE_THRESHOLD = 1000;

/**
 * Calculate Shannon entropy of a string.
 * Formula: -sum(p * log2(p)) where p = frequency / total.
 */
function shannonEntropy(data: string): number {
  if (data.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of data) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  const len = data.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Recursively collect all source files from a directory.
 */
async function collectSourceFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true, recursive: true });

  for (const entry of entries) {
    if (!entry.isFile()) continue;

    const ext = extname(entry.name);
    if (!CODE_EXTENSIONS.has(ext)) continue;

    const parentPath = (entry as any).parentPath ?? (entry as any).path ?? dir;
    const fullPath = join(parentPath, entry.name);
    const relPath = relative(dir, fullPath);
    if (relPath.includes('node_modules')) continue;

    files.push(fullPath);
  }

  return files;
}

/**
 * Scan files for obfuscation indicators.
 */
export async function scanObfuscation(pkgDir: string): Promise<ScannerResult> {
  const findings: Finding[] = [];

  let sourceFiles: string[];
  try {
    sourceFiles = await collectSourceFiles(pkgDir);
  } catch {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'No source files found to scan',
    };
  }

  for (const filePath of sourceFiles) {
    const relPath = relative(pkgDir, filePath);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue;
    }

    // Shannon entropy check (whole file)
    if (content.length >= MIN_ENTROPY_SIZE) {
      const entropy = shannonEntropy(content);
      if (entropy >= ENTROPY_CRITICAL) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'critical',
          message: `Very high Shannon entropy: ${entropy.toFixed(2)} (threshold: ${ENTROPY_CRITICAL}) — likely obfuscated`,
          file: relPath,
          evidence: `File entropy: ${entropy.toFixed(2)} bits/char`,
        });
      } else if (entropy >= ENTROPY_WARNING) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'warning',
          message: `Elevated Shannon entropy: ${entropy.toFixed(2)} (threshold: ${ENTROPY_WARNING}) — possible obfuscation`,
          file: relPath,
          evidence: `File entropy: ${entropy.toFixed(2)} bits/char`,
        });
      }
    }

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Hex-encoded strings
      if (HEX_PATTERN.test(line)) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'warning',
          message: 'Hex-encoded string sequences detected',
          file: relPath,
          line: i + 1,
          evidence: line.trim().substring(0, 200),
        });
      }

      // Base64 blobs
      if (BASE64_PATTERN.test(line)) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'warning',
          message: 'Large base64-encoded blob (>500 chars)',
          file: relPath,
          line: i + 1,
          evidence: line.trim().substring(0, 200),
        });
      }

      // Long lines (possible minification)
      if (line.length > LONG_LINE_THRESHOLD) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'info',
          message: `Very long line (${line.length} chars) — possible minification without source maps`,
          file: relPath,
          line: i + 1,
        });
      }
    }

    // String array rotation (check whole file content)
    if (hasLargeStringArray(content)) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'critical',
        message: 'Large string array (>50 elements) — common obfuscation pattern',
        file: relPath,
        evidence: 'String array with 50+ elements detected',
      });
    }
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;
  const passed = criticalCount === 0 && warningCount === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = 'No obfuscation detected';
  } else {
    const parts: string[] = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical`);
    if (warningCount > 0) parts.push(`${warningCount} warning`);
    if (infoCount > 0) parts.push(`${infoCount} info`);
    summary = `Obfuscation indicators: ${parts.join(', ')}`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
