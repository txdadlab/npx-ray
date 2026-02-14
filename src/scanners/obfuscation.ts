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

/** Shannon entropy thresholds. Normal JS: 4.0-5.5, minified: 5.5-6.2. */
const ENTROPY_WARNING = 6.2;
const ENTROPY_CRITICAL = 6.8;

/** Test file/directory patterns to skip — these are not runtime code. */
const TEST_DIR_SEGMENTS = ['__tests__', 'tests', 'test', 'fixtures', '__fixtures__', '__mocks__'];

function isTestFile(relPath: string): boolean {
  const segments = relPath.split(/[\\/]/);
  if (segments.some(s => TEST_DIR_SEGMENTS.includes(s))) return true;
  const filename = segments[segments.length - 1];
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(filename)) return true;
  return false;
}

/**
 * Heuristic: does the file look like minified (not obfuscated) code?
 * Minified code has long lines and retains JS keywords but lacks heavy hex escapes.
 */
function looksMinified(content: string): boolean {
  const lines = content.split('\n');
  const hasLongLines = lines.some(l => l.length > 500);
  if (!hasLongLines) return false;

  // Check for JS keywords that survive minification
  const jsKeywords = /\b(function|return|var|let|const|if|else|for|while|class|export|import|typeof|instanceof)\b/;
  const hasKeywords = jsKeywords.test(content);

  // Check for heavy hex escapes (obfuscation indicator)
  const hexMatches = content.match(/(\\x[0-9a-fA-F]{2}){4,}/g);
  const heavyHex = hexMatches !== null && hexMatches.length > 5;

  return hasKeywords && !heavyHex;
}

/** Minimum file size to run entropy analysis (skip tiny files). */
const MIN_ENTROPY_SIZE = 256;

/** Consecutive hex escape sequences: \x41\x42\x43\x44 (4+ in a row). */
const HEX_PATTERN = /(\\x[0-9a-fA-F]{2}){4,}/;

/** Base64 string longer than 500 chars. */
const BASE64_PATTERN = /[A-Za-z0-9+/=]{500,}/;

/**
 * Result from large string array detection.
 * - 'obfuscated': array looks like obfuscation (short/encoded strings, rotation pattern)
 * - 'data': array is a data table (readable strings like keywords, identifiers)
 * - false: no large string array found
 */
type StringArrayResult = 'obfuscated' | 'data' | false;

/**
 * Detect large string arrays (>50 elements) and classify them.
 *
 * Obfuscation arrays have short/encoded strings and often a rotation function.
 * Data tables in bundled code have readable strings (keywords, identifiers, etc.).
 */
function detectLargeStringArray(content: string): StringArrayResult {
  let found: StringArrayResult = false;

  let i = 0;
  while (i < content.length) {
    if (content[i] === '[') {
      const strings: string[] = [];
      let j = i + 1;
      while (j < content.length && content[j] !== ']') {
        // Skip whitespace
        while (j < content.length && /\s/.test(content[j])) j++;
        // Check for quoted string
        const q = content[j];
        if (q === '"' || q === "'" || q === '`') {
          const start = j + 1;
          j++;
          while (j < content.length && content[j] !== q) {
            if (content[j] === '\\') j++; // skip escaped chars
            j++;
          }
          if (j < content.length) {
            // Collect up to 60 strings for analysis
            if (strings.length < 60) {
              strings.push(content.slice(start, j));
            }
            j++; // skip closing quote
          }
          // Skip whitespace and comma
          while (j < content.length && /[\s,]/.test(content[j])) j++;
        } else {
          break; // not a string element, stop counting
        }
        if (strings.length > 50 && found === false) {
          // Classify this array
          found = classifyStringArray(strings, content, i, j);
        }
      }
      // Final check if we exited the loop exactly at 50
      if (strings.length > 50 && found === false) {
        found = classifyStringArray(strings, content, i, j);
      }
      // If we found obfuscation, return immediately
      if (found === 'obfuscated') return 'obfuscated';
    }
    i++;
  }
  return found;
}

/**
 * Classify a large string array as obfuscation or data table.
 */
function classifyStringArray(
  strings: string[],
  content: string,
  arrayStart: number,
  arrayEnd: number,
): StringArrayResult {
  // Check for rotation pattern near the array (push + shift = obfuscation)
  const windowAfter = content.slice(arrayEnd, arrayEnd + 500);
  const hasRotation = /\.\s*push\s*\(/.test(windowAfter) && /\.\s*shift\s*\(/.test(windowAfter);

  // Check for obfuscator-style variable name (_0x...) before the array
  const windowBefore = content.slice(Math.max(0, arrayStart - 50), arrayStart);
  const hasObfuscatorVar = /_0x[0-9a-fA-F]+\s*=\s*$/.test(windowBefore);

  // If rotation + obfuscator var name, definitely obfuscation
  if (hasRotation && hasObfuscatorVar) return 'obfuscated';

  // Check string content readability
  const avgLen = strings.reduce((sum, s) => sum + s.length, 0) / strings.length;

  // Readable: string contains at least one letter and no hex/unicode escape sequences
  const readableCount = strings.filter(s =>
    /[a-zA-Z]/.test(s) && !/(\\x[0-9a-fA-F]{2}){2,}/.test(s) && !/(\\u[0-9a-fA-F]{4}){2,}/.test(s)
  ).length;
  const readableRatio = readableCount / strings.length;

  // If rotation pattern present, it's obfuscation regardless of readability
  if (hasRotation) return 'obfuscated';

  // Data tables: strings are partially readable and reasonably sized.
  // Bundled parsers/compilers often have arrays mixing keywords with short
  // symbol tokens, so a moderate readability threshold (>=30%) is appropriate.
  if (readableRatio >= 0.3 && avgLen >= 2) return 'data';

  // No rotation + very low readability — still suspicious but without
  // the rotation pattern it's not classic obfuscation. Treat as data.
  // (The entropy scanner will catch truly obfuscated content separately.)
  return 'data';
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
    if (isTestFile(relPath)) continue;

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
      const minified = looksMinified(content);

      if (entropy >= ENTROPY_CRITICAL) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: minified ? 'info' : 'critical',
          message: minified
            ? `High Shannon entropy: ${entropy.toFixed(2)} (threshold: ${ENTROPY_CRITICAL}) — appears to be minified code`
            : `Very high Shannon entropy: ${entropy.toFixed(2)} (threshold: ${ENTROPY_CRITICAL}) — likely obfuscated`,
          file: relPath,
          evidence: `File entropy: ${entropy.toFixed(2)} bits/char`,
        });
      } else if (entropy >= ENTROPY_WARNING) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: minified ? 'info' : 'warning',
          message: minified
            ? `Elevated Shannon entropy: ${entropy.toFixed(2)} (threshold: ${ENTROPY_WARNING}) — appears to be minified code`
            : `Elevated Shannon entropy: ${entropy.toFixed(2)} (threshold: ${ENTROPY_WARNING}) — possible obfuscation`,
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

    // Large string array detection (check whole file content)
    const arrayResult = detectLargeStringArray(content);
    if (arrayResult === 'obfuscated') {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'critical',
        message: 'Large string array (>50 elements) with obfuscation markers',
        file: relPath,
        evidence: 'String array with 50+ elements and rotation/encoding detected',
      });
    } else if (arrayResult === 'data') {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'info',
        message: 'Large string array (>50 elements) — appears to be a data table',
        file: relPath,
        evidence: 'String array with 50+ readable elements (keywords, identifiers, etc.)',
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
