/**
 * Secrets scanner.
 *
 * Scans all text files for embedded secrets: API keys, tokens,
 * private keys, credentials in URLs, and provider-specific patterns.
 */

import { promises as fs } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'secrets';

/** Binary file extensions to skip. */
const BINARY_EXTENSIONS = new Set([
  '.node', '.so', '.dll', '.dylib', '.exe', '.bin', '.wasm',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi',
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.ttf', '.otf', '.woff', '.woff2', '.eot',
  '.lock',
]);

/** Secret patterns to detect. */
interface SecretPattern {
  regex: RegExp;
  severity: Finding['severity'];
  message: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS keys (critical)
  {
    regex: /AKIA[0-9A-Z]{16}/,
    severity: 'critical',
    message: 'AWS Access Key ID detected',
  },
  // Private keys (critical)
  {
    regex: /-----BEGIN.*PRIVATE KEY-----/,
    severity: 'critical',
    message: 'Private key detected',
  },
  // GitHub tokens (critical)
  {
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/,
    severity: 'critical',
    message: 'GitHub token detected',
  },
  // npm tokens (critical)
  {
    regex: /npm_[A-Za-z0-9]{36,}/,
    severity: 'critical',
    message: 'npm token detected',
  },
  // Credentials in URLs (critical)
  {
    regex: /https?:\/\/[^:\s]+:[^@\s]+@/,
    severity: 'critical',
    message: 'Embedded credentials in URL',
  },
  // Generic API keys (warning)
  {
    regex: /api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]/i,
    severity: 'warning',
    message: 'Possible API key detected',
  },
  // Generic tokens (warning)
  {
    regex: /token\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]/i,
    severity: 'warning',
    message: 'Possible token/secret detected',
  },
];

/**
 * Check if a file is likely binary by reading the first few hundred bytes.
 */
function isLikelyBinary(buffer: Buffer): boolean {
  // Check for null bytes in the first 512 bytes
  const checkLength = Math.min(buffer.length, 512);
  for (let i = 0; i < checkLength; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

/**
 * Recursively collect all text files from a directory.
 */
async function collectTextFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true, recursive: true });

  for (const entry of entries) {
    if (!entry.isFile()) continue;

    const ext = extname(entry.name).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    const parentPath = (entry as any).parentPath ?? (entry as any).path ?? dir;
    const fullPath = join(parentPath, entry.name);
    const relPath = relative(dir, fullPath);

    // Skip node_modules
    if (relPath.includes('node_modules')) continue;

    files.push(fullPath);
  }

  return files;
}

/**
 * Scan all text files for embedded secrets.
 */
export async function scanSecrets(pkgDir: string): Promise<ScannerResult> {
  const findings: Finding[] = [];

  let textFiles: string[];
  try {
    textFiles = await collectTextFiles(pkgDir);
  } catch {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'No files found to scan',
    };
  }

  for (const filePath of textFiles) {
    const relPath = relative(pkgDir, filePath);

    let buffer: Buffer;
    try {
      buffer = await fs.readFile(filePath);
    } catch {
      continue;
    }

    // Skip binary files
    if (isLikelyBinary(buffer)) continue;

    const content = buffer.toString('utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const pattern of SECRET_PATTERNS) {
        const match = pattern.regex.exec(line);
        if (match) {
          // Mask the actual secret in the evidence
          const rawEvidence = match[0];
          const masked =
            rawEvidence.length > 8
              ? rawEvidence.substring(0, 4) + '****' + rawEvidence.substring(rawEvidence.length - 4)
              : '****';

          findings.push({
            scanner: SCANNER_NAME,
            severity: pattern.severity,
            message: pattern.message,
            file: relPath,
            line: i + 1,
            evidence: masked,
          });
        }
      }
    }
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const passed = criticalCount === 0 && warningCount === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = 'No embedded secrets detected';
  } else {
    const parts: string[] = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical`);
    if (warningCount > 0) parts.push(`${warningCount} warning`);
    summary = `Secrets found: ${parts.join(', ')}`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
