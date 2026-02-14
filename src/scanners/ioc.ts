/**
 * IOC (Indicators of Compromise) scanner.
 *
 * Extracts URLs and IP addresses from package source code and outputs
 * them in defanged format to prevent accidental navigation/resolution.
 *
 * Defanging: http → hxxp, :// → [://], . in domains/IPs → [.]
 */

import { promises as fs } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'ioc';

/** File extensions to scan for IOCs. */
const SCAN_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts',
  '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg',
  '.sh', '.bash', '.bat', '.cmd', '.ps1',
  '.md', '.txt', '.html', '.htm', '.xml',
]);

/** URL pattern — matches http(s) and ftp URLs. */
const URL_PATTERN = /\bhttps?:\/\/[^\s"'`<>\]\)}{,;]+|ftp:\/\/[^\s"'`<>\]\)}{,;]+/g;

/** IPv4 pattern — 4 octets, not inside a longer number sequence. */
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\b/g;

/** Domains/URLs to exclude (common, expected, non-suspicious). */
const IGNORED_DOMAINS = [
  'registry.npmjs.org',
  'nodejs.org',
  'github.com',
  'raw.githubusercontent.com',
  'npmjs.com',
  'www.npmjs.com',
  'docs.npmjs.com',
  'opensource.org',
  'spdx.org',
  'creativecommons.org',
  'shields.io',
  'img.shields.io',
  'badge.fury.io',
  'www.w3.org',
  'schema.org',
  'json-schema.org',
  'tc39.es',
  'developer.mozilla.org',
  'eslint.org',
  'prettier.io',
  'jestjs.io',
  'typescriptlang.org',
  'www.typescriptlang.org',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  'example.com',
  'example.org',
  'example.net',
];

/** IP addresses to exclude (loopback, link-local, documentation). */
const IGNORED_IPS = new Set([
  '127.0.0.1',
  '0.0.0.0',
  '255.255.255.255',
  '192.168.0.1',
  '10.0.0.0',
  '10.0.0.1',
]);

/** Tracked IOC with location info. */
interface IocEntry {
  raw: string;
  defanged: string;
  type: 'url' | 'ipv4';
  files: Array<{ file: string; line: number }>;
}

/**
 * Defang a URL for safe display.
 * - http → hxxp, https → hxxps, ftp → fxp
 * - :// → [://]
 * - dots in domain → [.]
 */
function defangUrl(url: string): string {
  // Split into protocol, domain, and path
  const protoMatch = url.match(/^(https?|ftp):\/\//i);
  if (!protoMatch) {
    // No protocol — just defang all dots
    return url.replace(/\./g, '[.]');
  }

  const proto = protoMatch[1].toLowerCase();
  const afterProto = url.substring(protoMatch[0].length);

  // Defang protocol
  let defangedProto: string;
  if (proto === 'https') defangedProto = 'hxxps';
  else if (proto === 'http') defangedProto = 'hxxp';
  else defangedProto = 'fxp';

  // Split domain from path at first /
  const firstSlash = afterProto.indexOf('/');
  let domain: string;
  let pathPart: string;
  if (firstSlash !== -1) {
    domain = afterProto.substring(0, firstSlash);
    pathPart = afterProto.substring(firstSlash);
  } else {
    domain = afterProto;
    pathPart = '';
  }

  // Defang dots in domain (includes port if present)
  const defangedDomain = domain.replace(/\./g, '[.]');

  return `${defangedProto}[://]${defangedDomain}${pathPart}`;
}

/**
 * Defang an IPv4 address for safe display.
 */
function defangIp(ip: string): string {
  return ip.replace(/\./g, '[.]');
}

/**
 * Extract the domain from a URL string.
 */
function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    // Fallback: grab between :// and next /
    const match = url.match(/:\/\/([^/:]+)/);
    return match ? match[1].toLowerCase() : '';
  }
}

/**
 * Check if a string looks like a version number (e.g., 1.2.3.4).
 */
function looksLikeVersion(str: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(str) && str.split('.').some(n => parseInt(n) > 255);
}

/**
 * Scan all files in a package directory for URLs and IP addresses.
 * Returns them in defanged format.
 */
export async function scanIoc(pkgDir: string): Promise<ScannerResult> {
  const findings: Finding[] = [];
  const iocMap = new Map<string, IocEntry>();

  let entries: string[];
  try {
    const dirEntries = await fs.readdir(pkgDir, { withFileTypes: true, recursive: true });
    entries = [];
    for (const entry of dirEntries) {
      if (!entry.isFile()) continue;
      const ext = extname(entry.name).toLowerCase();
      if (!SCAN_EXTENSIONS.has(ext)) continue;
      const parentPath = (entry as any).parentPath ?? (entry as any).path ?? pkgDir;
      const fullPath = join(parentPath, entry.name);
      const relPath = relative(pkgDir, fullPath);
      if (relPath.includes('node_modules')) continue;
      entries.push(fullPath);
    }
  } catch {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'No files found to scan for IOCs',
    };
  }

  for (const filePath of entries) {
    const relPath = relative(pkgDir, filePath);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Extract URLs
      let match: RegExpExecArray | null;
      URL_PATTERN.lastIndex = 0;
      while ((match = URL_PATTERN.exec(line)) !== null) {
        const raw = match[0].replace(/[.),'";]+$/, ''); // trim trailing punctuation
        const domain = extractDomain(raw);
        if (IGNORED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d))) continue;

        const key = raw.toLowerCase();
        if (!iocMap.has(key)) {
          iocMap.set(key, {
            raw,
            defanged: defangUrl(raw),
            type: 'url',
            files: [],
          });
        }
        const entry = iocMap.get(key)!;
        // Only track up to 5 locations per IOC
        if (entry.files.length < 5) {
          entry.files.push({ file: relPath, line: i + 1 });
        }
      }

      // Extract IPv4 addresses
      IPV4_PATTERN.lastIndex = 0;
      while ((match = IPV4_PATTERN.exec(line)) !== null) {
        const raw = match[0];
        if (IGNORED_IPS.has(raw)) continue;
        if (looksLikeVersion(raw)) continue;

        const key = raw;
        if (!iocMap.has(key)) {
          iocMap.set(key, {
            raw,
            defanged: defangIp(raw),
            type: 'ipv4',
            files: [],
          });
        }
        const entry = iocMap.get(key)!;
        if (entry.files.length < 5) {
          entry.files.push({ file: relPath, line: i + 1 });
        }
      }
    }
  }

  // Convert IOC map to findings
  const urls = [...iocMap.values()].filter(e => e.type === 'url');
  const ips = [...iocMap.values()].filter(e => e.type === 'ipv4');

  for (const ioc of urls) {
    const firstLoc = ioc.files[0];
    findings.push({
      scanner: SCANNER_NAME,
      severity: 'info',
      message: `URL: ${ioc.defanged}`,
      file: firstLoc?.file,
      line: firstLoc?.line,
      evidence: ioc.files.length > 1
        ? `Found in ${ioc.files.length} location(s)`
        : undefined,
    });
  }

  for (const ioc of ips) {
    const firstLoc = ioc.files[0];
    findings.push({
      scanner: SCANNER_NAME,
      severity: 'info',
      message: `IP: ${ioc.defanged}`,
      file: firstLoc?.file,
      line: firstLoc?.line,
      evidence: ioc.files.length > 1
        ? `Found in ${ioc.files.length} location(s)`
        : undefined,
    });
  }

  const passed = true; // IOCs are informational, don't fail the scan

  let summary: string;
  if (findings.length === 0) {
    summary = 'No URLs or IP addresses found';
  } else {
    const parts: string[] = [];
    if (urls.length > 0) parts.push(`${urls.length} URL(s)`);
    if (ips.length > 0) parts.push(`${ips.length} IP(s)`);
    summary = `${parts.join(', ')} extracted (defanged)`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
