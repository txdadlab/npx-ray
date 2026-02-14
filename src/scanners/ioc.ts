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
  // npm / Node ecosystem
  'registry.npmjs.org',
  'nodejs.org',
  'npmjs.com',
  'www.npmjs.com',
  'docs.npmjs.com',
  'yarnpkg.com',
  'pnpm.io',

  // Code hosting / VCS
  'github.com',
  'raw.githubusercontent.com',
  'gist.github.com',
  'gitlab.com',
  'bitbucket.org',

  // Standards / specs
  'opensource.org',
  'spdx.org',
  'creativecommons.org',
  'www.w3.org',
  'schema.org',
  'json-schema.org',
  'tc39.es',
  'ecma-international.org',
  'whatwg.org',
  'ietf.org',

  // Documentation / reference
  'developer.mozilla.org',
  'mozilla.org',
  'wikipedia.org',
  'en.wikipedia.org',
  'stackoverflow.com',
  'readthedocs.io',
  'docs.rs',

  // JS tooling / frameworks
  'eslint.org',
  'prettier.io',
  'jestjs.io',
  'typescriptlang.org',
  'www.typescriptlang.org',
  'babeljs.io',
  'webpack.js.org',
  'vitejs.dev',
  'rollupjs.org',
  'esbuild.github.io',
  'reactjs.org',
  'react.dev',
  'vuejs.org',
  'angular.io',
  'svelte.dev',
  'nextjs.org',
  'nuxt.com',
  'deno.land',

  // Cloud / SaaS / infrastructure
  'googleapis.com',
  'google.com',
  'www.google.com',
  'cloud.google.com',
  'firebase.google.com',
  'firebaseio.com',
  'microsoft.com',
  'azure.com',
  'windows.net',
  'amazonaws.com',
  'aws.amazon.com',
  'cloudflare.com',
  'cloudflareinsights.com',
  'heroku.com',
  'digitalocean.com',
  'vercel.com',
  'netlify.com',
  'netlify.app',
  'railway.app',
  'render.com',
  'fly.io',
  'supabase.com',
  'supabase.co',

  // AI / ML
  'anthropic.com',
  'openai.com',
  'huggingface.co',
  'cohere.com',

  // Auth / identity
  'auth0.com',
  'okta.com',
  'clerk.dev',
  'clerk.com',

  // Monitoring / analytics / services
  'sentry.io',
  'sentry.dev',
  'datadog.com',
  'newrelic.com',
  'grafana.com',
  'segment.com',
  'mixpanel.com',
  'amplitude.com',
  'logflare.app',

  // Payments / communication
  'stripe.com',
  'twilio.com',
  'sendgrid.com',
  'mailgun.com',
  'postmarkapp.com',

  // Productivity / collaboration
  'linear.app',
  'notion.com',
  'notion.so',
  'slack.com',
  'discord.com',
  'discord.gg',

  // Social media
  'x.com',
  'twitter.com',
  'facebook.com',
  'linkedin.com',
  'youtube.com',

  // Package registries (non-npm)
  'pypi.org',
  'crates.io',
  'rubygems.org',
  'packagist.org',
  'pkg.go.dev',
  'mvnrepository.com',
  'nuget.org',

  // Container / CI
  'docker.com',
  'hub.docker.com',
  'ghcr.io',
  'circleci.com',
  'travis-ci.org',
  'travis-ci.com',

  // Badges / shields
  'shields.io',
  'img.shields.io',
  'badge.fury.io',
  'badgen.net',
  'codecov.io',
  'coveralls.io',
  'david-dm.org',
  'snyk.io',

  // CDNs
  'unpkg.com',
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
  'esm.sh',
  'skypack.dev',

  // Localhost / reserved
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

/** Obfuscation decode method. */
type DecodeMethod = 'hex' | 'unicode' | 'charcode' | 'base64';

/** Tracked IOC with location info. */
interface IocEntry {
  raw: string;
  defanged: string;
  type: 'url' | 'ipv4';
  files: Array<{ file: string; line: number }>;
  decodedFrom?: DecodeMethod;
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

// ── Deobfuscation ──────────────────────────────────────────────────

/** Matches sequences of 4+ hex escapes: \x68\x74\x74\x70 */
const HEX_ESCAPE_SEQ = /(?:\\x[0-9a-fA-F]{2}){4,}/g;

/** Matches sequences of 4+ unicode escapes: \u0068\u0074\u0074\u0070 */
const UNICODE_ESCAPE_SEQ = /(?:\\u[0-9a-fA-F]{4}){4,}/g;

/** Matches String.fromCharCode(104,116,116,112,...) */
const CHAR_CODE_PATTERN = /String\.fromCharCode\s*\(\s*([0-9][0-9,\s]*)\)/gi;

/** Matches base64 blobs ≥ 20 chars (decodes to ≥ 15 bytes). */
const BASE64_BLOB_PATTERN = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

interface DecodedFragment {
  text: string;
  method: DecodeMethod;
}

function decodeHexEscapes(encoded: string): string {
  return encoded.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16)),
  );
}

function decodeUnicodeEscapes(encoded: string): string {
  return encoded.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16)),
  );
}

function decodeCharCodes(codeList: string): string {
  const codes = codeList.split(',').map(s => parseInt(s.trim()));
  if (codes.some(n => isNaN(n) || n < 0 || n > 0x10ffff)) return '';
  try {
    return String.fromCharCode(...codes);
  } catch {
    return '';
  }
}

function tryDecodeBase64(encoded: string): string {
  try {
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
    // Only accept if mostly printable ASCII (URLs are ASCII)
    const printable = decoded.replace(/[^\x20-\x7e]/g, '');
    if (printable.length / decoded.length > 0.8 && decoded.length >= 6) {
      return decoded;
    }
    return '';
  } catch {
    return '';
  }
}

/**
 * Attempt to decode obfuscated content in a line and return decoded fragments.
 */
function extractDecodedFragments(line: string): DecodedFragment[] {
  const fragments: DecodedFragment[] = [];
  let m: RegExpExecArray | null;

  // Hex escapes
  HEX_ESCAPE_SEQ.lastIndex = 0;
  while ((m = HEX_ESCAPE_SEQ.exec(line)) !== null) {
    const decoded = decodeHexEscapes(m[0]);
    if (decoded.length >= 4) {
      fragments.push({ text: decoded, method: 'hex' });
    }
  }

  // Unicode escapes
  UNICODE_ESCAPE_SEQ.lastIndex = 0;
  while ((m = UNICODE_ESCAPE_SEQ.exec(line)) !== null) {
    const decoded = decodeUnicodeEscapes(m[0]);
    if (decoded.length >= 4) {
      fragments.push({ text: decoded, method: 'unicode' });
    }
  }

  // String.fromCharCode
  CHAR_CODE_PATTERN.lastIndex = 0;
  while ((m = CHAR_CODE_PATTERN.exec(line)) !== null) {
    const decoded = decodeCharCodes(m[1]);
    if (decoded.length >= 4) {
      fragments.push({ text: decoded, method: 'charcode' });
    }
  }

  // Base64 blobs
  BASE64_BLOB_PATTERN.lastIndex = 0;
  while ((m = BASE64_BLOB_PATTERN.exec(line)) !== null) {
    const decoded = tryDecodeBase64(m[0]);
    if (decoded) {
      fragments.push({ text: decoded, method: 'base64' });
    }
  }

  return fragments;
}

// ── Main scanner ───────────────────────────────────────────────────

/**
 * Scan all files in a package directory for URLs and IP addresses.
 * Includes a deobfuscation layer that decodes hex escapes, unicode
 * escapes, String.fromCharCode, and base64 before scanning.
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

      // Deobfuscation pass — decode hex/unicode/charcode/base64 and re-scan
      const fragments = extractDecodedFragments(line);
      for (const frag of fragments) {
        // Scan decoded fragment for URLs
        URL_PATTERN.lastIndex = 0;
        while ((match = URL_PATTERN.exec(frag.text)) !== null) {
          const raw = match[0].replace(/[.),'";]+$/, '');
          const domain = extractDomain(raw);
          if (IGNORED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d))) continue;

          const key = raw.toLowerCase();
          if (!iocMap.has(key)) {
            iocMap.set(key, {
              raw,
              defanged: defangUrl(raw),
              type: 'url',
              files: [],
              decodedFrom: frag.method,
            });
          }
          const entry = iocMap.get(key)!;
          if (entry.files.length < 5) {
            entry.files.push({ file: relPath, line: i + 1 });
          }
        }

        // Scan decoded fragment for IPs
        IPV4_PATTERN.lastIndex = 0;
        while ((match = IPV4_PATTERN.exec(frag.text)) !== null) {
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
              decodedFrom: frag.method,
            });
          }
          const entry = iocMap.get(key)!;
          if (entry.files.length < 5) {
            entry.files.push({ file: relPath, line: i + 1 });
          }
        }
      }
    }
  }

  // Convert IOC map to findings
  const urls = [...iocMap.values()].filter(e => e.type === 'url');
  const ips = [...iocMap.values()].filter(e => e.type === 'ipv4');

  for (const ioc of urls) {
    const firstLoc = ioc.files[0];
    const label = ioc.decodedFrom
      ? `URL (${ioc.decodedFrom}-decoded)`
      : 'External URL';
    const evidenceParts: string[] = [];
    if (ioc.decodedFrom) evidenceParts.push(`Decoded from ${ioc.decodedFrom} obfuscation`);
    if (ioc.files.length > 1) evidenceParts.push(`Found in ${ioc.files.length} location(s)`);
    findings.push({
      scanner: SCANNER_NAME,
      severity: ioc.decodedFrom ? 'warning' : 'info',
      message: `${label}: ${ioc.defanged}`,
      file: firstLoc?.file,
      line: firstLoc?.line,
      evidence: evidenceParts.length > 0 ? evidenceParts.join('; ') : undefined,
    });
  }

  for (const ioc of ips) {
    const firstLoc = ioc.files[0];
    const label = ioc.decodedFrom
      ? `IP (${ioc.decodedFrom}-decoded)`
      : 'External IP';
    const evidenceParts: string[] = [];
    if (ioc.decodedFrom) evidenceParts.push(`Decoded from ${ioc.decodedFrom} obfuscation`);
    if (ioc.files.length > 1) evidenceParts.push(`Found in ${ioc.files.length} location(s)`);
    findings.push({
      scanner: SCANNER_NAME,
      severity: ioc.decodedFrom ? 'warning' : 'info',
      message: `${label}: ${ioc.defanged}`,
      file: firstLoc?.file,
      line: firstLoc?.line,
      evidence: evidenceParts.length > 0 ? evidenceParts.join('; ') : undefined,
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
