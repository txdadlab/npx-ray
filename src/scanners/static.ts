/**
 * Static analysis scanner.
 *
 * Scans JavaScript/TypeScript source files for dangerous patterns:
 * code execution, network calls, dynamic requires, env access, and
 * dangerous filesystem operations.
 */

import { promises as fs } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'static';

/** Extensions to scan. */
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts']);

/** Test file/directory patterns to skip — these are not runtime code. */
const TEST_DIR_SEGMENTS = ['__tests__', 'tests', 'test', 'fixtures', '__fixtures__', '__mocks__'];

function isTestFile(relPath: string): boolean {
  const segments = relPath.split(/[\\/]/);
  if (segments.some(s => TEST_DIR_SEGMENTS.includes(s))) return true;
  const filename = segments[segments.length - 1];
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(filename)) return true;
  return false;
}

/** Patterns to detect, grouped by category. */
interface Pattern {
  regex: RegExp;
  severity: Finding['severity'];
  message: string;
  /** If true, severity is downgraded to 'info' when the package is a CLI tool. */
  cliExpected?: boolean;
  /** If true, matches inside string literals or comments are downgraded to info.
   *  Used for function-call patterns (eval, exec) that can appear in strings as
   *  documentation or linter rule references. Not used for module-name patterns
   *  (child_process, axios) which are always referenced as strings. */
  checkStringContext?: boolean;
}

const PATTERNS: Pattern[] = [
  // Code execution (critical) — eval/Function stay critical even for CLI tools
  { regex: /\beval\s*\(/, severity: 'critical', message: 'eval() call — arbitrary code execution', checkStringContext: true },
  { regex: /new\s+Function\s*\(/, severity: 'critical', message: 'new Function() — dynamic code generation', checkStringContext: true, cliExpected: true },

  // Shell execution (critical, but expected for CLI tools)
  { regex: /\bchild_process\b/, severity: 'critical', message: 'child_process module — shell command execution', cliExpected: true },
  { regex: /\bexecSync\s*\(/, severity: 'critical', message: 'execSync() — synchronous shell command execution', cliExpected: true, checkStringContext: true },
  { regex: /\bexecFile\s*\(/, severity: 'critical', message: 'execFile() — external program execution', cliExpected: true, checkStringContext: true },
  { regex: /\bspawn\s*\(/, severity: 'critical', message: 'spawn() — child process creation', cliExpected: true, checkStringContext: true },
  // exec() is checked separately to avoid matching execSync/execFile and regex .exec()
  { regex: /(?<!\.)(?<!\w)exec\s*\(/, severity: 'critical', message: 'exec() — shell command execution', cliExpected: true, checkStringContext: true },

  // Network calls (warning, but expected for CLI tools that fetch updates/plugins)
  { regex: /\bfetch\s*\(/, severity: 'warning', message: 'fetch() — network request', checkStringContext: true, cliExpected: true },
  { regex: /\bhttp\.request\b/, severity: 'warning', message: 'http.request — network request', cliExpected: true },
  { regex: /\bhttps\.request\b/, severity: 'warning', message: 'https.request — network request', cliExpected: true },
  { regex: /\bXMLHttpRequest\b/, severity: 'warning', message: 'XMLHttpRequest — network request' },
  { regex: /\baxios\b/, severity: 'warning', message: 'axios — HTTP client', cliExpected: true },
  { regex: /\bgot\s*\(/, severity: 'warning', message: 'got() — HTTP client', checkStringContext: true, cliExpected: true },
  { regex: /\bnode-fetch\b/, severity: 'warning', message: 'node-fetch — HTTP client', cliExpected: true },
  { regex: /\bundici\b/, severity: 'warning', message: 'undici — HTTP client', cliExpected: true },

  // Dynamic requires (warning, but expected for CLI tools that load plugins/configs)
  { regex: /\brequire\s*\(\s*[^'"`\s]/, severity: 'warning', message: 'Dynamic require() — variable module path', checkStringContext: true, cliExpected: true },

  // Env access (info)
  { regex: /\bprocess\.env\b/, severity: 'info', message: 'process.env access — environment variable read' },

  // Dangerous fs operations (warning, but expected for CLI tools that write output/cache)
  { regex: /\bfs\.\s*writeFile/, severity: 'warning', message: 'fs.writeFile — file system write', cliExpected: true },
  { regex: /\bfs\.\s*rm\b/, severity: 'warning', message: 'fs.rm — file system deletion', cliExpected: true },
  { regex: /\bfs\.\s*unlink\b/, severity: 'warning', message: 'fs.unlink — file deletion', cliExpected: true },
];

/**
 * Check whether a regex match at a given index falls inside a string literal
 * or single-line comment. Walks the line tracking quote state.
 * Returns true if the match is inside a string or comment (i.e. not real code).
 */
function isInsideStringOrComment(line: string, matchIndex: number): boolean {
  let inString: string | null = null; // current quote char if inside string
  for (let i = 0; i < matchIndex; i++) {
    const ch = line[i];
    if (inString) {
      if (ch === '\\') { i++; continue; } // skip escaped char
      if (ch === inString) { inString = null; }
    } else {
      if (ch === '"' || ch === "'" || ch === '`') {
        inString = ch;
      } else if (ch === '/' && line[i + 1] === '/') {
        // Rest of line is a comment
        return true;
      }
    }
  }
  return inString !== null;
}

/**
 * Detect whether a package is a CLI tool by checking for a "bin" field
 * in its package.json.
 */
async function isCli(pkgDir: string): Promise<boolean> {
  try {
    const raw = await fs.readFile(join(pkgDir, 'package.json'), 'utf-8');
    const pkg = JSON.parse(raw);
    return pkg.bin !== undefined && pkg.bin !== null;
  } catch {
    return false;
  }
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

    // Skip TypeScript declaration files — they describe types, not runtime code
    if (entry.name.endsWith('.d.ts') || entry.name.endsWith('.d.mts') || entry.name.endsWith('.d.cts')) continue;

    // Build full path — entry.parentPath was added in Node 20, fall back to entry.path
    const parentPath = (entry as any).parentPath ?? (entry as any).path ?? dir;
    const fullPath = join(parentPath, entry.name);

    // Skip node_modules and test files
    const relPath = relative(dir, fullPath);
    if (relPath.includes('node_modules')) continue;
    if (isTestFile(relPath)) continue;

    files.push(fullPath);
  }

  return files;
}

/**
 * Scan all source files for dangerous patterns.
 */
export async function scanStatic(pkgDir: string): Promise<ScannerResult> {
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

  // CLI tools are expected to use child_process/exec/spawn — don't penalize them
  const cliTool = await isCli(pkgDir);

  for (const filePath of sourceFiles) {
    const relPath = relative(pkgDir, filePath);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue; // Skip unreadable files
    }

    const lines = content.split('\n');
    let inBlockComment = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Track block comment state (/* ... */) across lines
      let lineInBlockComment = inBlockComment;
      if (inBlockComment) {
        if (line.includes('*/')) {
          inBlockComment = false;
        }
      }
      if (!lineInBlockComment) {
        // Check if a block comment starts on this line (and doesn't close)
        const stripped = line.replace(/\/\*[\s\S]*?\*\//g, ''); // remove inline /* */
        if (/\/\*/.test(stripped)) {
          inBlockComment = true;
        }
      }

      for (const pattern of PATTERNS) {
        const match = pattern.regex.exec(line);
        if (match) {
          // For exec(), avoid double-counting execSync/execFile
          if (pattern.message.startsWith('exec()')) {
            if (/\bexecSync\s*\(/.test(line) || /\bexecFile\s*\(/.test(line)) {
              continue;
            }
          }

          // For function-call patterns, check if the match is inside a string
          // literal, single-line comment, or block comment. Pattern references
          // in strings/comments (e.g., ESLint's no-eval rule describing "eval()")
          // are not actual code execution. Not applied to module-name patterns
          // (child_process, axios) which naturally appear as string arguments.
          const inStringOrComment = pattern.checkStringContext
            ? (lineInBlockComment || isInsideStringOrComment(line, match.index))
            : false;

          // Downgrade shell execution patterns for CLI tools
          let severity = (cliTool && pattern.cliExpected)
            ? 'info' as Finding['severity']
            : pattern.severity;
          let message = (cliTool && pattern.cliExpected)
            ? `${pattern.message} (expected for CLI tool)`
            : pattern.message;

          if (inStringOrComment && severity !== 'info') {
            severity = 'info';
            message = `${pattern.message} (in string/comment)`;
          }

          findings.push({
            scanner: SCANNER_NAME,
            severity,
            message,
            file: relPath,
            line: i + 1,
            evidence: line.trim().substring(0, 200),
          });
        }
      }
    }
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;
  const passed = criticalCount === 0 && warningCount === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = 'No dangerous patterns detected';
  } else {
    const parts: string[] = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical`);
    if (warningCount > 0) parts.push(`${warningCount} warning`);
    if (infoCount > 0) parts.push(`${infoCount} info`);
    const cliNote = cliTool ? ' (CLI tool — shell execution expected)' : '';
    summary = `Found ${parts.join(', ')} pattern(s) across ${sourceFiles.length} files${cliNote}`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
