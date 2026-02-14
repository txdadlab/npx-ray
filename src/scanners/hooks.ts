/**
 * Lifecycle hooks scanner.
 *
 * Checks package.json for lifecycle scripts (preinstall, postinstall, etc.)
 * that could execute arbitrary code during npm install.
 */

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'hooks';

/** Lifecycle scripts that run automatically and are security-sensitive. */
const DANGEROUS_HOOKS = new Set([
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'uninstall',
  'postuninstall',
]);

/** Shell commands that elevate a lifecycle script to critical severity. */
const SHELL_COMMANDS = [
  'curl',
  'wget',
  'bash',
  'sh -c',
  'node -e',
  'powershell',
  'cmd /c',
];

/**
 * Scan package.json for lifecycle hook scripts.
 */
export async function scanHooks(pkgDir: string): Promise<ScannerResult> {
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

  const scripts = pkgJson.scripts as Record<string, string> | undefined;
  if (!scripts || typeof scripts !== 'object') {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'No scripts defined',
    };
  }

  for (const [name, command] of Object.entries(scripts)) {
    if (typeof command !== 'string') continue;

    // Handle 'prepare' script — info only (common for build steps)
    if (name === 'prepare') {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'info',
        message: `"prepare" script defined: ${command}`,
        file: 'package.json',
        evidence: command,
      });
      continue;
    }

    // Only flag dangerous lifecycle hooks
    if (!DANGEROUS_HOOKS.has(name)) continue;

    // Check if the script contains shell commands (elevates to critical)
    const hasShellCommand = SHELL_COMMANDS.some(cmd =>
      command.toLowerCase().includes(cmd.toLowerCase()),
    );

    if (hasShellCommand) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'critical',
        message: `"${name}" script executes shell commands: ${command}`,
        file: 'package.json',
        evidence: command,
      });
    } else {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'warning',
        message: `"${name}" lifecycle script defined: ${command}`,
        file: 'package.json',
        evidence: command,
      });
    }
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const passed = criticalCount === 0 && warningCount === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = 'No lifecycle hooks found';
  } else {
    const hookNames = findings
      .filter(f => f.severity !== 'info')
      .map(f => {
        const match = f.message.match(/^"(\w+)"/);
        return match ? match[1] : '';
      })
      .filter(Boolean);

    if (hookNames.length > 0) {
      summary = `Lifecycle hooks: ${hookNames.join(', ')}`;
      if (criticalCount > 0) summary += ` (${criticalCount} with shell commands)`;
    } else {
      summary = 'Only benign lifecycle hooks (prepare)';
    }
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
