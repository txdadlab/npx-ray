/**
 * Output formatting for npx-ray scan results.
 *
 * Provides both human-readable (chalk-colored) and machine-readable (JSON)
 * output formats for scan reports.
 */

import chalk from 'chalk';
import type { ScanReport, ScannerResult, Finding } from './types.js';

/** Format bytes into a human-readable string. */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Format milliseconds into a human-readable duration. */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = (ms / 1000).toFixed(1);
  return `${seconds}s`;
}

/** Get the status icon for a scanner result. */
function statusIcon(result: ScannerResult): string {
  const hasCritical = result.findings.some(f => f.severity === 'critical');
  const hasWarning = result.findings.some(f => f.severity === 'warning');

  if (hasCritical) return chalk.red('\u274c');
  if (hasWarning) return chalk.yellow('\u26a0\ufe0f');
  return chalk.green('\u2705');
}

/** Get the colored label for a severity level. */
function severityLabel(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical':
      return chalk.red.bold('CRITICAL');
    case 'warning':
      return chalk.yellow('WARNING');
    case 'info':
      return chalk.blue('INFO');
  }
}

/** Color a score based on its grade. */
function colorScore(score: number, grade: string): string {
  const label = `${score}/100 (${grade})`;
  switch (grade) {
    case 'A':
    case 'B':
      return chalk.green.bold(label);
    case 'C':
      return chalk.yellow.bold(label);
    case 'D':
    case 'F':
      return chalk.red.bold(label);
    default:
      return label;
  }
}

/** Color a verdict string based on its prefix. */
function colorVerdict(verdict: string): string {
  if (verdict.startsWith('CLEAN')) return chalk.green.bold(verdict);
  if (verdict.startsWith('CAUTION')) return chalk.yellow.bold(verdict);
  if (verdict.startsWith('DANGER')) return chalk.red.bold(verdict);
  return chalk.bold(verdict);
}

/** Capitalize the first letter of a scanner name for display. */
function scannerDisplayName(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

/**
 * Render a finding as a single line for verbose output.
 */
function renderFinding(finding: Finding): string {
  const location = finding.file
    ? finding.line
      ? chalk.dim(` ${finding.file}:${finding.line}`)
      : chalk.dim(` ${finding.file}`)
    : '';
  return `    ${severityLabel(finding.severity)} ${finding.message}${location}`;
}

/**
 * Render a scanner section in the pretty report.
 */
function renderScannerSection(result: ScannerResult, verbose: boolean): string {
  const lines: string[] = [];
  const icon = statusIcon(result);
  const name = scannerDisplayName(result.name);

  lines.push(`  ${icon} ${chalk.bold(name)}: ${result.summary}`);

  if (verbose && result.findings.length > 0) {
    for (const finding of result.findings) {
      lines.push(renderFinding(finding));
    }
  }

  return lines.join('\n');
}

/**
 * Generate a human-readable, chalk-colored report.
 *
 * @param report  - The complete scan report.
 * @param verbose - Whether to show individual findings.
 * @returns Formatted string ready for console output.
 */
export function reportPretty(report: ScanReport, verbose: boolean): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(chalk.cyan.bold('npx-ray v1.0.0 \u2014 X-ray vision for npm packages'));
  lines.push(chalk.dim('\u2500'.repeat(55)));

  // Package info block
  const pkg = report.package;
  lines.push('');
  lines.push(chalk.bold('Package: ') + `${pkg.name}@${pkg.version}`);
  lines.push(chalk.bold('Publisher: ') + (pkg.publisher || chalk.dim('unknown')));
  lines.push(chalk.bold('Published: ') + (pkg.publishedAt || chalk.dim('unknown')));
  lines.push(chalk.bold('License: ') + (pkg.license || chalk.dim('none')));
  lines.push(chalk.bold('Files: ') + pkg.fileCount.toString());
  lines.push(chalk.bold('Size: ') + formatBytes(pkg.unpackedSize));

  // Risk score
  lines.push('');
  lines.push(chalk.dim('\u2500'.repeat(55)));
  lines.push(`  Risk Score: ${colorScore(report.score, report.grade)}`);
  lines.push(chalk.dim('\u2500'.repeat(55)));

  // Scanner sections
  lines.push('');
  lines.push(chalk.bold.underline('Scan Results'));
  lines.push('');

  for (const result of report.scanners) {
    lines.push(renderScannerSection(result, verbose));
  }

  // GitHub section
  if (report.github) {
    lines.push('');
    lines.push(chalk.bold.underline('GitHub'));
    lines.push('');

    const gh = report.github;
    if (!gh.found) {
      lines.push(`  ${chalk.yellow('\u26a0\ufe0f')} No GitHub repository found`);
    } else {
      const repoIcon = gh.archived ? chalk.yellow('\u26a0\ufe0f') : chalk.green('\u2705');
      lines.push(`  ${repoIcon} ${chalk.bold('Repository:')} ${gh.fullName}`);
      lines.push(`    Stars: ${gh.stars} | Forks: ${gh.forks} | Open Issues: ${gh.openIssues}`);
      lines.push(`    Created: ${gh.createdAt} | Last Push: ${gh.lastPush}`);
      if (gh.archived) {
        lines.push(`    ${chalk.yellow('Repository is archived')}`);
      }
      if (!gh.publisherMatchesOwner) {
        lines.push(`    ${chalk.yellow('npm publisher does not match GitHub owner')}`);
      }
    }
  }

  // Diff section
  if (report.diff) {
    lines.push('');
    lines.push(chalk.bold.underline('Source Diff'));
    lines.push('');

    const diff = report.diff;
    if (!diff.performed) {
      lines.push(`  ${chalk.dim('\u2014')} Diff not performed${diff.error ? `: ${diff.error}` : ''}`);
    } else if (diff.unexpectedFiles.length === 0 && diff.modifiedFiles.length === 0) {
      lines.push(`  ${chalk.green('\u2705')} Source matches published package`);
    } else {
      if (diff.unexpectedFiles.length > 0) {
        lines.push(`  ${chalk.red('\u274c')} ${diff.unexpectedFiles.length} unexpected file(s) in npm package:`);
        if (verbose) {
          for (const file of diff.unexpectedFiles) {
            lines.push(`    ${chalk.red('\u2022')} ${file}`);
          }
        }
      }
      if (diff.modifiedFiles.length > 0) {
        lines.push(`  ${chalk.yellow('\u26a0\ufe0f')} ${diff.modifiedFiles.length} modified file(s):`);
        if (verbose) {
          for (const file of diff.modifiedFiles) {
            lines.push(`    ${chalk.yellow('\u2022')} ${file}`);
          }
        }
      }
    }
  }

  // Final verdict
  lines.push('');
  lines.push(chalk.dim('\u2500'.repeat(55)));
  lines.push(`  Verdict: ${colorVerdict(report.verdict)}`);
  lines.push(chalk.dim('\u2500'.repeat(55)));

  // Duration
  lines.push('');
  lines.push(chalk.dim(`Scan completed in ${formatDuration(report.duration)}`));
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate a machine-readable JSON report.
 *
 * @param report - The complete scan report.
 * @returns Pretty-printed JSON string.
 */
export function reportJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
