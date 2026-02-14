#!/usr/bin/env node
/**
 * npx-ray CLI — Main entry point.
 *
 * Orchestrates the full scan pipeline: fetch metadata, download tarball,
 * run all security scanners, calculate score, and output the report.
 */

import { Command } from 'commander';
import ora from 'ora';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type {
  ScanReport,
  ScannerResult,
  PackageMetadata,
  GitHubHealth,
  DiffResult,
  McpServerEntry,
} from './types.js';
import { calculateScore } from './scorer.js';
import { reportPretty, reportJson } from './reporter.js';
import { fetchPackageMetadata } from './registry.js';
import { extractPackage } from './extract.js';
import { scanStatic } from './scanners/static.js';
import { scanObfuscation } from './scanners/obfuscation.js';
import { scanHooks } from './scanners/hooks.js';
import { scanSecrets } from './scanners/secrets.js';
import { scanBinaries } from './scanners/binaries.js';
import { scanDependencies } from './scanners/dependencies.js';
import { scanTyposquatting } from './scanners/typosquatting.js';
import { scanIoc } from './scanners/ioc.js';
import { checkGitHubHealth } from './github.js';
import { diffSource } from './diff.js';
import { scanMcpConfigs } from './mcp.js';

const VERSION = '1.0.0';

/**
 * Run the full scan pipeline for a single package.
 */
async function scanPackage(
  target: string,
  options: { json: boolean; verbose: boolean; noGithub: boolean; noDiff: boolean },
): Promise<{ report: ScanReport; exitCode: number }> {
  const startTime = Date.now();
  let tmpDir: string | undefined;

  try {
    // Step 1: Fetch package metadata
    const spinner = ora('Fetching package metadata...').start();
    let meta: PackageMetadata;
    try {
      meta = await fetchPackageMetadata(target);
      spinner.succeed(`Fetched metadata for ${meta.name}@${meta.version}`);
    } catch (err) {
      spinner.fail('Failed to fetch package metadata');
      throw err;
    }

    // Step 2: Download and extract
    const extractSpinner = ora('Downloading and extracting...').start();
    let pkgDir: string;
    try {
      tmpDir = await fs.mkdtemp(join(tmpdir(), 'npx-ray-'));
      pkgDir = await extractPackage(meta.tarballUrl, tmpDir);
      extractSpinner.succeed('Package extracted');
    } catch (err) {
      extractSpinner.fail('Failed to download/extract package');
      throw err;
    }

    // Step 3: Run all scanners in parallel
    const scanSpinner = ora('Running security scans...').start();
    let scanners: ScannerResult[];
    try {
      scanners = await Promise.all([
        scanStatic(pkgDir),
        scanObfuscation(pkgDir),
        scanHooks(pkgDir),
        scanSecrets(pkgDir),
        scanBinaries(pkgDir),
        scanDependencies(pkgDir),
        scanTyposquatting(meta.name),
        scanIoc(pkgDir),
      ]);
      scanSpinner.succeed('Security scans complete');
    } catch (err) {
      scanSpinner.fail('Scanner error');
      throw err;
    }

    // Step 4: Optional GitHub health check
    let github: GitHubHealth | undefined;
    if (!options.noGithub && meta.repositoryUrl) {
      const ghSpinner = ora('Checking GitHub repository...').start();
      try {
        github = await checkGitHubHealth(meta.repositoryUrl, meta.publisher);
        ghSpinner.succeed(github.found ? `GitHub: ${github.fullName}` : 'No GitHub repo found');
      } catch {
        ghSpinner.warn('GitHub check failed');
      }
    }

    // Step 5: Optional source diff
    let diff: DiffResult | undefined;
    if (!options.noDiff && github?.found && meta.repositoryUrl) {
      const diffSpinner = ora('Comparing source with published package...').start();
      try {
        diff = await diffSource(meta.repositoryUrl, pkgDir);
        diffSpinner.succeed(diff.performed ? 'Source diff complete' : 'Source diff skipped');
      } catch {
        diffSpinner.warn('Source diff failed');
      }
    }

    // Step 6: Calculate score
    const { score, grade, verdict } = calculateScore(scanners, github, diff);

    // Step 7: Build report
    const duration = Date.now() - startTime;
    const report: ScanReport = {
      package: meta,
      scanners,
      github,
      diff,
      score,
      grade,
      verdict,
      duration,
    };

    // Step 8: Determine exit code
    let exitCode: number;
    if (grade === 'A' || grade === 'B') {
      exitCode = 0;
    } else if (grade === 'C') {
      exitCode = 1;
    } else {
      exitCode = 2;
    }

    return { report, exitCode };
  } finally {
    // Cleanup temp dir
    if (tmpDir) {
      try {
        await fs.rm(tmpDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup
      }
    }
  }
}

/**
 * Run MCP mode: scan all npm-based MCP servers from editor configs.
 */
async function scanMcpServers(
  options: { json: boolean; verbose: boolean; noGithub: boolean; noDiff: boolean },
): Promise<number> {
  const spinner = ora('Scanning MCP server configurations...').start();
  let servers: McpServerEntry[];
  try {
    servers = await scanMcpConfigs();
    spinner.succeed(`Found ${servers.length} MCP server(s)`);
  } catch (err) {
    spinner.fail('Failed to scan MCP configurations');
    throw err;
  }

  const npmServers = servers.filter(s => s.npmPackage);
  if (npmServers.length === 0) {
    console.log('\nNo npm-based MCP servers found in editor configurations.');
    return 0;
  }

  console.log(`\nScanning ${npmServers.length} npm-based MCP server(s)...\n`);

  let worstExit = 0;
  const allReports: ScanReport[] = [];

  for (const server of npmServers) {
    console.log(`\n${'='.repeat(55)}`);
    console.log(`MCP Server: ${server.name} (${server.npmPackage})`);
    console.log(`Config: ${server.configFile}`);
    if (!server.versionPinned) {
      console.log('\u26a0\ufe0f  Version is NOT pinned');
    }
    console.log('='.repeat(55));

    try {
      const { report, exitCode } = await scanPackage(server.npmPackage!, options);
      allReports.push(report);

      if (options.json) {
        console.log(reportJson(report));
      } else {
        console.log(reportPretty(report, options.verbose));
      }

      if (exitCode > worstExit) {
        worstExit = exitCode;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\nFailed to scan ${server.npmPackage}: ${message}`);
      worstExit = Math.max(worstExit, 2);
    }
  }

  // Summary
  if (!options.json && allReports.length > 1) {
    console.log(`\n${'='.repeat(55)}`);
    console.log('MCP Scan Summary');
    console.log('='.repeat(55));
    for (const report of allReports) {
      console.log(`  ${report.package.name}@${report.package.version}: ${report.grade} (${report.score}/100) - ${report.verdict}`);
    }
  }

  return worstExit;
}

/**
 * Main CLI entry point.
 */
async function main(): Promise<void> {
  const program = new Command();

  program
    .name('npx-ray')
    .description('X-ray vision for npm packages \u2014 security scanner that audits source code, detects obfuscation, and flags supply chain risks before you install')
    .version(VERSION)
    .argument('[package]', 'Package to scan (name, name@version, or local tarball path)')
    .option('--json', 'Output results as JSON', false)
    .option('--verbose', 'Show detailed findings for each scanner', false)
    .option('--mcp', 'Scan MCP servers from editor configurations', false)
    .option('--no-github', 'Skip GitHub repository checks')
    .option('--no-diff', 'Skip source-vs-published diff');

  program.parse();

  const opts = program.opts<{
    json: boolean;
    verbose: boolean;
    mcp: boolean;
    github: boolean;
    diff: boolean;
  }>();

  const packageArg = program.args[0];

  const scanOptions = {
    json: opts.json,
    verbose: opts.verbose,
    noGithub: !opts.github,
    noDiff: !opts.diff,
  };

  // MCP mode
  if (opts.mcp) {
    try {
      const exitCode = await scanMcpServers(scanOptions);
      process.exit(exitCode);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\nError: ${message}`);
      process.exit(2);
    }
    return;
  }

  // Single package mode
  if (!packageArg) {
    program.help();
    return;
  }

  try {
    const { report, exitCode } = await scanPackage(packageArg, scanOptions);

    if (opts.json) {
      console.log(reportJson(report));
    } else {
      console.log(reportPretty(report, opts.verbose));
    }

    process.exit(exitCode);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\nError: ${message}`);
    process.exit(2);
  }
}

main();
