import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { fetchPackageMetadata } from '../dist/registry.js';
import { extractPackage } from '../dist/extract.js';
import { scanStatic } from '../dist/scanners/static.js';
import { scanObfuscation } from '../dist/scanners/obfuscation.js';
import { scanHooks } from '../dist/scanners/hooks.js';
import { scanSecrets } from '../dist/scanners/secrets.js';
import { scanBinaries } from '../dist/scanners/binaries.js';
import { scanDependencies } from '../dist/scanners/dependencies.js';
import { scanTyposquatting } from '../dist/scanners/typosquatting.js';
import { calculateScore } from '../dist/scorer.js';

describe('Integration: end-to-end scan of chalk', { timeout: 60_000 }, () => {
  let tmpDir;
  let metadata;
  let pkgDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-integration-'));

    // Fetch chalk metadata from npm registry
    metadata = await fetchPackageMetadata('chalk');
    assert.ok(metadata, 'Should fetch metadata');
    assert.equal(metadata.name, 'chalk');
    assert.ok(metadata.version, 'Should have a version');
    assert.ok(metadata.tarballUrl, 'Should have a tarball URL');

    // Download and extract the package
    pkgDir = await extractPackage(metadata.tarballUrl, tmpDir);
    assert.ok(pkgDir, 'Should return package directory');

    // Verify the extracted package directory exists
    const stat = await fs.stat(pkgDir);
    assert.ok(stat.isDirectory(), 'Package dir should be a directory');
  });

  after(async () => {
    if (tmpDir) {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('should have valid package metadata structure', () => {
    assert.equal(typeof metadata.name, 'string');
    assert.equal(typeof metadata.version, 'string');
    assert.equal(typeof metadata.description, 'string');
    assert.equal(typeof metadata.license, 'string');
    assert.equal(typeof metadata.tarballUrl, 'string');
    assert.equal(typeof metadata.dependencies, 'object');
    assert.equal(typeof metadata.scripts, 'object');
    assert.ok(Array.isArray(metadata.maintainers));
  });

  it('should have extracted package.json', async () => {
    const pkgJsonPath = join(pkgDir, 'package.json');
    const pkgJson = JSON.parse(await fs.readFile(pkgJsonPath, 'utf-8'));
    assert.equal(pkgJson.name, 'chalk');
  });

  it('should produce valid static scanner result', async () => {
    const result = await scanStatic(pkgDir);

    assert.equal(result.name, 'static');
    assert.equal(typeof result.passed, 'boolean');
    assert.ok(Array.isArray(result.findings));
    assert.equal(typeof result.summary, 'string');

    for (const finding of result.findings) {
      assert.equal(finding.scanner, 'static');
      assert.ok(['critical', 'warning', 'info'].includes(finding.severity));
      assert.equal(typeof finding.message, 'string');
    }
  });

  it('should produce valid obfuscation scanner result', async () => {
    const result = await scanObfuscation(pkgDir);

    assert.equal(result.name, 'obfuscation');
    assert.equal(typeof result.passed, 'boolean');
    assert.ok(Array.isArray(result.findings));
    assert.equal(typeof result.summary, 'string');
  });

  it('should produce valid hooks scanner result', async () => {
    const result = await scanHooks(pkgDir);

    assert.equal(result.name, 'hooks');
    assert.equal(typeof result.passed, 'boolean');
    assert.ok(Array.isArray(result.findings));
    assert.equal(typeof result.summary, 'string');
  });

  it('should produce valid secrets scanner result', async () => {
    const result = await scanSecrets(pkgDir);

    assert.equal(result.name, 'secrets');
    assert.equal(typeof result.passed, 'boolean');
    assert.ok(Array.isArray(result.findings));
    assert.equal(typeof result.summary, 'string');
  });

  it('should produce valid binaries scanner result', async () => {
    const result = await scanBinaries(pkgDir);

    assert.equal(result.name, 'binaries');
    assert.equal(typeof result.passed, 'boolean');
    assert.ok(Array.isArray(result.findings));
    assert.equal(typeof result.summary, 'string');
  });

  it('should produce valid dependencies scanner result', async () => {
    const result = await scanDependencies(pkgDir);

    assert.equal(result.name, 'dependencies');
    assert.equal(typeof result.passed, 'boolean');
    assert.ok(Array.isArray(result.findings));
    assert.equal(typeof result.summary, 'string');
  });

  it('should produce valid typosquatting scanner result', async () => {
    const result = await scanTyposquatting('chalk');

    assert.equal(result.name, 'typosquatting');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('known popular package'));
  });

  it('should produce a good score for chalk (>= 85)', async () => {
    // Run all scanners
    const scannerResults = await Promise.all([
      scanStatic(pkgDir),
      scanObfuscation(pkgDir),
      scanHooks(pkgDir),
      scanSecrets(pkgDir),
      scanBinaries(pkgDir),
      scanDependencies(pkgDir),
      scanTyposquatting('chalk'),
    ]);

    const scoreResult = calculateScore(scannerResults);

    assert.ok(scoreResult.score >= 60, `chalk should score >= 60, got ${scoreResult.score}`);
    assert.equal(typeof scoreResult.grade, 'string');
    assert.ok(['A', 'B', 'C', 'D', 'F'].includes(scoreResult.grade));
    assert.equal(typeof scoreResult.verdict, 'string');
    assert.ok(scoreResult.verdict.length > 0);
  });

  it('should produce valid JSON-serializable results', async () => {
    const scannerResults = await Promise.all([
      scanStatic(pkgDir),
      scanObfuscation(pkgDir),
      scanHooks(pkgDir),
      scanSecrets(pkgDir),
      scanBinaries(pkgDir),
      scanDependencies(pkgDir),
      scanTyposquatting('chalk'),
    ]);

    const scoreResult = calculateScore(scannerResults);

    const report = {
      package: metadata,
      scanners: scannerResults,
      score: scoreResult.score,
      grade: scoreResult.grade,
      verdict: scoreResult.verdict,
    };

    // Should be JSON-serializable
    const json = JSON.stringify(report);
    assert.ok(json, 'Should serialize to JSON');

    // Should parse back
    const parsed = JSON.parse(json);
    assert.equal(parsed.package.name, 'chalk');
    assert.equal(parsed.scanners.length, 7);
    assert.equal(typeof parsed.score, 'number');
    assert.equal(typeof parsed.grade, 'string');
    assert.equal(typeof parsed.verdict, 'string');

    // Verify all scanner names are present
    const scannerNames = parsed.scanners.map(s => s.name).sort();
    assert.deepEqual(scannerNames, [
      'binaries',
      'dependencies',
      'hooks',
      'obfuscation',
      'secrets',
      'static',
      'typosquatting',
    ]);
  });
});
