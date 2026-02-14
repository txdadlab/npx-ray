import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { scanDependencies } from '../../dist/scanners/dependencies.js';

describe('Dependencies Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-deps-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for package.json with few deps', async () => {
    const dir = join(tmpDir, 'few-deps');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'small-package',
      version: '1.0.0',
      dependencies: {
        lodash: '^4.17.21',
        chalk: '^5.0.0',
      },
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.name, 'dependencies');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('2 direct'));
  });

  it('should flag >20 dependencies as warning', async () => {
    const dir = join(tmpDir, 'many-deps');
    await fs.mkdir(dir, { recursive: true });

    // Build 25 dependencies
    const deps = {};
    for (let i = 0; i < 25; i++) {
      deps[`package-${i}`] = `^1.0.${i}`;
    }

    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'bloated-package',
      version: '1.0.0',
      dependencies: deps,
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, false);
    const countFindings = result.findings.filter(f =>
      f.message.includes('dependency count')
    );
    assert.ok(countFindings.length > 0, 'Should flag high dependency count');
    assert.equal(countFindings[0].severity, 'warning');
  });

  it('should flag >50 dependencies as critical', async () => {
    const dir = join(tmpDir, 'extreme-deps');
    await fs.mkdir(dir, { recursive: true });

    const deps = {};
    for (let i = 0; i < 55; i++) {
      deps[`package-${i}`] = `^1.0.${i}`;
    }

    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'extreme-package',
      version: '1.0.0',
      dependencies: deps,
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, false);
    const countFindings = result.findings.filter(f =>
      f.message.includes('dependency count')
    );
    assert.ok(countFindings.length > 0);
    assert.equal(countFindings[0].severity, 'critical');
  });

  it('should flag wildcard (*) version as critical', async () => {
    const dir = join(tmpDir, 'wildcard');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'unpinned-package',
      version: '1.0.0',
      dependencies: {
        'dangerous-dep': '*',
      },
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, false);
    const wildcardFindings = result.findings.filter(f =>
      f.message.includes('Unpinned')
    );
    assert.ok(wildcardFindings.length > 0, 'Should flag wildcard version');
    assert.equal(wildcardFindings[0].severity, 'critical');
    assert.ok(wildcardFindings[0].message.includes('dangerous-dep'));
  });

  it('should flag "latest" version as critical', async () => {
    const dir = join(tmpDir, 'latest');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'latest-package',
      version: '1.0.0',
      dependencies: {
        'some-dep': 'latest',
      },
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, false);
    const latestFindings = result.findings.filter(f =>
      f.message.includes('Unpinned')
    );
    assert.ok(latestFindings.length > 0, 'Should flag latest version');
    assert.equal(latestFindings[0].severity, 'critical');
  });

  it('should flag empty version string as critical', async () => {
    const dir = join(tmpDir, 'empty-version');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'empty-version-package',
      version: '1.0.0',
      dependencies: {
        'empty-dep': '',
      },
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, false);
    const unpinnedFindings = result.findings.filter(f =>
      f.message.includes('Unpinned')
    );
    assert.ok(unpinnedFindings.length > 0);
    assert.equal(unpinnedFindings[0].severity, 'critical');
  });

  it('should flag git URL dependencies as warning', async () => {
    const dir = join(tmpDir, 'git-deps');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'git-deps-package',
      version: '1.0.0',
      dependencies: {
        'my-lib': 'git+https://github.com/user/repo.git',
      },
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, false);
    const gitFindings = result.findings.filter(f =>
      f.message.includes('Git URL')
    );
    assert.ok(gitFindings.length > 0, 'Should flag git URL dependency');
    assert.equal(gitFindings[0].severity, 'warning');
  });

  it('should include optionalDependencies in count', async () => {
    const dir = join(tmpDir, 'optional');
    await fs.mkdir(dir, { recursive: true });

    const deps = {};
    for (let i = 0; i < 15; i++) {
      deps[`dep-${i}`] = `^1.0.0`;
    }
    const optDeps = {};
    for (let i = 0; i < 10; i++) {
      optDeps[`opt-${i}`] = `^1.0.0`;
    }

    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'opt-package',
      version: '1.0.0',
      dependencies: deps,
      optionalDependencies: optDeps,
    }));

    const result = await scanDependencies(dir);

    // 15 + 10 = 25, which is > 20 threshold
    assert.equal(result.passed, false);
    const countFindings = result.findings.filter(f =>
      f.message.includes('dependency count')
    );
    assert.ok(countFindings.length > 0, 'Should count optional deps too');
  });

  it('should handle missing package.json gracefully', async () => {
    const dir = join(tmpDir, 'no-pkg');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanDependencies(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No package.json'));
  });

  it('should handle package.json with no dependencies field', async () => {
    const dir = join(tmpDir, 'no-deps-field');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'no-deps-package',
      version: '1.0.0',
    }));

    const result = await scanDependencies(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('0 direct'));
  });
});
