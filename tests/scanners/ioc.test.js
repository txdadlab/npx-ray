import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scanIoc } from '../../dist/scanners/ioc.js';

describe('IOC Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(tmpdir(), 'npx-ray-test-ioc-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for a clean JS file', async () => {
    const dir = join(tmpDir, 'clean');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'index.js'), 'const x = 1 + 2;\nconsole.log(x);\n');

    const result = await scanIoc(dir);
    assert.equal(result.name, 'ioc');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No URLs'));
  });

  it('should extract and defang HTTP URLs', async () => {
    const dir = join(tmpDir, 'urls');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'index.js'), `
      const endpoint = "https://evil.badsite.xyz/payload?q=1";
      fetch(endpoint);
    `);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    const f = result.findings[0];
    assert.equal(f.severity, 'info');
    assert.ok(f.message.includes('hxxps[://]evil[.]badsite[.]xyz/payload?q=1'));
  });

  it('should defang dots in domain but not in path', async () => {
    const dir = join(tmpDir, 'dotpath');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'config.json'), JSON.stringify({
      api: 'https://api.malware.cc/v2/file.exe'
    }));

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    // Domain dots defanged, path dots preserved
    assert.ok(result.findings[0].message.includes('api[.]malware[.]cc/v2/file.exe'));
  });

  it('should extract and defang IPv4 addresses', async () => {
    const dir = join(tmpDir, 'ips');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'config.js'), `
      const server = "45.33.32.156";
      connect(server);
    `);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].message.includes('45[.]33[.]32[.]156'));
  });

  it('should skip localhost and loopback IPs', async () => {
    const dir = join(tmpDir, 'loopback');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'dev.js'), `
      const dev = "127.0.0.1";
      const any = "0.0.0.0";
    `);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 0);
  });

  it('should skip github.com and registry URLs', async () => {
    const dir = join(tmpDir, 'ignored');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'package.json'), JSON.stringify({
      repository: 'https://github.com/user/repo',
      homepage: 'https://registry.npmjs.org/pkg',
    }));

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 0);
  });

  it('should deduplicate repeated URLs', async () => {
    const dir = join(tmpDir, 'dedup');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'a.js'), 'const x = "https://evil.badsite.xyz/a";\n');
    await fs.writeFile(join(dir, 'b.js'), 'const y = "https://evil.badsite.xyz/a";\n');

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].evidence?.includes('2 location'));
  });

  it('should always pass (IOCs are informational)', async () => {
    const dir = join(tmpDir, 'pass');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'bad.js'), `
      fetch("https://evil.badsite.xyz/steal");
      const c2 = "45.33.32.156";
    `);

    const result = await scanIoc(dir);
    assert.equal(result.passed, true);
    assert.ok(result.findings.length > 0);
  });

  it('should handle empty directory', async () => {
    const dir = join(tmpDir, 'empty');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanIoc(dir);
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });
});
