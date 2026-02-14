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
    assert.ok(f.message.includes('External URL:'), 'Non-decoded URLs should use "External URL" label');
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
    assert.ok(result.findings[0].message.includes('External IP:'), 'Non-decoded IPs should use "External IP" label');
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

  it('should skip well-known SaaS and cloud domains', async () => {
    const dir = join(tmpDir, 'saas-urls');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'config.js'), `
      const sentry = "https://sentry.io/project/123";
      const api = "https://api.anthropic.com/v1/messages";
      const deploy = "https://vercel.com/dashboard";
      const cdn = "https://cdn.jsdelivr.net/npm/pkg";
      const stripe = "https://api.stripe.com/v1/charges";
      const cloud = "https://us-east-1.amazonaws.com/bucket";
      const openai = "https://api.openai.com/v1/chat";
    `);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 0, 'Well-known SaaS domains should be filtered');
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

  // ── Deobfuscation tests ──────────────────────────────────────────

  it('should detect URLs hidden in hex escapes', async () => {
    const dir = join(tmpDir, 'hex');
    await fs.mkdir(dir, { recursive: true });
    // "https://evil.badsite.xyz/steal" as hex escapes
    const hexUrl = Array.from(Buffer.from('https://evil.badsite.xyz/steal'))
      .map(b => '\\x' + b.toString(16).padStart(2, '0'))
      .join('');
    await fs.writeFile(join(dir, 'mal.js'), `const c2 = "${hexUrl}";\n`);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].message.includes('hex-decoded'));
    assert.ok(result.findings[0].message.includes('hxxps[://]evil[.]badsite[.]xyz/steal'));
    assert.equal(result.findings[0].severity, 'warning');
    assert.ok(result.findings[0].evidence?.includes('hex obfuscation'));
  });

  it('should detect URLs hidden in unicode escapes', async () => {
    const dir = join(tmpDir, 'unicode');
    await fs.mkdir(dir, { recursive: true });
    const unicodeUrl = Array.from('https://evil.badsite.xyz')
      .map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
      .join('');
    await fs.writeFile(join(dir, 'mal.js'), `const url = "${unicodeUrl}";\n`);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].message.includes('unicode-decoded'));
    assert.ok(result.findings[0].message.includes('hxxps[://]evil[.]badsite[.]xyz'));
    assert.equal(result.findings[0].severity, 'warning');
  });

  it('should detect URLs hidden in String.fromCharCode', async () => {
    const dir = join(tmpDir, 'charcode');
    await fs.mkdir(dir, { recursive: true });
    const codes = Array.from('https://evil.badsite.xyz/c2')
      .map(c => c.charCodeAt(0))
      .join(',');
    await fs.writeFile(join(dir, 'mal.js'), `const url = String.fromCharCode(${codes});\n`);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].message.includes('charcode-decoded'));
    assert.ok(result.findings[0].message.includes('hxxps[://]evil[.]badsite[.]xyz/c2'));
    assert.equal(result.findings[0].severity, 'warning');
  });

  it('should detect URLs hidden in base64', async () => {
    const dir = join(tmpDir, 'b64');
    await fs.mkdir(dir, { recursive: true });
    const b64 = Buffer.from('https://evil.badsite.xyz/payload').toString('base64');
    await fs.writeFile(join(dir, 'mal.js'), `const ep = atob("${b64}");\n`);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].message.includes('base64-decoded'));
    assert.ok(result.findings[0].message.includes('hxxps[://]evil[.]badsite[.]xyz/payload'));
    assert.equal(result.findings[0].severity, 'warning');
  });

  it('should detect IPs hidden in hex escapes', async () => {
    const dir = join(tmpDir, 'hexip');
    await fs.mkdir(dir, { recursive: true });
    const hexIp = Array.from(Buffer.from('45.33.32.156'))
      .map(b => '\\x' + b.toString(16).padStart(2, '0'))
      .join('');
    await fs.writeFile(join(dir, 'mal.js'), `const srv = "${hexIp}";\n`);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].message.includes('hex-decoded'));
    assert.ok(result.findings[0].message.includes('45[.]33[.]32[.]156'));
    assert.equal(result.findings[0].severity, 'warning');
  });

  it('should not flag base64 that decodes to non-URL content', async () => {
    const dir = join(tmpDir, 'b64clean');
    await fs.mkdir(dir, { recursive: true });
    // "Hello World!!!!!" — no URL in decoded content
    const b64 = Buffer.from('Hello World!!!!!').toString('base64');
    await fs.writeFile(join(dir, 'clean.js'), `const msg = atob("${b64}");\n`);

    const result = await scanIoc(dir);
    assert.equal(result.findings.length, 0);
  });

  it('should deduplicate plaintext and decoded versions of same URL', async () => {
    const dir = join(tmpDir, 'dedup-decode');
    await fs.mkdir(dir, { recursive: true });
    const hexUrl = Array.from(Buffer.from('https://evil.badsite.xyz/dup'))
      .map(b => '\\x' + b.toString(16).padStart(2, '0'))
      .join('');
    await fs.writeFile(join(dir, 'mal.js'), [
      `const a = "https://evil.badsite.xyz/dup";`,
      `const b = "${hexUrl}";`,
    ].join('\n'));

    const result = await scanIoc(dir);
    // Same URL — should be deduplicated to 1 finding
    assert.equal(result.findings.length, 1);
    // Plaintext found first, so should be 'info' not 'warning'
    assert.equal(result.findings[0].severity, 'info');
  });
});
