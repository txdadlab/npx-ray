import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { scanStatic } from '../../dist/scanners/static.js';

describe('Static Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-static-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for a clean JS file', async () => {
    const dir = join(tmpDir, 'clean');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'index.js'), `
const x = 1 + 2;
console.log(x);
function add(a, b) { return a + b; }
module.exports = { add };
`);

    const result = await scanStatic(dir);

    assert.equal(result.name, 'static');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No dangerous patterns'));
  });

  it('should detect eval() as critical', async () => {
    const dir = join(tmpDir, 'eval');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'bad.js'), `
const code = "console.log('hi')";
eval(code);
`);

    const result = await scanStatic(dir);

    assert.equal(result.passed, false);
    const evalFindings = result.findings.filter(f => f.message.includes('eval()'));
    assert.ok(evalFindings.length > 0, 'Should find eval() pattern');
    assert.equal(evalFindings[0].severity, 'critical');
    assert.equal(evalFindings[0].scanner, 'static');
    assert.ok(evalFindings[0].file.includes('bad.js'));
    assert.ok(evalFindings[0].line > 0);
  });

  it('should detect fetch() as warning', async () => {
    const dir = join(tmpDir, 'fetch');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'net.js'), `
const data = await fetch("https://example.com/api");
console.log(data);
`);

    const result = await scanStatic(dir);

    assert.equal(result.passed, false);
    const fetchFindings = result.findings.filter(f => f.message.includes('fetch()'));
    assert.ok(fetchFindings.length > 0, 'Should find fetch() pattern');
    assert.equal(fetchFindings[0].severity, 'warning');
  });

  it('should NOT flag .exec() regex method (false positive avoidance)', async () => {
    const dir = join(tmpDir, 'regex-exec');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'regex.js'), `
const pattern = /hello/;
const match = pattern.exec("hello world");
console.log(match);
`);

    const result = await scanStatic(dir);

    // The regex .exec() should NOT trigger the exec() pattern
    // because the pattern uses (?<!\.) negative lookbehind
    const execFindings = result.findings.filter(
      f => f.message.startsWith('exec()')
    );
    assert.equal(execFindings.length, 0, 'Should not flag regex .exec() as exec()');
  });

  it('should detect dynamic require() as warning', async () => {
    const dir = join(tmpDir, 'dynamic-require');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'dyn.js'), `
const modName = "fs";
const mod = require(modName);
`);

    const result = await scanStatic(dir);

    assert.equal(result.passed, false);
    const reqFindings = result.findings.filter(f =>
      f.message.includes('Dynamic require()')
    );
    assert.ok(reqFindings.length > 0, 'Should find dynamic require() pattern');
    assert.equal(reqFindings[0].severity, 'warning');
  });

  it('should detect child_process as critical', async () => {
    const dir = join(tmpDir, 'child-proc');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'cmd.js'), `
const { exec } = require('child_process');
exec('ls -la');
`);

    const result = await scanStatic(dir);

    assert.equal(result.passed, false);
    const cpFindings = result.findings.filter(f =>
      f.message.includes('child_process')
    );
    assert.ok(cpFindings.length > 0, 'Should detect child_process');
    assert.equal(cpFindings[0].severity, 'critical');
  });

  it('should detect process.env as info', async () => {
    const dir = join(tmpDir, 'env-access');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'env.js'), `
const apiKey = process.env.API_KEY;
`);

    const result = await scanStatic(dir);

    // Info-level findings do not cause failure
    assert.equal(result.passed, true);
    const envFindings = result.findings.filter(f =>
      f.message.includes('process.env')
    );
    assert.ok(envFindings.length > 0, 'Should detect process.env access');
    assert.equal(envFindings[0].severity, 'info');
  });

  it('should only scan .js/.mjs/.cjs/.ts files', async () => {
    const dir = join(tmpDir, 'non-code');
    await fs.mkdir(dir, { recursive: true });
    // Write eval in a .txt file - should be ignored
    await fs.writeFile(join(dir, 'notes.txt'), 'eval("dangerous")');
    await fs.writeFile(join(dir, 'data.json'), '{"eval": true}');

    const result = await scanStatic(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should handle an empty directory', async () => {
    const dir = join(tmpDir, 'empty');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanStatic(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should handle a nonexistent directory gracefully', async () => {
    const result = await scanStatic(join(tmpDir, 'does-not-exist'));

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });
});
