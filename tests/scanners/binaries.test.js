import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { scanBinaries } from '../../dist/scanners/binaries.js';

describe('Binaries Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-binaries-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for an empty directory', async () => {
    const dir = join(tmpDir, 'empty');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanBinaries(dir);

    assert.equal(result.name, 'binaries');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No binary files'));
  });

  it('should return no findings for directory with only JS files', async () => {
    const dir = join(tmpDir, 'js-only');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'index.js'), 'console.log("hello");');
    await fs.writeFile(join(dir, 'utils.js'), 'module.exports = {};');

    const result = await scanBinaries(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should detect .node file as warning', async () => {
    const dir = join(tmpDir, 'node-addon');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'addon.node'), Buffer.from([0x00, 0x01, 0x02]));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.ok(result.findings.length > 0);
    assert.equal(result.findings[0].severity, 'warning');
    assert.ok(result.findings[0].message.includes('.node'));
    assert.ok(result.findings[0].message.includes('cannot be source-reviewed'));
  });

  it('should detect .wasm file as warning', async () => {
    const dir = join(tmpDir, 'wasm');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'module.wasm'), Buffer.from([0x00, 0x61, 0x73, 0x6d]));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.ok(result.findings.length > 0);
    assert.equal(result.findings[0].severity, 'warning');
    assert.ok(result.findings[0].message.includes('.wasm'));
  });

  it('should detect .exe file as warning', async () => {
    const dir = join(tmpDir, 'exe');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'tool.exe'), Buffer.from([0x4d, 0x5a]));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.ok(result.findings.length > 0);
    assert.ok(result.findings[0].message.includes('.exe'));
  });

  it('should detect .dll file as warning', async () => {
    const dir = join(tmpDir, 'dll');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'native.dll'), Buffer.from([0x4d, 0x5a]));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.ok(result.findings.length > 0);
    assert.ok(result.findings[0].message.includes('.dll'));
  });

  it('should detect .so file as warning', async () => {
    const dir = join(tmpDir, 'so');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'libcrypto.so'), Buffer.from([0x7f, 0x45, 0x4c, 0x46]));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.ok(result.findings.length > 0);
    assert.ok(result.findings[0].message.includes('.so'));
  });

  it('should detect multiple binary files and summarize', async () => {
    const dir = join(tmpDir, 'multi');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'addon.node'), Buffer.alloc(10));
    await fs.writeFile(join(dir, 'module.wasm'), Buffer.alloc(10));
    await fs.writeFile(join(dir, 'tool.exe'), Buffer.alloc(10));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.equal(result.findings.length, 3);
    assert.ok(result.summary.includes('3 binary file(s)'));
  });

  it('should detect binaries in subdirectories', async () => {
    const dir = join(tmpDir, 'nested');
    const subDir = join(dir, 'build', 'Release');
    await fs.mkdir(subDir, { recursive: true });
    await fs.writeFile(join(subDir, 'binding.node'), Buffer.alloc(10));

    const result = await scanBinaries(dir);

    assert.equal(result.passed, false);
    assert.ok(result.findings.length > 0);
    assert.ok(result.findings[0].file.includes('binding.node'));
  });

  it('should handle nonexistent directory gracefully', async () => {
    const result = await scanBinaries(join(tmpDir, 'nonexistent'));

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });
});
