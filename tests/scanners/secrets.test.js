import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { scanSecrets } from '../../dist/scanners/secrets.js';

describe('Secrets Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-secrets-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for a clean file', async () => {
    const dir = join(tmpDir, 'clean');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'index.js'), `
const greeting = "Hello, World!";
console.log(greeting);
`);

    const result = await scanSecrets(dir);

    assert.equal(result.name, 'secrets');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No embedded secrets'));
  });

  it('should detect AWS Access Key ID as critical', async () => {
    const dir = join(tmpDir, 'aws-key');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'config.js'), `
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
`);

    const result = await scanSecrets(dir);

    assert.equal(result.passed, false);
    const awsFindings = result.findings.filter(f =>
      f.message.includes('AWS Access Key')
    );
    assert.ok(awsFindings.length > 0, 'Should detect AWS key');
    assert.equal(awsFindings[0].severity, 'critical');
    // Evidence should be masked
    assert.ok(awsFindings[0].evidence.includes('****'), 'Evidence should be masked');
  });

  it('should detect private key as critical', async () => {
    const dir = join(tmpDir, 'private-key');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'key.pem'), `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBh1ckhKBi94jn2oVYhSH
-----END RSA PRIVATE KEY-----`);

    const result = await scanSecrets(dir);

    assert.equal(result.passed, false);
    const keyFindings = result.findings.filter(f =>
      f.message.includes('Private key')
    );
    assert.ok(keyFindings.length > 0, 'Should detect private key');
    assert.equal(keyFindings[0].severity, 'critical');
  });

  it('should detect GitHub personal access token as critical', async () => {
    const dir = join(tmpDir, 'github-token');
    await fs.mkdir(dir, { recursive: true });
    // ghp_ tokens are 36+ alphanumeric chars
    await fs.writeFile(join(dir, 'deploy.js'), `
const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
`);

    const result = await scanSecrets(dir);

    assert.equal(result.passed, false);
    const ghFindings = result.findings.filter(f =>
      f.message.includes('GitHub token')
    );
    assert.ok(ghFindings.length > 0, 'Should detect GitHub token');
    assert.equal(ghFindings[0].severity, 'critical');
  });

  it('should detect npm token as critical', async () => {
    const dir = join(tmpDir, 'npm-token');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, '.npmrc'), `
//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
`);

    const result = await scanSecrets(dir);

    assert.equal(result.passed, false);
    const npmFindings = result.findings.filter(f =>
      f.message.includes('npm token')
    );
    assert.ok(npmFindings.length > 0, 'Should detect npm token');
    assert.equal(npmFindings[0].severity, 'critical');
  });

  it('should detect credentials in URLs as critical', async () => {
    const dir = join(tmpDir, 'url-creds');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'db.js'), `
const DB_URL = "https://admin:secretpassword@db.example.com:5432/mydb";
`);

    const result = await scanSecrets(dir);

    assert.equal(result.passed, false);
    const urlFindings = result.findings.filter(f =>
      f.message.includes('credentials in URL')
    );
    assert.ok(urlFindings.length > 0, 'Should detect embedded credentials in URL');
    assert.equal(urlFindings[0].severity, 'critical');
  });

  it('should skip binary files', async () => {
    const dir = join(tmpDir, 'binary');
    await fs.mkdir(dir, { recursive: true });
    // Write a binary file with null bytes
    const buffer = Buffer.alloc(256);
    buffer.write('AKIAIOSFODNN7EXAMPLE');
    buffer[100] = 0; // null byte makes it binary
    await fs.writeFile(join(dir, 'data.dat'), buffer);

    const result = await scanSecrets(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should skip files with binary extensions', async () => {
    const dir = join(tmpDir, 'binary-ext');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'image.png'), 'AKIAIOSFODNN7EXAMPLE');

    const result = await scanSecrets(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should handle empty directory', async () => {
    const dir = join(tmpDir, 'empty');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanSecrets(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should detect generic API key pattern as warning', async () => {
    const dir = join(tmpDir, 'generic-api-key');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'config.js'), `
const api_key = "abcdefghijklmnopqrstuvwxyz12345";
`);

    const result = await scanSecrets(dir);

    const apiKeyFindings = result.findings.filter(f =>
      f.message.includes('API key')
    );
    assert.ok(apiKeyFindings.length > 0, 'Should detect generic API key');
    assert.equal(apiKeyFindings[0].severity, 'warning');
  });
});
