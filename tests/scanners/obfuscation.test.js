import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { scanObfuscation } from '../../dist/scanners/obfuscation.js';

describe('Obfuscation Scanner', () => {
  let tmpDir;

  before(async () => {
    tmpDir = await fs.mkdtemp(join(os.tmpdir(), 'npx-ray-obfuscation-'));
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return no findings for a clean JS file', async () => {
    const dir = join(tmpDir, 'clean');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'index.js'), `
// A normal JavaScript file
function greet(name) {
  return "Hello, " + name + "!";
}

const items = [1, 2, 3, 4, 5];
const doubled = items.map(x => x * 2);
console.log(greet("World"));
console.log(doubled);
`);

    const result = await scanObfuscation(dir);

    assert.equal(result.name, 'obfuscation');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No obfuscation'));
  });

  it('should detect high entropy content as warning or critical', async () => {
    const dir = join(tmpDir, 'high-entropy');
    await fs.mkdir(dir, { recursive: true });

    // Generate a high-entropy string (random-looking characters)
    // Shannon entropy > 6.2 requires a very diverse character distribution
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    let highEntropy = '';
    for (let i = 0; i < 2000; i++) {
      highEntropy += chars[i % chars.length];
    }
    // Shuffle to increase entropy
    highEntropy = highEntropy.split('').sort(() => Math.random() - 0.5).join('');

    // Include hex escapes so it doesn't look like minified code
    const hexPart = '\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64'.repeat(6);
    // Split into multiple lines to avoid triggering looksMinified long-line heuristic
    const lines = [];
    for (let i = 0; i < highEntropy.length; i += 80) {
      lines.push(highEntropy.slice(i, i + 80));
    }
    const content = `_0x${lines.join('\n')}\n${hexPart}`;

    await fs.writeFile(join(dir, 'obfuscated.js'), content);

    const result = await scanObfuscation(dir);

    // Should detect elevated entropy
    const entropyFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('entropy')
    );
    assert.ok(entropyFindings.length > 0, 'Should detect high entropy');
    assert.ok(
      entropyFindings[0].severity === 'warning' || entropyFindings[0].severity === 'critical',
      'Entropy finding should be warning or critical'
    );
  });

  it('should detect hex-encoded strings as warning', async () => {
    const dir = join(tmpDir, 'hex');
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, 'hex.js'), `
var msg = "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64";
console.log(msg);
`);

    const result = await scanObfuscation(dir);

    const hexFindings = result.findings.filter(f =>
      f.message.includes('Hex-encoded')
    );
    assert.ok(hexFindings.length > 0, 'Should detect hex-encoded strings');
    assert.equal(hexFindings[0].severity, 'warning');
  });

  it('should detect large base64 blobs as warning', async () => {
    const dir = join(tmpDir, 'base64');
    await fs.mkdir(dir, { recursive: true });

    // Create a base64 blob > 500 chars
    const base64Blob = Buffer.from('A'.repeat(500)).toString('base64');
    await fs.writeFile(join(dir, 'b64.js'), `
var payload = "${base64Blob}";
atob(payload);
`);

    const result = await scanObfuscation(dir);

    const b64Findings = result.findings.filter(f =>
      f.message.includes('base64')
    );
    assert.ok(b64Findings.length > 0, 'Should detect large base64 blob');
    assert.equal(b64Findings[0].severity, 'warning');
  });

  it('should detect very long lines as info', async () => {
    const dir = join(tmpDir, 'longline');
    await fs.mkdir(dir, { recursive: true });

    const longLine = 'var x = ' + '"a"'.repeat(500) + ';';
    assert.ok(longLine.length > 1000, 'Line should be > 1000 chars');
    await fs.writeFile(join(dir, 'minified.js'), longLine);

    const result = await scanObfuscation(dir);

    const longFindings = result.findings.filter(f =>
      f.message.includes('Very long line')
    );
    assert.ok(longFindings.length > 0, 'Should detect very long lines');
    assert.equal(longFindings[0].severity, 'info');
  });

  it('should handle an empty directory', async () => {
    const dir = join(tmpDir, 'empty');
    await fs.mkdir(dir, { recursive: true });

    const result = await scanObfuscation(dir);

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should skip files smaller than 256 bytes for entropy analysis', async () => {
    const dir = join(tmpDir, 'tiny');
    await fs.mkdir(dir, { recursive: true });
    // Even high-entropy content in a tiny file should not trigger entropy warning
    await fs.writeFile(join(dir, 'small.js'), 'x=1;');

    const result = await scanObfuscation(dir);

    const entropyFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('entropy')
    );
    assert.equal(entropyFindings.length, 0, 'Should not flag entropy on tiny files');
  });

  it('should downgrade minified files to info instead of critical/warning', async () => {
    const dir = join(tmpDir, 'minified');
    await fs.mkdir(dir, { recursive: true });

    // Create content that looks minified: long lines, JS keywords, high entropy
    // but no hex escapes
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    let filler = '';
    for (let i = 0; i < 2000; i++) {
      filler += chars[i % chars.length];
    }
    filler = filler.split('').sort(() => Math.random() - 0.5).join('');

    // Include JS keywords to trigger looksMinified()
    const content = `function minifiedBundle(){var a=1;const b=2;let c=3;if(a){return b}else{for(let i=0;i<c;i++){while(true){class X{}}}}export default function(){import("x")};typeof a;a instanceof b;${filler}}`;
    await fs.writeFile(join(dir, 'bundle.min.js'), content);

    const result = await scanObfuscation(dir);

    const entropyFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('entropy')
    );
    // If entropy is high enough to trigger, it should be info (not critical/warning)
    for (const f of entropyFindings) {
      assert.equal(f.severity, 'info', `Minified file entropy should be info, got ${f.severity}: ${f.message}`);
    }
  });

  it('should downgrade readable string arrays to info (not critical)', async () => {
    const dir = join(tmpDir, 'data-table');
    await fs.mkdir(dir, { recursive: true });

    // Create a file with a large array of readable keyword strings (like bundled parsers)
    const keywords = Array.from({ length: 60 }, (_, i) =>
      `"keyword${String.fromCharCode(65 + (i % 26))}Statement"`
    ).join(',');
    await fs.writeFile(join(dir, 'parser.js'), `var nodeTypes = [${keywords}];\n`);

    const result = await scanObfuscation(dir);

    const arrayFindings = result.findings.filter(f =>
      f.message.includes('string array')
    );
    assert.ok(arrayFindings.length > 0, 'Should detect the large string array');
    assert.equal(arrayFindings[0].severity, 'info', 'Readable string arrays should be info, not critical');
    assert.ok(arrayFindings[0].message.includes('data table'), 'Should identify as data table');
  });

  it('should flag obfuscation-style string arrays as critical', async () => {
    const dir = join(tmpDir, 'obfuscated-array');
    await fs.mkdir(dir, { recursive: true });

    // Create obfuscation pattern: _0x variable + array + rotation function
    const strings = Array.from({ length: 60 }, (_, i) =>
      `"\\x${(i+65).toString(16)}\\x${(i+66).toString(16)}\\x${(i+67).toString(16)}"`
    ).join(',');
    const code = `var _0x1a2b = [${strings}];\n(function(arr,d){var fn=function(n){while(--n){arr.push(arr.shift())}};fn(++d)})(_0x1a2b,0x1e3);\n`;
    await fs.writeFile(join(dir, 'evil.js'), code);

    const result = await scanObfuscation(dir);

    const arrayFindings = result.findings.filter(f =>
      f.message.includes('string array') && f.message.includes('obfuscation')
    );
    assert.ok(arrayFindings.length > 0, 'Should detect obfuscation-style string array');
    assert.equal(arrayFindings[0].severity, 'critical', 'Obfuscation string arrays should be critical');
  });

  it('should skip test files in test directories', async () => {
    const dir = join(tmpDir, 'with-tests');
    await fs.mkdir(join(dir, '__tests__'), { recursive: true });

    // High entropy content in a test file — should be skipped
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    let highEntropy = '';
    for (let i = 0; i < 2000; i++) {
      highEntropy += chars[i % chars.length];
    }
    highEntropy = highEntropy.split('').sort(() => Math.random() - 0.5).join('');
    await fs.writeFile(join(dir, '__tests__', 'obfuscated.js'), `var _0x${highEntropy}`);

    const result = await scanObfuscation(dir);

    assert.equal(result.findings.length, 0, 'Test files should be excluded from obfuscation scanning');
  });
});
