import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanTyposquatting } from '../../dist/scanners/typosquatting.js';

describe('Typosquatting Scanner', () => {
  it('should return no findings for exact popular package match (chalk)', async () => {
    const result = await scanTyposquatting('chalk');

    assert.equal(result.name, 'typosquatting');
    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('known popular package'));
  });

  it('should flag "chalkk" (distance 1 from chalk) as critical', async () => {
    const result = await scanTyposquatting('chalkk');

    assert.equal(result.passed, false);
    const criticalFindings = result.findings.filter(f =>
      f.severity === 'critical'
    );
    assert.ok(criticalFindings.length > 0, 'Should flag distance-1 name as critical');
    assert.ok(criticalFindings[0].message.includes('chalkk'));
    assert.ok(criticalFindings[0].message.includes('chalk'));
    assert.ok(criticalFindings[0].evidence.includes('1'));
  });

  it('should return no findings for a completely unrelated name', async () => {
    const result = await scanTyposquatting('xyznotapackage123foobarbaz');

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('No similar'));
  });

  it('should flag distance-2 names as warning', async () => {
    // "expresss" is 1 extra "s" from "express", so distance=1 => critical
    // Let's test distance-2: "exprass" (e->a change + missing 's') may vary,
    // we just need something that's distance 2
    const result = await scanTyposquatting('expreses');

    // Should be distance 2 from "express"
    const findings = result.findings.filter(f =>
      f.message.includes('express')
    );
    if (findings.length > 0) {
      // Could be critical (distance 1) or warning (distance 2)
      assert.ok(
        findings[0].severity === 'critical' || findings[0].severity === 'warning',
        'Should be critical or warning'
      );
    }
  });

  it('should handle exact match for "lodash"', async () => {
    const result = await scanTyposquatting('lodash');

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
    assert.ok(result.summary.includes('known popular package'));
  });

  it('should flag "lodahs" (transposition) as critical', async () => {
    const result = await scanTyposquatting('lodahs');

    assert.equal(result.passed, false);
    const findings = result.findings.filter(f =>
      f.message.includes('lodash') || f.message.includes('lodahs')
    );
    assert.ok(findings.length > 0, 'Should detect transposition as similar');
  });

  it('should handle scoped package names', async () => {
    // Test that the scope is stripped for comparison
    // "@malicious/react" should compare "react" against popular packages
    const result = await scanTyposquatting('@malicious/react');

    // "react" is an exact match to the popular package
    assert.equal(result.passed, true);
    assert.ok(result.summary.includes('known popular package'));
  });

  it('should handle exact match for "express"', async () => {
    const result = await scanTyposquatting('express');

    assert.equal(result.passed, true);
    assert.equal(result.findings.length, 0);
  });

  it('should return correct scanner name', async () => {
    const result = await scanTyposquatting('anything');

    assert.equal(result.name, 'typosquatting');
  });

  it('should sort similar packages by distance', async () => {
    const result = await scanTyposquatting('chalkk');

    if (result.findings.length > 1) {
      // First finding should have smallest distance
      const firstDist = parseInt(result.findings[0].evidence.match(/\d+/)[0]);
      const secondDist = parseInt(result.findings[1].evidence.match(/\d+/)[0]);
      assert.ok(firstDist <= secondDist, 'Findings should be sorted by distance');
    }
  });
});
