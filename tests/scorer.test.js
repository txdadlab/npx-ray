import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { calculateScore } from '../dist/scorer.js';

describe('Scorer', () => {
  /**
   * Helper: create a scanner result with no findings (all pass).
   */
  function cleanResult(name) {
    return {
      name,
      passed: true,
      findings: [],
      summary: 'Clean',
    };
  }

  /**
   * Helper: create all 7 scanner results with no findings.
   */
  function allCleanResults() {
    return [
      cleanResult('static'),
      cleanResult('obfuscation'),
      cleanResult('hooks'),
      cleanResult('secrets'),
      cleanResult('binaries'),
      cleanResult('dependencies'),
      cleanResult('typosquatting'),
    ];
  }

  /**
   * Helper: create a good GitHub health object.
   */
  function goodGitHub() {
    return {
      found: true,
      fullName: 'user/repo',
      stars: 1000,
      forks: 100,
      openIssues: 5,
      license: 'MIT',
      createdAt: '2020-01-01T00:00:00Z',
      lastPush: '2024-01-01T00:00:00Z',
      archived: false,
      publisherMatchesOwner: true,
    };
  }

  it('should return score near 100 for all clean scanners + good GitHub', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();

    const result = calculateScore(scanners, github);

    // Max possible: 25+15+10+5+5+10+5 = 75 (scanners) + 15 (github) = 90
    // With no diff, no diff points are added
    assert.ok(result.score >= 85, `Score should be >= 85, got ${result.score}`);
    assert.ok(result.score <= 100, `Score should be <= 100, got ${result.score}`);
    assert.ok(result.grade === 'A' || result.grade === 'B', `Grade should be A or B, got ${result.grade}`);
    assert.ok(result.verdict.includes('Safe') || result.verdict.includes('CLEAN'));
  });

  it('should return exactly 90 for all clean scanners + good GitHub + no diff', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();

    const result = calculateScore(scanners, github);

    // Scanners max: 25+15+10+5+5+10+5 = 75
    // GitHub max: 15
    // No diff: 0
    // Total = 90
    assert.equal(result.score, 90);
    assert.equal(result.grade, 'A');
  });

  it('should significantly reduce score for critical findings', () => {
    const scanners = allCleanResults();
    // Add a critical finding to the static scanner
    scanners[0] = {
      name: 'static',
      passed: false,
      findings: [
        {
          scanner: 'static',
          severity: 'critical',
          message: 'eval() call',
          file: 'index.js',
          line: 1,
        },
      ],
      summary: 'Found critical patterns',
    };

    const github = goodGitHub();
    const result = calculateScore(scanners, github);

    // Static deduction: 15 points for critical, so static = max(0, 25-15) = 10
    // Total: 10+15+10+5+5+10+5+15 = 75
    assert.equal(result.score, 75);
    assert.equal(result.grade, 'C');
  });

  it('should return 0 GitHub points when no GitHub data', () => {
    const scanners = allCleanResults();

    const result = calculateScore(scanners);

    // Scanners max: 75, no github (0), no diff (0)
    assert.equal(result.score, 75);
    assert.equal(result.grade, 'C');
  });

  it('should return 0 GitHub points when repo not found', () => {
    const scanners = allCleanResults();
    const github = {
      found: false,
      fullName: '',
      stars: 0,
      forks: 0,
      openIssues: 0,
      license: '',
      createdAt: '',
      lastPush: '',
      archived: false,
      publisherMatchesOwner: false,
    };

    const result = calculateScore(scanners, github);

    assert.equal(result.score, 75);
  });

  it('should deduct for archived GitHub repo', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();
    github.archived = true;

    const result = calculateScore(scanners, github);

    // GitHub: 15 - 10 (archived) = 5
    // Total: 75 + 5 = 80
    assert.equal(result.score, 80);
    assert.equal(result.grade, 'B');
  });

  it('should deduct for zero stars', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();
    github.stars = 0;

    const result = calculateScore(scanners, github);

    // GitHub: 15 - 5 (0 stars) = 10
    // Total: 75 + 10 = 85
    assert.equal(result.score, 85);
  });

  it('should deduct for publisher not matching owner', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();
    github.publisherMatchesOwner = false;

    const result = calculateScore(scanners, github);

    // GitHub: 15 - 10 (publisher mismatch) = 5
    // Total: 75 + 5 = 80
    assert.equal(result.score, 80);
  });

  it('should deduct for repo created less than 1 month ago', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();
    // Set created date to yesterday
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    github.createdAt = yesterday.toISOString();

    const result = calculateScore(scanners, github);

    // GitHub: 15 - 5 (new repo) = 10
    // Total: 75 + 10 = 85
    assert.equal(result.score, 85);
  });

  it('should include diff score when diff is performed', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();
    const diff = {
      performed: true,
      unexpectedFiles: [],
      expectedBuildFiles: ['dist/index.js'],
      modifiedFiles: [],
    };

    const result = calculateScore(scanners, github, diff);

    // Scanners: 75, GitHub: 15, Diff: 10 = 100
    assert.equal(result.score, 100);
    assert.equal(result.grade, 'A');
  });

  it('should deduct diff points for unexpected files', () => {
    const scanners = allCleanResults();
    const github = goodGitHub();
    const diff = {
      performed: true,
      unexpectedFiles: ['suspicious.js'],
      expectedBuildFiles: [],
      modifiedFiles: [],
    };

    const result = calculateScore(scanners, github, diff);

    // Diff: 10 - 5*1 = 5
    // Total: 75 + 15 + 5 = 95
    assert.equal(result.score, 95);
  });

  it('should clamp score to 0 minimum', () => {
    // Create scanners with many critical findings to push score below 0
    const scanners = [
      {
        name: 'static',
        passed: false,
        findings: [
          { scanner: 'static', severity: 'critical', message: 'eval' },
          { scanner: 'static', severity: 'critical', message: 'exec' },
          { scanner: 'static', severity: 'critical', message: 'spawn' },
        ],
        summary: 'bad',
      },
      {
        name: 'obfuscation',
        passed: false,
        findings: [
          { scanner: 'obfuscation', severity: 'critical', message: 'obfuscated' },
          { scanner: 'obfuscation', severity: 'critical', message: 'obfuscated2' },
        ],
        summary: 'bad',
      },
      cleanResult('hooks'),
      cleanResult('secrets'),
      cleanResult('binaries'),
      cleanResult('dependencies'),
      cleanResult('typosquatting'),
    ];

    const result = calculateScore(scanners);

    assert.ok(result.score >= 0, 'Score should never be negative');
  });

  it('should return grade F for very low scores', () => {
    const scanners = [
      {
        name: 'static',
        passed: false,
        findings: [
          { scanner: 'static', severity: 'critical', message: 'eval' },
          { scanner: 'static', severity: 'critical', message: 'exec' },
        ],
        summary: 'bad',
      },
      {
        name: 'obfuscation',
        passed: false,
        findings: [
          { scanner: 'obfuscation', severity: 'critical', message: 'obfuscated' },
          { scanner: 'obfuscation', severity: 'critical', message: 'obfuscated2' },
        ],
        summary: 'bad',
      },
      {
        name: 'hooks',
        passed: false,
        findings: [
          { scanner: 'hooks', severity: 'critical', message: 'postinstall curl' },
        ],
        summary: 'bad',
      },
      {
        name: 'secrets',
        passed: false,
        findings: [
          { scanner: 'secrets', severity: 'critical', message: 'AWS key' },
        ],
        summary: 'bad',
      },
      cleanResult('binaries'),
      {
        name: 'dependencies',
        passed: false,
        findings: [
          { scanner: 'dependencies', severity: 'critical', message: 'wildcard' },
        ],
        summary: 'bad',
      },
      {
        name: 'typosquatting',
        passed: false,
        findings: [
          { scanner: 'typosquatting', severity: 'critical', message: 'typosquat' },
        ],
        summary: 'bad',
      },
    ];

    const result = calculateScore(scanners);

    assert.ok(result.score < 60, `Score should be < 60, got ${result.score}`);
    assert.ok(result.grade === 'D' || result.grade === 'F', `Grade should be D or F, got ${result.grade}`);
    assert.ok(result.verdict.includes('RISKY'));
  });

  it('should handle warning findings with smaller deduction', () => {
    const scanners = allCleanResults();
    scanners[0] = {
      name: 'static',
      passed: false,
      findings: [
        {
          scanner: 'static',
          severity: 'warning',
          message: 'fetch() call',
          file: 'index.js',
        },
      ],
      summary: 'Found warning patterns',
    };

    const github = goodGitHub();
    const result = calculateScore(scanners, github);

    // Static: 25 - 5 (warning) = 20
    // Total: 20+15+10+5+5+10+5+15 = 85
    assert.equal(result.score, 85);
  });

  it('should map grades correctly', () => {
    const scanners = allCleanResults();

    // Score = 90 (no github = 75, with good github = 90)
    const resultA = calculateScore(scanners, goodGitHub());
    assert.equal(resultA.grade, 'A');

    // Score = 80 -> B
    const github80 = goodGitHub();
    github80.publisherMatchesOwner = false; // -10 -> 80
    const resultB = calculateScore(scanners, github80);
    assert.equal(resultB.grade, 'B');

    // Score = 75 -> C (no github)
    const resultC = calculateScore(scanners);
    assert.equal(resultC.grade, 'C');
  });
});
