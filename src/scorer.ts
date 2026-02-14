/**
 * Risk scoring engine for npx-ray.
 *
 * Aggregates findings from all scanners into a single 0-100 score,
 * a letter grade, and a human-readable verdict.
 */

import type { ScannerResult, GitHubHealth, DiffResult, PackageMetadata } from './types.js';

export interface ScoreResult {
  /** Aggregate risk score (0 = dangerous, 100 = clean). */
  score: number;
  /** Letter grade: A, B, C, D, or F. */
  grade: string;
  /** Human-readable verdict string. */
  verdict: string;
}

/**
 * Category weight configuration.
 * Each category starts at its max points and deducts based on findings.
 */
interface CategoryConfig {
  maxPoints: number;
  criticalDeduction: number;
  warningDeduction: number;
  infoDeduction: number;
}

const CATEGORY_WEIGHTS: Record<string, CategoryConfig> = {
  static:        { maxPoints: 25, criticalDeduction: 15, warningDeduction: 5,  infoDeduction: 0 },
  obfuscation:   { maxPoints: 15, criticalDeduction: 10, warningDeduction: 10, infoDeduction: 3 },
  hooks:         { maxPoints: 10, criticalDeduction: 10, warningDeduction: 5,  infoDeduction: 0 },
  secrets:       { maxPoints: 5,  criticalDeduction: 5,  warningDeduction: 5,  infoDeduction: 0 },
  binaries:      { maxPoints: 5,  criticalDeduction: 3,  warningDeduction: 3,  infoDeduction: 1 },
  dependencies:  { maxPoints: 10, criticalDeduction: 10, warningDeduction: 5,  infoDeduction: 0 },
  typosquatting: { maxPoints: 5,  criticalDeduction: 5,  warningDeduction: 5,  infoDeduction: 0 },
};

/**
 * Score a single scanner category by deducting from max points based on
 * the severity of each finding.
 *
 * Uses diminishing returns: deduction = base * (1 + ln(count))
 * so many findings still hurt, but don't instantly zero out the category.
 * A single finding deducts the base amount (ln(1) = 0).
 */
function scoreCategory(result: ScannerResult): number {
  const config = CATEGORY_WEIGHTS[result.name];
  if (!config) {
    // Unknown scanner category — no score contribution
    return 0;
  }

  // Count findings by severity
  let criticalCount = 0;
  let warningCount = 0;
  let infoCount = 0;

  for (const finding of result.findings) {
    switch (finding.severity) {
      case 'critical': criticalCount++; break;
      case 'warning': warningCount++; break;
      case 'info': infoCount++; break;
    }
  }

  // Diminishing returns: base * (1 + ln(count))
  function diminishing(base: number, count: number): number {
    if (count === 0) return 0;
    return base * (1 + Math.log(count));
  }

  let points = config.maxPoints;
  points -= diminishing(config.criticalDeduction, criticalCount);
  points -= diminishing(config.warningDeduction, warningCount);
  points -= diminishing(config.infoDeduction, infoCount);

  return Math.max(0, points);
}

/**
 * Score GitHub repository health.
 * Max 15 points. Returns 0 if no repo found.
 *
 * @param github - GitHub health data.
 * @param hasProvenance - Whether the package has npm trusted publisher provenance.
 */
function scoreGitHub(github?: GitHubHealth, hasProvenance?: boolean): number {
  if (!github || !github.found) {
    return 0;
  }

  let points = 15;

  if (github.archived) {
    points -= 10;
  }

  if (github.stars === 0) {
    points -= 5;
  }

  // Check if repo is less than 1 month old
  const createdDate = new Date(github.createdAt);
  const oneMonthAgo = new Date();
  oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
  if (createdDate > oneMonthAgo) {
    points -= 5;
  }

  if (!github.publisherMatchesOwner) {
    if (hasProvenance) {
      // Trusted publisher (OIDC provenance) fully explains the mismatch —
      // CI published the package, not a human. No penalty.
      points -= 0;
    } else if (github.stars >= 100) {
      // Popular repos with publisher mismatch are less suspicious
      points -= 3;
    } else {
      points -= 10;
    }
  }

  return Math.max(0, points);
}

/**
 * Score source-vs-npm diff results.
 * Max 10 points. Returns 0 if diff was not performed.
 */
function scoreDiff(diff?: DiffResult): number {
  if (!diff || !diff.performed) {
    return 0;
  }

  let points = 10;

  // Diminishing returns: min(8, 3 * (1 + ln(count)))
  // 1 file = -3, 2 = -4, 5 = -6, 35 = -8 (capped)
  const count = diff.unexpectedFiles.length;
  if (count > 0) {
    points -= Math.min(8, 3 * (1 + Math.log(count)));
  }

  return Math.max(0, points);
}

/**
 * Map a numeric score to a letter grade.
 */
function toGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/**
 * Map a letter grade to a human-readable verdict string.
 */
function toVerdict(grade: string): string {
  switch (grade) {
    case 'A':
    case 'B':
      return 'CLEAN — No issues detected';
    case 'C':
      return 'CAUTION — Review findings before installing';
    case 'D':
    case 'F':
      return 'DANGER — Manual review strongly recommended';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Calculate the aggregate security score for a scanned package.
 *
 * Combines weighted scores from all scanner categories, GitHub health,
 * and source diff into a single 0-100 score.
 *
 * @param scanners - Results from all scanners.
 * @param github   - GitHub health data (optional).
 * @param diff     - Source diff data (optional).
 * @param meta     - Package metadata (optional, used for provenance).
 * @returns Score (0-100), letter grade, and verdict.
 */
export function calculateScore(
  scanners: ScannerResult[],
  github?: GitHubHealth,
  diff?: DiffResult,
  meta?: PackageMetadata,
): ScoreResult {
  let total = 0;

  // Score each scanner category
  for (const result of scanners) {
    total += scoreCategory(result);
  }

  // Add GitHub health score (0-15 pts)
  const hasProvenance = meta?.trustedPublisher !== undefined;
  total += scoreGitHub(github, hasProvenance);

  // Add diff score (0-10 pts)
  total += scoreDiff(diff);

  // Clamp to 0-100
  const score = Math.max(0, Math.min(100, total));
  const grade = toGrade(score);
  const verdict = toVerdict(grade);

  return { score, grade, verdict };
}
