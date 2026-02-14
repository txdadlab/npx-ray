/**
 * Typosquatting detection scanner.
 *
 * Checks if a package name is suspiciously similar to popular packages
 * using Levenshtein distance. Catches common supply chain attacks where
 * malicious packages use names close to popular ones.
 */

import { readFileSync } from 'node:fs';
import { distance } from 'fastest-levenshtein';
import type { ScannerResult, Finding } from '../types.js';

const SCANNER_NAME = 'typosquatting';

/** Levenshtein distance thresholds. */
const DISTANCE_CRITICAL = 1;
const DISTANCE_WARNING = 2;

/** Cached popular package names. */
let popularPackages: string[] | null = null;

/**
 * Load popular package names from the data file.
 */
function loadPopularPackages(): string[] {
  if (popularPackages !== null) return popularPackages;

  try {
    const dataUrl = new URL('../../data/popular-packages.json', import.meta.url);
    const raw = readFileSync(dataUrl, 'utf-8');
    popularPackages = JSON.parse(raw) as string[];
    return popularPackages;
  } catch {
    // Fallback: return empty array if data file is missing
    popularPackages = [];
    return popularPackages;
  }
}

/**
 * Strip common npm scope prefix for comparison.
 * e.g., "@malicious/lodash" -> "lodash"
 */
function stripScope(name: string): string {
  return name.replace(/^@[^/]+\//, '');
}

/**
 * Check if a package name is suspiciously similar to popular packages.
 */
export async function scanTyposquatting(packageName: string): Promise<ScannerResult> {
  const findings: Finding[] = [];
  const popular = loadPopularPackages();

  if (popular.length === 0) {
    return {
      name: SCANNER_NAME,
      passed: true,
      findings: [],
      summary: 'Popular packages list unavailable — skipped',
    };
  }

  const nameToCheck = stripScope(packageName).toLowerCase();
  const similarPackages: Array<{ name: string; dist: number }> = [];

  for (const pkg of popular) {
    const popularName = stripScope(pkg).toLowerCase();

    // Exact match = this IS the popular package — not a flag
    if (nameToCheck === popularName) {
      return {
        name: SCANNER_NAME,
        passed: true,
        findings: [],
        summary: `"${packageName}" is a known popular package`,
      };
    }

    const dist = distance(nameToCheck, popularName);

    if (dist <= DISTANCE_WARNING) {
      similarPackages.push({ name: pkg, dist });
    }
  }

  // Sort by distance (closest first)
  similarPackages.sort((a, b) => a.dist - b.dist);

  for (const sim of similarPackages) {
    const severity = sim.dist <= DISTANCE_CRITICAL ? 'critical' : 'warning';
    findings.push({
      scanner: SCANNER_NAME,
      severity,
      message: `Package name "${packageName}" is ${sim.dist} edit(s) from popular package "${sim.name}"`,
      evidence: `Levenshtein distance: ${sim.dist}`,
    });
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const passed = criticalCount === 0 && warningCount === 0;

  let summary: string;
  if (findings.length === 0) {
    summary = 'No similar popular package names';
  } else {
    const names = similarPackages.map(s => `"${s.name}" (dist ${s.dist})`).join(', ');
    summary = `Similar to: ${names}`;
  }

  return {
    name: SCANNER_NAME,
    passed,
    findings,
    summary,
  };
}
