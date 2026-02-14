/**
 * Shared type definitions for npx-ray.
 */

/** Severity level for a finding. */
export type Severity = "critical" | "warning" | "info";

/** A single security finding from any scanner. */
export interface Finding {
  /** Which scanner produced this finding. */
  scanner: string;
  /** Severity level. */
  severity: Severity;
  /** Human-readable description. */
  message: string;
  /** File path relative to package root (if applicable). */
  file?: string;
  /** Line number (if applicable). */
  line?: number;
  /** The matched pattern or evidence. */
  evidence?: string;
}

/** Results from a single scanner. */
export interface ScannerResult {
  /** Scanner name (e.g., "static", "obfuscation"). */
  name: string;
  /** Whether the scan passed (no critical/warning findings). */
  passed: boolean;
  /** All findings. */
  findings: Finding[];
  /** Short summary for display. */
  summary: string;
}

/** Package metadata from the npm registry. */
export interface PackageMetadata {
  /** Package name. */
  name: string;
  /** Resolved version. */
  version: string;
  /** Package description. */
  description: string;
  /** SPDX license identifier. */
  license: string;
  /** npm publisher username. */
  publisher: string;
  /** Publish date for this version. */
  publishedAt: string;
  /** Tarball download URL. */
  tarballUrl: string;
  /** Repository URL (from package.json). */
  repositoryUrl: string;
  /** Homepage URL. */
  homepage: string;
  /** Total file count in tarball. */
  fileCount: number;
  /** Unpacked size in bytes. */
  unpackedSize: number;
  /** Direct dependencies. */
  dependencies: Record<string, string>;
  /** Optional dependencies. */
  optionalDependencies: Record<string, string>;
  /** Lifecycle scripts from package.json. */
  scripts: Record<string, string>;
  /** All maintainers. */
  maintainers: Array<{ name: string; email?: string }>;
  /** Trusted publisher info (npm provenance via OIDC). Undefined if not present. */
  trustedPublisher?: { id: string };
}

/** GitHub repository health info. */
export interface GitHubHealth {
  /** Whether the repo was found. */
  found: boolean;
  /** Owner/repo string. */
  fullName: string;
  /** Star count. */
  stars: number;
  /** Fork count. */
  forks: number;
  /** Open issue count. */
  openIssues: number;
  /** SPDX license. */
  license: string;
  /** ISO date of repo creation. */
  createdAt: string;
  /** ISO date of last push. */
  lastPush: string;
  /** Whether the repo is archived. */
  archived: boolean;
  /** Whether the npm publisher matches the GitHub owner. */
  publisherMatchesOwner: boolean;
}

/** Source-vs-npm diff results. */
export interface DiffResult {
  /** Whether the diff was performed (requires GitHub repo). */
  performed: boolean;
  /** Files in npm but not in repo (excluding expected build dirs). */
  unexpectedFiles: string[];
  /** Files in npm not in repo that are expected (dist/, lib/, build/). */
  expectedBuildFiles: string[];
  /** Files that differ in content between npm and repo. */
  modifiedFiles: string[];
  /** Error message if diff failed. */
  error?: string;
}

/** MCP server config entry. */
export interface McpServerEntry {
  /** Server name. */
  name: string;
  /** Command to run. */
  command: string;
  /** Arguments. */
  args: string[];
  /** Source config file. */
  configFile: string;
  /** Extracted npm package name (if npm-based). */
  npmPackage?: string;
  /** Whether the version is pinned. */
  versionPinned: boolean;
}

/** Complete scan report. */
export interface ScanReport {
  /** Package metadata. */
  package: PackageMetadata;
  /** Results from all scanners. */
  scanners: ScannerResult[];
  /** GitHub health (if available). */
  github?: GitHubHealth;
  /** Source diff (if available). */
  diff?: DiffResult;
  /** MCP-specific findings (if --mcp or MCP package). */
  mcp?: ScannerResult;
  /** Aggregate risk score 0-100. */
  score: number;
  /** Letter grade. */
  grade: string;
  /** Overall verdict. */
  verdict: string;
  /** Scan duration in ms. */
  duration: number;
}

/** CLI options parsed from arguments. */
export interface CliOptions {
  /** Package specifier (name, name@version, or local path). */
  target: string;
  /** Output as JSON. */
  json: boolean;
  /** Verbose output. */
  verbose: boolean;
  /** Scan MCP servers from editor configs. */
  mcp: boolean;
  /** Skip GitHub checks. */
  noGithub: boolean;
  /** Skip source diff. */
  noDiff: boolean;
}
