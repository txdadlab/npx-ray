# npx-ray

**X-ray vision for npm packages.**

A security scanner that audits source code, detects obfuscation, and flags supply chain risks -- all before you install. Downloads the tarball, runs 7 scanners in parallel, checks GitHub health, diffs source against the published package, and gives you a 0-100 risk score. No account required. Runs entirely locally.

[![npm version](https://img.shields.io/npm/v/npx-ray)](https://www.npmjs.com/package/npx-ray)
[![license](https://img.shields.io/npm/l/npx-ray)](https://github.com/txdadlab/npx-ray/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/npx-ray)](https://nodejs.org)

---

## Quick Start

```bash
npx npx-ray chalk              # Scan any package
npx npx-ray chalk@5.0.0        # Scan specific version
npx npx-ray --json chalk       # JSON output for CI/CD
npx npx-ray --mcp              # Scan your MCP servers
npx npx-ray --verbose express  # Detailed findings
```

Or install globally:

```bash
npm install -g npx-ray
npx-ray lodash
```

---

## Example Output

```
npx-ray v1.0.0 — X-ray vision for npm packages
───────────────────────────────────────────────────────

Package: chalk@5.4.1
Publisher: sindresorhus
Published: 2024-11-21
License: MIT
Files: 7
Size: 11.2 KB

───────────────────────────────────────────────────────
  Risk Score: 90/100 (A)
───────────────────────────────────────────────────────

Scan Results

  ✅ Static: No dangerous patterns detected
  ✅ Obfuscation: No obfuscation detected
  ✅ Hooks: No lifecycle hooks found
  ✅ Secrets: No embedded secrets detected
  ✅ Binaries: No binary files found
  ✅ Dependencies: 0 direct, 0 optional dependencies
  ✅ Typosquatting: "chalk" is a known popular package

GitHub
  ✅ Repository: chalk/chalk
    Stars: 22000 | Forks: 850 | Open Issues: 12
    Created: 2013-07-18 | Last Push: 2024-11-21

Source Diff
  ✅ Source matches published package

───────────────────────────────────────────────────────
  Verdict: CLEAN — No issues detected
───────────────────────────────────────────────────────

Scan completed in 3.2s
```

---

## What It Checks

| Scanner | What it detects | Severity |
|---|---|---|
| **Static Analysis** | `eval()`, `child_process`, `exec()`, `spawn()`, `fetch()`, dynamic `require()`, filesystem writes, `process.env` access | Critical / Warning / Info |
| **Obfuscation** | Shannon entropy anomalies, hex-encoded strings, base64 blobs (>500 chars), string array rotation (>50 elements), suspiciously long lines | Critical / Warning / Info |
| **Lifecycle Hooks** | `preinstall`, `postinstall`, and other install-time scripts; shell commands in hooks (`curl`, `wget`, `bash`, `node -e`) | Critical / Warning |
| **Secrets** | AWS keys, GitHub/npm tokens, private keys, credentials in URLs, generic API keys and tokens | Critical / Warning |
| **Binaries** | `.node`, `.so`, `.dll`, `.dylib`, `.exe`, `.bin`, `.wasm` files that cannot be source-reviewed | Warning |
| **Dependencies** | Dependency bloat (>20 warning, >50 critical), wildcard/unpinned versions (`*`, `latest`), git URL dependencies | Critical / Warning |
| **Typosquatting** | Package names within 1-2 edits of popular packages (Levenshtein distance) | Critical / Warning |
| **GitHub Health** | Stars, forks, archive status, repo age, publisher-vs-owner mismatch | Scoring adjustment |
| **Source Diff** | Files in npm but not in GitHub repo, content hash mismatches between published and source | Scoring adjustment |
| **MCP Servers** | Unpinned MCP server versions in editor configs, tool description injection risks | Via `--mcp` flag |

---

## Risk Scoring

Every package receives a score from 0 (dangerous) to 100 (clean), computed by summing weighted category scores. Each category starts at its maximum points and deducts based on the severity of findings.

### Category Weights

| Category | Max Points | Critical Deduction | Warning Deduction | Info Deduction |
|---|---|---|---|---|
| Static Analysis | 25 | -15 | -5 | 0 |
| Obfuscation | 15 | -10 | -10 | -3 |
| Lifecycle Hooks | 10 | -10 | -5 | 0 |
| Dependencies | 10 | -10 | -5 | 0 |
| GitHub Health | 15 | -- | -- | -- |
| Source Diff | 10 | -- | -- | -- |
| Secrets | 5 | -5 | -5 | 0 |
| Binaries | 5 | -3 | -3 | -1 |
| Typosquatting | 5 | -5 | -5 | 0 |
| **Total** | **100** | | | |

GitHub Health deductions: archived repo (-10), zero stars (-5), repo less than 1 month old (-5), publisher does not match GitHub owner (-10).

Source Diff deductions: -5 per unexpected file in the npm package that is not in the GitHub repo.

### Letter Grades

| Grade | Score | Verdict | Exit Code |
|---|---|---|---|
| **A** | 90 -- 100 | CLEAN -- No issues detected | 0 |
| **B** | 80 -- 89 | CLEAN -- No issues detected | 0 |
| **C** | 70 -- 79 | CAUTION -- Review findings before installing | 1 |
| **D** | 60 -- 69 | DANGER -- Manual review strongly recommended | 2 |
| **F** | 0 -- 59 | DANGER -- Manual review strongly recommended | 2 |

---

## CLI Reference

```
Usage: npx-ray [options] [package]

X-ray vision for npm packages — security scanner that audits source code,
detects obfuscation, and flags supply chain risks before you install

Arguments:
  package              Package to scan (name, name@version, or local tarball)

Options:
  --json               Output results as JSON (for CI/CD pipelines)
  --verbose            Show detailed findings for each scanner
  --mcp                Scan MCP servers from editor configurations
  --no-github          Skip GitHub repository checks
  --no-diff            Skip source-vs-published diff
  -V, --version        Output the version number
  -h, --help           Display help
```

### Examples

```bash
# Scan a package by name (resolves latest version)
npx npx-ray express

# Scan a specific version
npx npx-ray lodash@4.17.21

# JSON output for scripting or CI
npx npx-ray react --json

# Full detail with every individual finding
npx npx-ray axios --verbose

# Fast scan (skip GitHub API and source diff)
npx npx-ray leftpad --no-github --no-diff

# Scan all MCP servers configured on your machine
npx npx-ray --mcp
```

---

## MCP Server Scanning

The `--mcp` flag scans your local editor configurations for MCP (Model Context Protocol) servers that use npm packages. It automatically discovers servers from:

- **Claude Desktop** (macOS, Windows, Linux)
- **Cursor** (`~/.cursor/mcp.json`)
- **VS Code** (`~/.vscode/mcp.json`)
- **Claude Code** (`~/.claude.json`)
- **Windsurf** (`~/.windsurf/mcp.json`, `~/.codeium/windsurf/mcp_config.json`)

For each npm-based MCP server found, npx-ray:

1. Checks whether the package version is **pinned** (e.g., `@anthropic-ai/mcp-server@1.2.3` vs unpinned `@anthropic-ai/mcp-server`)
2. Runs the **full security scan** on the npm package
3. Reports a summary across all servers

Unpinned MCP servers are a supply chain risk -- an attacker who compromises a package can push a new version that gets auto-installed the next time your editor launches.

```bash
npx npx-ray --mcp
```

---

## CI/CD Integration

Use npx-ray in your CI pipeline to gate new dependencies before they enter your project.

### GitHub Actions

```yaml
name: Dependency Security Scan
on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        package: [express, lodash, axios]  # or parse from diff
    steps:
      - name: Security scan
        run: npx npx-ray ${{ matrix.package }} --json
```

### Exit Codes

| Code | Meaning | Action |
|---|---|---|
| 0 | Grade A or B -- clean | Proceed |
| 1 | Grade C -- warnings found | Review findings |
| 2 | Grade D or F -- critical issues | Block and investigate |

### JSON Output Schema

The `--json` flag outputs a structured report that can be parsed by downstream tools:

```json
{
  "package": {
    "name": "example",
    "version": "1.0.0",
    "license": "MIT",
    "publisher": "author",
    "dependencies": {}
  },
  "scanners": [
    {
      "name": "static",
      "passed": true,
      "findings": [],
      "summary": "No dangerous patterns detected"
    }
  ],
  "score": 95,
  "grade": "A",
  "verdict": "CLEAN — No issues detected",
  "duration": 2100
}
```

---

## How It Works

1. **Fetch metadata** from the npm registry (version, tarball URL, publisher, dependencies)
2. **Download and extract** the tarball to a temporary directory -- nothing is installed, no scripts run
3. **Run 7 scanners in parallel** against the extracted source code:
   - Static analysis (dangerous API patterns)
   - Obfuscation detection (entropy, hex, base64, string arrays)
   - Lifecycle hooks (install scripts)
   - Secrets (API keys, tokens, private keys)
   - Binaries (non-reviewable native addons)
   - Dependency analysis (bloat, wildcards, git URLs)
   - Typosquatting (Levenshtein distance against top npm packages)
4. **Check GitHub health** via the unauthenticated API (stars, age, archive status, publisher match)
5. **Diff source vs. published** by downloading the GitHub repo tarball and comparing file lists and content hashes
6. **Calculate score** using weighted category deductions
7. **Output report** (colored terminal output or JSON)
8. **Clean up** the temporary directory

No data is sent to any external service. GitHub API requests are unauthenticated and optional (skip with `--no-github`).

---

## Comparison

| Feature | npx-ray | npm audit | socket.dev | mcp-scan |
|---|---|---|---|---|
| Source code analysis | Yes | No | No | No |
| Obfuscation detection | Yes | No | Yes | No |
| Shannon entropy analysis | Yes | No | No | No |
| Typosquatting detection | Yes | No | Yes | No |
| Source-vs-npm diff | Yes | No | No | No |
| Lifecycle hook scanning | Yes | No | Yes | No |
| Secret detection | Yes | No | No | No |
| Binary file detection | Yes | No | No | No |
| Dependency analysis | Yes | Yes | Yes | No |
| GitHub health check | Yes | No | Yes | No |
| MCP server scanning | Yes | No | No | Yes |
| Works pre-install | Yes | No (post-install) | Yes | Yes |
| Runs locally | Yes | Yes | No (SaaS) | Yes |
| No account required | Yes | Yes | No | Yes |
| JSON output for CI | Yes | Yes | Yes | Yes |

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

```bash
git clone https://github.com/txdadlab/npx-ray.git
cd npx-ray
npm install
npm run build
node dist/cli.js chalk    # Test your changes
npm test                  # Run the test suite
```

### Adding a New Scanner

1. Create `src/scanners/your-scanner.ts` implementing the `ScannerResult` interface
2. Import and add it to the `Promise.all` array in `src/cli.ts`
3. Add a weight entry in `src/scorer.ts` under `CATEGORY_WEIGHTS`
4. Add tests in `tests/`

---

## License

[Apache-2.0](LICENSE)
