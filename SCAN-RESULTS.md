# npx-ray Scan Results — Live Package Testing

Scans performed **2026-02-14** against packages published within minutes of testing, sourced from the npm registry RSS feed (`https://registry.npmjs.org/-/rss`). This validates npx-ray's detection capabilities against real-world, in-the-wild packages rather than synthetic test fixtures.

---

## Summary

| Package | Version | Score | Grade | Verdict |
|---|---|---|---|---|
| bt-bot-vpn-tele-manager | 1.0.1 | 50 | F | DANGER |
| killer-skills | 1.7.17 | 40 | F | DANGER |
| cowork-os | 0.3.83 | 25 | F | DANGER |
| @samooth/open-codex | 0.3.21 | 45 | F | DANGER |
| memorix | 0.3.7 | 70 | C | CAUTION |
| @tokentop/agent-opencode | 1.0.0 | 85 | B | CLEAN |

---

## Detailed Findings

### bt-bot-vpn-tele-manager@1.0.1 — Score: 50/F

**Publisher:** bangtepllo | **License:** MIT | **Files:** 10 | **Size:** 43.8 KB

**Initial assessment:** Obfuscated Telegram bot with no description, apparent embedded credentials, and IP geolocation API calls. Flagged as suspicious.

**Post-deobfuscation verdict:** Not malware. It's an **Indonesian VPN reseller management bot** (Telegram-based) for provisioning SSH, VLESS, and ZIVPN accounts. The obfuscation is likely commercial code protection, not malicious intent.

| Scanner | Result |
|---|---|
| Static | 1 warning: axios HTTP client |
| Obfuscation | 1 critical (190-element string array), 2 warnings (hex-encoded strings), 8 info (long lines up to 24,733 chars) |
| Secrets | 1 critical: false positive — SSH connection string template (`:443@`) matched credential-in-URL pattern |
| IOC | 1 URL: `hxxp[://]ip-api[.]com/json/` (used to display server geolocation to admin, not victim fingerprinting) |
| GitHub | No repository found |

**Flags that triggered the score:**
- 24,733-character single-line source file (heavy javascript-obfuscator output)
- Large string array rotation (190 elements) — all strings resolved via deobfuscation
- Hex-encoded string sequences hiding actual behavior
- `:443@` and `:80@` patterns in SSH connection string templates (false positive for secrets scanner)
- `ip-api.com/json/` called to look up VPN server locations for admin display
- No GitHub repository, no package description

**Deobfuscation details:**
- String array extracted and rotation function executed in isolation (no bot code executed)
- All 190 strings recovered — UI is in Indonesian (Bahasa Indonesia)
- Bot reads `BOT_TOKEN` and `ADMIN_ID` from env, restricts access to admin only
- Creates VPN accounts via `http://{domain}:1000/create-{protocol}?username=...&password=...`
- Manages servers in local SQLite database
- Supports SSH, VLESS, ZIVPN protocols with TLS/gRPC/non-TLS variants
- See [blog post](blog/2026-02-14-catching-malware-in-real-time.md) for full analysis

---

### killer-skills@1.7.17 — Score: 40/F

**Publisher:** kakawah | **License:** MIT | **Files:** 156 | **Size:** 480.6 KB

**Why it's suspicious:** CLI tool claiming to install "AI agent skills" with excessive shell execution, obfuscation, and publisher/repo mismatch.

| Scanner | Result |
|---|---|
| Static | 21 critical (child_process, execSync, exec), 22 warnings (fetch, fs.writeFile, https.request), 5 info |
| Obfuscation | 1 critical: large string array (>50 elements) in `dist/commands/do.js` |
| Dependencies | 9 direct dependencies |
| IOC | 4 URLs: killer-skills.com, killer-skills.vercel.app |
| GitHub | 0 stars, 0 forks, created 2 days ago, publisher != repo owner |
| Diff | 2 unexpected files (CHANGELOG.md, LICENSE), 1 modified (README.md) |

**Red flags:**
- 21 critical findings — heavy use of `execSync()` and `child_process` across multiple files
- Obfuscated `do.js` command with 50+ string array (what is it doing?)
- GitHub repo created 2 days before scan, zero community traction
- npm publisher (`kakawah`) does not match GitHub owner (`asiawright1122-boop`)
- Files in npm package not in GitHub repo
- Writes to filesystem extensively (MCP configs, editor configs)

---

### cowork-os@0.3.83 — Score: 25/F

**Publisher:** coworkos | **License:** MIT | **Files:** 21,164 | **Size:** 155.2 MB

**Why it's suspicious:** Massively oversized npm package (155 MB, 21K files) with enormous attack surface and files not present in the source repo.

| Scanner | Result |
|---|---|
| Static | 140 critical, 385 warnings, 509 info across 880 files |
| Obfuscation | 6 critical (high entropy, base64 blobs, string arrays), 6 warnings, 6 info |
| Dependencies | 54 direct + 4 optional (critical: >50 deps) |
| IOC | 70+ URLs, 11 IPs extracted |
| GitHub | 95 stars, publisher != repo owner |
| Diff | 9 unexpected files, 11 modified files vs source repo |

**Red flags:**
- 155 MB published to npm — extraordinarily large, likely includes build artifacts that shouldn't be published
- 140 critical static findings across 880 files
- 9 files in npm package not in GitHub source (connector dist/ files, executor-helpers.ts)
- 54 direct dependencies — massive supply chain surface
- High entropy and base64 blob detections in obfuscation scanner
- npm publisher does not match GitHub owner

---

### @samooth/open-codex@0.3.21 — Score: 45/F

**Publisher:** samooth | **License:** Apache-2.0 | **Files:** 4 | **Size:** 16.7 MB

**Why it's suspicious:** Fork of OpenAI's open-codex bundled into a single 16.7 MB file with full shell and network access.

| Scanner | Result |
|---|---|
| Static | 13 critical (exec, spawn, child_process), 15 warnings (fetch, node-fetch, got, dynamic require), 51 info |
| Obfuscation | 2 critical (high entropy, large string arrays), 6 warnings, 11 info |
| Secrets | 1 critical: generic API key pattern |
| IOC | 65+ URLs (OpenAI, Google Cloud, Anthropic, metadata endpoints), 2 IPs |
| GitHub | 0 stars, 0 forks |

**Red flags:**
- Entire application bundled into single `dist/cli.js` file — hard to review
- 13 critical patterns including `exec()`, `spawn()`, and `child_process`
- Cloud metadata endpoint access (`169.254.169.254`, `metadata.google.internal`) — could be used for cloud credential theft
- Generic API key pattern detected
- Accesses multiple AI provider API key URLs (OpenAI, Anthropic, Google, xAI, Groq)
- 0 stars, single maintainer

---

### memorix@0.3.7 — Score: 70/C

**Publisher:** avids2 | **License:** Apache-2.0 | **Files:** 15 | **Size:** 838.2 KB

**Why it's flagged:** CLI tool with shell execution capabilities, brand new repository.

| Scanner | Result |
|---|---|
| Static | 6 critical (child_process, execSync), 8 warnings (fetch, fs.writeFile) |
| GitHub | 1 star, repo created same day as scan |

**Assessment:** Likely a legitimate new project (source diff matches, no obfuscation, no secrets). The `execSync` calls are typical for CLI tools that need to run git or npm commands. Flagged as CAUTION due to the new repo and shell execution, but no obvious malicious intent.

---

### @tokentop/agent-opencode@1.0.0 — Score: 85/B

**Publisher:** GitHub Actions | **License:** MIT | **Files:** 21 | **Size:** 44.2 KB

| Scanner | Result |
|---|---|
| Static | 1 info (process.env) |
| IOC | 1 URL: opencode.ai |
| GitHub | 0 stars, repo created same day, publisher != owner |

**Assessment:** Clean package. Published via GitHub Actions (good practice). Only flag is the brand-new repo with zero stars and publisher mismatch, which is normal for new projects using automated publishing.

---

## Previously Reported Malicious Packages (All Pulled)

The following packages were reported as malicious by security researchers but have all been replaced by npm with `0.0.1-security` placeholder stubs. npx-ray correctly identifies these as suspicious (75/C) due to missing GitHub repos and no source diff, but the malicious code is no longer present.

| Package | Original Threat | Status |
|---|---|---|
| bitcoin-main-lib | NodeCordRAT — Discord C2, Chrome credential theft | Pulled |
| bitcoin-lib-js | NodeCordRAT — same campaign | Pulled |
| ethers-provide-bundle | Crypto wallet stealer via Telegram exfiltration | Pulled |
| sdk-ethers | Base64-encoded mnemonic seed stealer | Pulled |
| lotusbail | WhatsApp session hijacker, 56K downloads | Pulled |
| fezbox | QR code steganography credential stealer | Pulled |
| reproduction-hardhat | Reverse shell to 5.199.166.1 | Pulled |
| xlsx-to-json-lh | C2 connection + project directory deletion | Pulled |
| eslint-plugin-unicorn-ts-2 | AI prompt injection + postinstall hook | Pulled |

---

## Reporting Malicious Packages

If npx-ray flags a package you believe is malicious:

1. **npm security team:** https://docs.npmjs.com/reporting-malware-in-an-npm-package
2. **Email:** security@npmjs.com
3. **Socket.dev:** https://socket.dev/npm/issue (community reports)
4. **OpenSSF Package Analysis:** https://github.com/ossf/package-analysis (automated detection)

Include the npx-ray JSON output (`--json` flag) as evidence in your report.

---

## Methodology

1. Packages sourced from the npm registry RSS feed (`https://registry.npmjs.org/-/rss`) which lists the most recently published/updated packages
2. Scanned with `npx-ray <package> --verbose` within minutes of publication
3. All analysis is static — no code was executed from any scanned package
4. Scans performed on 2026-02-14 from a local machine

## Scanner Effectiveness

Based on this live testing session:

- **Obfuscation detection** correctly identified string array rotation, hex encoding, and minified single-line files
- **Static analysis** caught all instances of `exec()`, `spawn()`, `child_process`, `fetch()`, and credential access patterns
- **Secrets scanner** found credential-like patterns in URLs (note: `bt-bot-vpn-tele-manager` finding was a false positive — SSH connection string template, not actual embedded credentials)
- **IOC extraction** surfaced IP geolocation endpoints and URLs with proper defanging
- **GitHub health** correctly flagged zero-star repos, new repos, and publisher/owner mismatches
- **Source diff** caught files present in npm but missing from GitHub source
- **Dependency analysis** flagged excessive dependency counts (>50)

### Limitations Observed

- Packages already pulled by npm (replaced with `0.0.1-security`) cannot be analyzed — the malicious code is gone
- The `bt-bot-vpn-tele-manager` obfuscation was detectable but the IOC scanner could not decode strings hidden behind string array rotation (see Limitations section in README). Manual deobfuscation (extracting and running the rotation function in isolation) recovered all 190 strings and revealed the package is a benign VPN management bot, not malware — demonstrating that obfuscation flags require manual follow-up
- The secrets scanner produced a false positive on SSH connection string templates (`:443@` matched the credential-in-URL pattern). This is expected behavior — pattern-based scanning will have edge cases
- Very large packages (cowork-os at 155 MB) take longer to scan but complete successfully
