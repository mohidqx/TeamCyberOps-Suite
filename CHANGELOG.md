# Changelog

All notable changes to TeamCyberOps Suite are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [5.0.0] — 2026-04-10

### Breaking Changes
- Complete rewrite: monolithic `main.py` → modular architecture
- Database: JSON files → SQLite WAL (thread-safe, ACID)
- UI: Tkinter/ttk → CustomTkinter (HUD/Sci-Fi design system)

### Added
- **52 tabs** (up from 39 in v4)
- **SQLite database** with schema: projects, findings, scan_results, users, config
- **Gemini Flash 2.0** AI integration (free tier at aistudio.google.com)
- **AI Auto-Exploit**: PoC generator, chain analyzer, bounty estimator, smart reporter
- **Nuclei AI Generator**: describe a vuln → Gemini generates Nuclei YAML template
- **Live Monitor**: 24/7 subdomain + HTTP change detection
- **OAuth ATO standalone tab**: full OAuth account takeover tester
- **SAST Scanner**: paste code or scan GitHub repo for secrets/vulns
- **API Tester**: load Swagger/OpenAPI spec → auto-test all endpoints
- **TeamCyberOps Owl Badge** logo on login screen and topbar
- **HUD/Sci-Fi FUI** design system (UI-UX-Pro-Max skill applied)
- **Sidebar search**: live filter across all 52 tabs
- **Active indicator bar**: 2px color stripe on selected tab
- **Error tab**: shows traceback when a tab fails to load
- **config.json sync**: SQLite config stays in sync for legacy modules
- **Docker support**: Dockerfile + docker-compose.yml

### Fixed
- `RuntimeError: Too early to create variable` — `ctk.CTk()` now created before `ctk.StringVar()`
- `TclError: invalid color name "#RRGGBBAA"` — all colors pre-blended to 6-digit hex
- `TypeError: multiple values for keyword argument` — override-friendly `defaults.update(kw)` pattern
- `CTkComboBox command=lambda:` — changed to `lambda v=None:` to receive value
- `_refresh_findings()` in thread — wrapped with `root.after(0, ...)`
- Missing `__init__.py` in module packages
- Circular import: scanner.py → ReconMixin removed
- Thread exceptions swallowed silently — all `_go()` functions wrapped in try/except

### Modules Upgraded
- `passive.py`: 6 parallel sources (crt.sh, HackerTarget, AlienVault, URLScan, ThreatCrowd, subfinder)
- `active.py`: port scan, HTTP probe, dir fuzz, tech detect, WAF detect (all with Python fallbacks)
- `scanner.py`: 40+ checks, nuclei, XSS, SQLi, nikto
- `url_discovery.py`: Wayback + CommonCrawl + GAU + Katana + Python crawler
- `security_tools.py`: JS analyzer (30 secret types), CSP, CORS, headers
- `cve_fetcher.py`: NVD API v2, CISA KEV (1hr cache), tech-to-CVE
- `engine.py`: WHOIS/RDAP, ASN/BGP, email, favicon MurmurHash3, cloud assets
- `web_scanners.py`: prototype pollution, cache poison, CORS, redirect, NoSQL, WebSocket, XXE, OAuth ATO

---

## [4.0.0] — 2026-03-15

### Added
- SSRF Suite (4 sub-tabs: quick detect, bypass gen, cloud extractor, port scanner)
- 2FA Bypass Suite (5 sub-tabs: auto scan, OTP leakage, rate limit, reuse, response manip)
- HTTP Request Smuggling (timing-based: CL.TE, TE.CL, 14 TE.TE variants)
- AI Auto-Exploit (Claude API: PoC, Burp request, impact, remediation)
- 270 dorks (Google 130 + Shodan 58 + Censys 28 + GitHub 54)
- Dork Runner with proxy rotation

### Fixed
- Findings double-click broken (iid mismatch) — fixed values[0] resolution
- Dork Runner proxy tunnel errors

---

## [3.0.0] — 2026-01-10

### Added
- OAST Server (HTTP:8877 + DNS:5353, pure Python)
- JWT/OAuth Suite (alg=none, brute secret, RS256→HS256, 9 OAuth attack URLs)
- Race Condition Tester (8 scenarios, synchronized barrier launch)
- GraphQL Security Tester (16 paths, introspection, batching, IDOR)
- Origin Hunter (WAF detection, subdomain resolve, SSL cert scan)

---

## [2.0.0] — 2025-11-20

### Added
- Multi-project support
- Findings database (JSON)
- Report generator (HackerOne, Bugcrowd, HTML, Markdown)
- CVE Intelligence (NVD API, CISA KEV)

---

## [1.0.0] — 2025-09-01

### Initial Release
- Basic recon (passive, active)
- Vuln scanner with Nuclei
- OSINT engine
- Single-file architecture
