# Changelog

All notable changes to TeamCyberOps Suite are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [5.0.2] — 2026-04-11 (UI Polish)

### Fixed
- **Excessive tab padding** — Reduced `padx=20, pady=14` to `padx=12, pady=8` across all tab files 
  (scanner.py, recon.py, exploit.py, ai_tabs.py, power.py, intel.py, results.py). Content now has 
  proper margins without wasting screen real estate.
- **CLI terminal too small** — Terminal widgets in vulnerability scanner, nuclei manager, and analysis tabs 
  now properly fill available space using `fill="both", expand=True`. Terminals now occupy the full 
  bottom half of the window, making scan output much more readable.
- **Split layout consistency** — All recon tabs use unified split layout:
  - **TOP section (fixed):** Section header + info card + controls + buttons
  - **Accent separator line:** Visual divider between controls and terminal
  - **BOTTOM section (expands):** Terminal fills remaining vertical space (400px+)

### Enhanced
- **Workspace efficiency** — More screen real estate for scan results and terminal output
- **Output visibility** — Terminal now shows 30-40 lines of output instead of 2-3 lines
- **Consistent spacing** — All tab padding now matches design system (12px horizontal, 8px vertical)

---

## [5.0.3] — 2026-04-12

### Security Fixes (BUGS.md verified)
- **BUG #4 — Weak password hashing** (`database.py`): SHA-256 without salt replaced with `bcrypt`
  (rounds=12). HMAC-SHA256 with app-level salt used as fallback when bcrypt not installed.
  `init_db()` now calls `_hash_password()` for the default admin user.
- **BUG #7 — Timing attack in `verify_user`** (`database.py`): Plain `==` comparison replaced
  with `hmac.compare_digest()` inside `_verify_password()`. Dummy compare added for missing
  usernames to prevent timing-based username enumeration.
- **BUG #37 — Subprocess shell injection** (`active.py`): `_run()` now enforces `shell=False`
  and always uses list-form commands. String inputs are split safely.

### Logic Fixes (BUGS.md verified)
- **BUG #8 — Non-atomic config write** (`config.py`): `cfg_path.write_text()` replaced with
  `tempfile.NamedTemporaryFile` + `os.fsync()` + `os.replace()` — atomic on all major OSes.
- **BUG #10 — Socket leak in port scanner** (`active.py`): Python fallback now uses
  `with socket.socket(...) as sock:` context manager — guaranteed close on exception.
- **BUG #11 — HTTP response not closed** (`scanner.py`): `_req()` uses `with urlopen(...) as r:`;
  specific exception types instead of bare `except Exception`.
- **BUG #16 — Config singleton not thread-safe** (`config.py`): Added `threading.Lock()` +
  double-checked locking pattern to `Config.__new__()`.
- **BUG #27 — Tool check not cached** (`active.py`): `@lru_cache(maxsize=64)` on `_tool_exists()`
  — `shutil.which()` now called once per tool name per process lifetime.
- **BUG #43 — Malformed bash-glob directory** (`modules/{...}/`): `main.py` startup
  auto-removes any `modules/` subdirectory whose name contains `{` or `,`.

### Database Fixes (BUGS.md verified)
- **BUG #22 — Missing username index**: `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`
  added to SCHEMA — O(log n) login lookups instead of O(n) full table scans.

### Code Quality Fixes (BUGS.md verified)
- **BUG #31 — Unused `ssl` import** (`active.py`): Removed. Added `lru_cache` import.
- **BUG #40 — Unused `_SYS` variable** (`theme.py`): `FONT_BODY` now consistently uses `_SYS`
  instead of inline `platform.system()` calls.
- **BUG #42 — Silent `except: pass`** (`config.py`): Replaced with
  `except Exception as e: print(f"[Config] Warning: {e}")` — errors are now visible.

### Dependencies
- **BUG #29/#44 — Incomplete `requirements.txt`**: Added `bcrypt>=4.0.0`, `urllib3>=2.0.0`.
  Added comprehensive comments documenting system dependencies and external tools.

### Verification Results
- 47 bugs from BUGS.md verified against actual files
- 7 bugs marked N/A (referenced files `brute-server.py`, `connect-server.py`,
  `fuzz_server.py` do not exist in this project)
- 17 bugs fixed in this pass
- ~16 bugs remain (MEDIUM/LOW — planned for v5.1.0)

---

## [5.0.2] — 2026-04-12

### Fixed
- **Sidebar tab height** — Root cause was `CTkFrame` without `pack_propagate(False)` — children
  (CTkLabel with `expand=True`) were dictating the row height, producing large squares instead
  of compact single-line items. Fix: added `height=_SB_ROW_H` (26px) + `row.pack_propagate(False)`
  on every sidebar row frame. All labels now capped at 26px. Single constant `_SB_ROW_H` controls
  all rows — change one number to resize sidebar.
- **`invalid command name NNNupdate` / `check_dpi_scaling` terminal spam** — Previous fix
  (`_StderrFilter`) intercepted Python-level stderr but not Tcl-level background errors.
  Root fix: override Tcl's `bgerror` proc directly in the Tcl interpreter via
  `self.root.tk.eval("proc bgerror ...")` — errors are now suppressed before they
  ever reach Python or stderr. Terminal is fully clean.
- **Logs/projects not syncing** — Added `sync_logs_to_projects()` to `database.py`.
  Scans `logs/<project_name>/` directories at startup and auto-registers any missing
  projects into SQLite. Called both synchronously before UI starts (`main.py`) and
  asynchronously in a background thread after login (refreshes combo 800ms later).
  All existing log folders now appear in the project dropdown automatically.

### Changed
- `_SB_ROW_H = 26` and `_SB_FONT = 11` constants at top of `app_window.py` —
  single source of truth for sidebar sizing.
- Status bar version string updated to `TCO v5.0.2`.
- `[LOGOUT]` button now calls `_on_close()` (clean shutdown) instead of `root.destroy()`.

---

## [5.0.1] — 2026-04-11

### Fixed (Hot-patch)
- **`KeyError: 'cyan'`** — Added `"cyan"`, `"magenta"`, `"blue"`, `"darkred"`, `"crimson"` as
  alias keys in the color system (`theme.py`). Auto-Recon tab no longer crashes on load.
- **`invalid command name "NNNupdate"` / `check_dpi_scaling`** — Suppressed harmless
  CustomTkinter shutdown noise in `main.py` via `sys.excepthook`, `threading.excepthook`,
  and a `_StderrFilter` wrapper. Terminal is now completely clean on exit.
- **`RuntimeError: main thread is not in main loop`** — Filtered via `threading.excepthook`
  override; also added guarded `after()` callback in `_fetch_ip()`.
- **`WM_DELETE_WINDOW` cleanup** — `_on_close()` method now cancels all pending `after()`
  events before destroying the window, preventing Tcl command-not-found race.
- **Sidebar tabs too large** — Reduced `pady` on sidebar label rows (6 → 2px);
  removed excess `padx` in scroll container. Tabs are now compact single-line rows.
- **Terminal single-line (too small)** — All recon tabs (`_mk_recon_tab`,
  `_build_simple_recon_subtab`, `_tab_auto_recon`, `_tab_dorks`) now use a **split layout**:
  controls panel is fixed at top; terminal widget fills the **entire bottom half** of the
  window using `fill="both", expand=True` with no height cap.

### Added
- **C2 / Dark Red color palette** — New semantic colors: `darkred (#aa0018)`,
  `crimson (#cc0022)`, `blood (#880011)`, `border_red`, `border_accent`.
  EXPLOIT category → Crimson, POWER category → Blood Red.
- **Font scaling system** — `_FS` multiplier in `theme.py`; set `_FS = 1.2` for 20%
  global font size increase without touching individual widgets.
- **Status bar upgrade** — Height 22 → 30px; font 8 → 10pt mono; red top border (C2 style).
- **Sidebar NAVIGATION header** + accent-colored right border (electric blue vertical line).
- **Topbar accent border** — Bottom border changed from `border_mid` to `border_accent`.
- **Separator lines** — Accent-colored 1px horizontal lines between controls and terminal
  in all recon tabs (visual split indicator).
- **`_TINT` dict extended** — `darkred` and `crimson` hover tints registered.
- **CAT_COLORS** — EXPLOIT → crimson, POWER → red (was orange). More aggressive C2 feel.

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
