"""
TeamCyberOps Suite v4 — Passive Recon Module (Production Grade)
Multi-source subdomain enumeration with Python fallbacks for every tool
"""
import json, subprocess, urllib.request, urllib.parse, re, socket, threading
import concurrent.futures, time, os
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
CFG_PATH = BASE_DIR / "config.json"
LOGS_DIR = BASE_DIR / "logs"

def _cfg():
    try:
        with open(CFG_PATH) as f: return json.load(f)
    except Exception: return {}

def _save_log(project, filename, lines):
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    p = d / filename
    with open(p, 'w') as f: f.write('\n'.join(lines))
    return str(p)

def _tool_exists(name):
    import shutil; return shutil.which(name) is not None

def _run_tool(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired: return ""
    except FileNotFoundError: return ""
    except Exception: return ""

# ── crt.sh — Certificate Transparency ───────────────────────────
def crtsh_lookup(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[crt.sh] Querying certificate transparency for *.{domain}", "info")
    subs = set()
    # Try JSON API first
    for q in [f"%.{domain}", domain]:
        try:
            url = f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json"
            req = urllib.request.Request(url, headers={"Accept":"application/json","User-Agent":"TeamCyberOps/4"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            for entry in data:
                for name in entry.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name and name != domain: subs.add(name)
        except Exception: pass
    # HTML fallback
    if not subs:
        try:
            url = f"https://crt.sh/?q=%.{domain}"
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
            with urllib.request.urlopen(req, timeout=20) as r:
                html = r.read().decode("utf-8","replace")
            subs.update(re.findall(rf'([a-zA-Z0-9\-\.]+\.{re.escape(domain)})', html))
        except Exception: pass
    result = sorted(subs)
    log(f"[crt.sh] Found {len(result)} subdomains", "ok" if result else "dim")
    return result

# ── HackerTarget ─────────────────────────────────────────────────
def hackertarget_lookup(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[HackerTarget] Querying subdomain API", "info")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        with urllib.request.urlopen(url, timeout=15) as r:
            lines = r.read().decode("utf-8","replace").strip().splitlines()
        subs = [l.split(",")[0].strip() for l in lines if "," in l and domain in l]
        log(f"[HackerTarget] Found {len(subs)} subdomains", "ok" if subs else "dim")
        return subs
    except Exception as e:
        log(f"[HackerTarget] Error: {e}", "err"); return []

# ── AlienVault OTX ───────────────────────────────────────────────
def alienvault_lookup(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[AlienVault OTX] Querying passive DNS", "info")
    subs = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4","X-OTX-API-KEY":""})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        for entry in data.get("passive_dns",[]):
            h = entry.get("hostname","")
            if domain in h: subs.add(h.lstrip("*."))
    except Exception: pass
    try:
        url2 = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        with urllib.request.urlopen(url2, timeout=15) as r:
            data2 = json.loads(r.read())
        for entry in data2.get("url_list",[]):
            u = entry.get("url","")
            m = re.search(rf'([a-zA-Z0-9\-]+\.{re.escape(domain)})', u)
            if m: subs.add(m.group(1))
    except Exception: pass
    result = sorted(subs)
    log(f"[AlienVault] Found {len(result)} subdomains", "ok" if result else "dim")
    return result

# ── URLScan.io ───────────────────────────────────────────────────
def urlscan_lookup(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[URLScan.io] Querying scan database", "info")
    subs = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        for result in data.get("results",[]):
            task_domain = result.get("task",{}).get("domain","")
            if domain in task_domain: subs.add(task_domain)
            for dom in result.get("page",{}).get("domain","").split(","):
                if domain in dom: subs.add(dom.strip())
    except Exception: pass
    result = sorted(subs)
    log(f"[URLScan] Found {len(result)} subdomains", "ok" if result else "dim")
    return result

# ── ThreatCrowd ──────────────────────────────────────────────────
def threatcrowd_lookup(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read())
        subs = [s for s in data.get("subdomains",[]) if domain in s]
        log(f"[ThreatCrowd] Found {len(subs)}", "ok" if subs else "dim")
        return subs
    except Exception: return []

# ── Subfinder (tool) ─────────────────────────────────────────────
def subfinder_enum(domain, output_file, log_cb=None, timeout=120):
    log = log_cb or (lambda m,t='': None)
    if not _tool_exists("subfinder"):
        log("[subfinder] Not installed — using API fallback", "warn"); return []
    log(f"[subfinder] Running: subfinder -d {domain}", "info")
    cmd = ["subfinder", "-d", domain, "-o", output_file, "-silent", "-all"]
    out = _run_tool(cmd, timeout)
    try:
        subs = [l.strip() for l in open(output_file) if l.strip() and domain in l]
        log(f"[subfinder] Found {len(subs)} subdomains", "ok" if subs else "dim")
        return subs
    except Exception: return []

# ── Amass (tool) ─────────────────────────────────────────────────
def amass_enum(domain, output_file, log_cb=None, timeout=300):
    log = log_cb or (lambda m,t='': None)
    if not _tool_exists("amass"):
        log("[amass] Not installed — skipping", "warn"); return []
    log(f"[amass] Running passive enum (may take 2-5 min)", "info")
    cmd = ["amass", "enum", "-passive", "-d", domain, "-o", output_file, "-timeout", "4"]
    out = _run_tool(cmd, timeout)
    try:
        subs = [l.strip() for l in open(output_file) if l.strip() and domain in l]
        log(f"[amass] Found {len(subs)} subdomains", "ok" if subs else "dim")
        return subs
    except Exception: return []

# ── Full passive recon (all sources parallel) ────────────────────
def full_passive_recon(domain, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"\n{'='*50}", "dim")
    log(f"[*] PASSIVE RECON: {domain}", "info")
    log(f"{'='*50}\n", "dim")

    proj_dir = LOGS_DIR / project
    proj_dir.mkdir(parents=True, exist_ok=True)
    all_subs = set()

    # Run all API sources concurrently
    sources = [
        ("crt.sh",        lambda: crtsh_lookup(domain, log)),
        ("HackerTarget",  lambda: hackertarget_lookup(domain, log)),
        ("AlienVault",    lambda: alienvault_lookup(domain, log)),
        ("URLScan",       lambda: urlscan_lookup(domain, log)),
        ("ThreatCrowd",   lambda: threatcrowd_lookup(domain, log)),
    ]

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(fn): name for name, fn in sources}
        for fut in concurrent.futures.as_completed(futs, timeout=60):
            name = futs[fut]
            try:
                subs = fut.result()
                results[name] = subs
                all_subs.update(subs)
                _save_log(project, f"{name.lower().replace('.','_').replace('/','_')}.txt", subs)
            except Exception as e:
                log(f"[{name}] Error: {e}", "err")

    # Run tool-based (sequential — resource intensive)
    sf_file = str(proj_dir / "subfinder.txt")
    am_file = str(proj_dir / "amass.txt")
    sf_subs = subfinder_enum(domain, sf_file, log)
    am_subs = amass_enum(domain, am_file, log)
    all_subs.update(sf_subs); all_subs.update(am_subs)

    # Merge & deduplicate
    final = sorted(s for s in all_subs if s and not s.startswith("ERROR"))
    _save_log(project, "subdomains_all.txt", final)

    log(f"\n{'='*50}", "dim")
    log(f"[✓] TOTAL: {len(final)} unique subdomains", "ok")
    log(f"[✓] Saved: logs/{project}/subdomains_all.txt", "ok")
    log(f"{'='*50}\n", "dim")

    return {"domain": domain, "subdomains": final, "total": len(final),
            "sources": {k: len(v) for k,v in results.items()}}

# ── DNS Resolution (Python fallback) ─────────────────────────────
def resolve_subdomains(subdomains, project, threads=50, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[*] Resolving {len(subdomains)} subdomains ({threads} threads)", "info")
    resolved = {}; lock = threading.Lock()

    def _resolve(sub):
        try:
            ip = socket.gethostbyname(sub.strip())
            with lock: resolved[sub] = ip
        except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(_resolve, subdomains))

    result = [f"{sub} — {ip}" for sub, ip in sorted(resolved.items())]
    _save_log(project, "resolved_hosts.txt", result)
    _save_log(project, "resolved_ips.txt", list(set(resolved.values())))
    log(f"[✓] Resolved: {len(resolved)}/{len(subdomains)}", "ok")
    return resolved

# ── Shodan lookup ────────────────────────────────────────────────
def shodan_lookup(query, api_key="", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if not api_key:
        try: api_key = _cfg().get("api_keys",{}).get("shodan","")
        except Exception: pass
    if not api_key:
        log("[Shodan] No API key — skipping", "warn"); return []
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={urllib.parse.quote(query)}&minify=false"
        with urllib.request.urlopen(url, timeout=15) as r:
            data = json.loads(r.read())
        results = []
        for m in data.get("matches",[]):
            entry = {
                "ip":       m.get("ip_str",""),
                "port":     m.get("port",""),
                "org":      m.get("org",""),
                "product":  m.get("product",""),
                "version":  m.get("version",""),
                "vulns":    list(m.get("vulns",{}).keys()),
                "hostnames":m.get("hostnames",[]),
                "country":  m.get("location",{}).get("country_name",""),
            }
            results.append(entry)
            log(f"  [{entry['ip']}:{entry['port']}] {entry['org']} {entry['product']} {entry['version']}", "info")
            if entry["vulns"]:
                log(f"  [!] CVEs: {', '.join(entry['vulns'][:3])}", "ok")
        log(f"[Shodan] {len(results)} results for: {query}", "ok" if results else "dim")
        return results
    except Exception as e:
        log(f"[Shodan] Error: {e}", "err"); return []

# ── Build commands (GUI uses these) ──────────────────────────────
def build_cmd_subfinder(domain, output_file, api_key=""):
    return ["subfinder", "-d", domain, "-o", output_file, "-silent", "-all"]

def build_cmd_amass(domain, output_file):
    return ["amass", "enum", "-passive", "-d", domain, "-o", output_file, "-timeout", "4"]

def build_cmd_httpx(input_file, output_file):
    return ["httpx", "-l", input_file, "-o", output_file, "-silent",
            "-title", "-status-code", "-content-length", "-tech-detect",
            "-follow-redirects", "-threads", "50", "-timeout", "10"]

def merge_subdomains(project):
    all_subs = set()
    proj_dir = LOGS_DIR / project
    if not proj_dir.exists(): return []
    for fname in ["subdomains_all.txt","subfinder.txt","amass.txt","crt_sh.txt",
                  "hackertarget.txt","alienvault.txt","urlscan.txt"]:
        fp = proj_dir / fname
        if fp.exists():
            all_subs.update(l.strip() for l in fp.read_text(errors='replace').splitlines() if l.strip())
    return sorted(all_subs)

def censys_lookup(query, api_id="", api_secret="", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if not api_id:
        cfg = _cfg().get("api_keys",{})
        api_id = cfg.get("censys_id",""); api_secret = cfg.get("censys_secret","")
    if not api_id: log("[Censys] No API key", "warn"); return []
    try:
        import base64
        creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        url = "https://search.censys.io/api/v2/hosts/search"
        payload = json.dumps({"q":query,"per_page":50,"virtual_hosts":"INCLUDE"}).encode()
        req = urllib.request.Request(url, data=payload, headers={
            "Authorization":f"Basic {creds}", "Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        results = []
        for h in data.get("result",{}).get("hits",[]):
            results.append({
                "ip":       h.get("ip",""),
                "services": [f"{s.get('port','')}/{s.get('transport_protocol','')}" for s in h.get("services",[])],
                "name":     h.get("name",""),
            })
        log(f"[Censys] {len(results)} results", "ok" if results else "dim")
        return results
    except Exception as e:
        log(f"[Censys] {e}", "err"); return []


# ── Command builder wrappers required by main.py ─────────────────────────────

def build_cmd_assetfinder(domain: str, output_file: str = "") -> list:
    cmd = f'assetfinder --subs-only {domain}'
    if output_file:
        cmd += f' | tee {output_file}'
    cmd += ' 2>&1'
    return ['bash', '-c', cmd]

def build_cmd_theharvester(domain: str, sources: str = "all", limit: int = 500) -> list:
    return ['bash', '-c',
        f'theHarvester -d {domain} -b {sources} -l {limit} 2>&1 || '
        f'echo "[!] theHarvester not installed: pip3 install theHarvester"']

def build_cmd_spyhunt(domain: str) -> list:
    return ['bash', '-c',
        f'spyhunt -d {domain} 2>&1 || '
        f'python3 -c "import spyhunt; spyhunt.run(\'{domain}\')" 2>&1 || '
        f'echo "[!] spyhunt not installed: pip3 install spyhunt"']
