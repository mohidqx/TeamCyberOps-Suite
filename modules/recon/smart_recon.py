"""
TeamCyberOps Suite v4 — Smart Recon Workflow
Automated: GitHub Dorks → Google Dorks → Shodan → Subdomains → httpx → Tech Files → AI Suggestions
"""
import os, json, subprocess, threading
from pathlib import Path
from datetime import datetime

BASE_DIR  = Path(__file__).parent.parent.parent
LOGS_DIR  = BASE_DIR / "logs"
DB_DIR    = BASE_DIR / "db"

TECH_CATEGORIES = {
    "wordpress": [], "joomla": [], "drupal": [], "magento": [],
    "nginx": [], "apache": [], "iis": [], "cloudfront": [],
    "spring": [], "laravel": [], "django": [], "rails": [],
    "react": [], "angular": [], "vue": [], "nextjs": [],
    "php": [], "java": [], "python": [], "nodejs": [],
    "jenkins": [], "grafana": [], "kibana": [], "elastic": [],
    "aws": [], "azure": [], "gcp": [], "cloudflare": [],
    "mysql": [], "postgresql": [], "mongodb": [], "redis": [],
    "other": [],
}


def detect_tech_from_httpx_line(line: str) -> list:
    """Parse tech stack from httpx output line."""
    techs = []
    line_lower = line.lower()
    tech_map = {
        "wordpress": "wordpress", "joomla": "joomla", "drupal": "drupal",
        "nginx": "nginx", "apache": "apache", "iis": "iis",
        "cloudfront": "cloudfront", "spring": "spring", "laravel": "laravel",
        "django": "django", "rails": "rails", "react": "react",
        "angular": "angular", "vue": "vue", "nextjs": "nextjs",
        "php": "php", "java": "java", "python": "python", "node": "nodejs",
        "jenkins": "jenkins", "grafana": "grafana", "kibana": "kibana",
        "elasticsearch": "elastic", "amazon": "aws", "azure": "azure",
        "google cloud": "gcp", "cloudflare": "cloudflare",
        "mysql": "mysql", "postgresql": "postgresql", "mongodb": "mongodb",
        "redis": "redis",
    }
    for keyword, category in tech_map.items():
        if keyword in line_lower:
            techs.append(category)
    return list(set(techs)) or ["other"]


def save_tech_files(project: str, httpx_output_file: str) -> dict:
    """Parse httpx output and save subdomains categorized by tech."""
    tech_files = {k: [] for k in TECH_CATEGORIES}
    if not os.path.isfile(httpx_output_file):
        return {}
    with open(httpx_output_file) as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line: continue
        techs = detect_tech_from_httpx_line(line)
        url = line.split()[0] if line.split() else line
        for tech in techs:
            if tech in tech_files:
                tech_files[tech].append(url)
    # Save non-empty tech files
    saved = {}
    tech_dir = LOGS_DIR / project / "tech"
    tech_dir.mkdir(parents=True, exist_ok=True)
    for tech, urls in tech_files.items():
        if urls:
            outpath = tech_dir / f"{tech}.txt"
            with open(outpath, 'w') as f:
                f.write('\n'.join(set(urls)))
            saved[tech] = str(outpath)
    return saved


def build_smart_recon_commands(target: str, project: str) -> list:
    """
    Returns ordered list of (label, command, description) for smart recon workflow.
    Each step feeds into the next.
    """
    proj_dir = str(LOGS_DIR / project)
    os.makedirs(proj_dir, exist_ok=True)

    subs_file    = f"{proj_dir}/{target}_subs.txt"
    resolved     = f"{proj_dir}/{target}_resolved.txt"
    live_file    = f"{proj_dir}/{target}_httpx.txt"
    urls_file    = f"{proj_dir}/{target}_urls.txt"
    params_file  = f"{proj_dir}/{target}_params.txt"
    vuln_file    = f"{proj_dir}/{target}_vulns.txt"
    nuclei_out   = f"{proj_dir}/{target}_nuclei.txt"
    xss_out      = f"{proj_dir}/{target}_xss.txt"
    sqli_out     = f"{proj_dir}/{target}_sqli_candidates.txt"

    steps = [
        # ── Phase 1: Passive Intelligence ─────────────────────────
        ("1a. GitHub Dork", ["bash", "-c",
            f'echo "[*] GitHub dork: {target} password | api_key | secret"'],
            "Search GitHub for leaked credentials (manual step — opens in browser)"),

        ("1b. Subfinder (passive)", ["bash", "-c",
            f'subfinder -d {target} -silent -o {subs_file} 2>/dev/null || echo "[!] subfinder not found" && echo "[+] Subfinder done: $(wc -l < {subs_file} 2>/dev/null || echo 0) subs"'],
            "Passive subdomain enumeration via APIs"),

        ("1c. Amass (passive)", ["bash", "-c",
            f'amass enum -passive -d {target} -o /tmp/amass_{target}.txt 2>/dev/null; cat /tmp/amass_{target}.txt 2>/dev/null | anew {subs_file} > /dev/null; echo "[+] Amass done: $(wc -l < {subs_file}) total subs"'],
            "DNS intelligence gathering"),

        ("1d. Assetfinder", ["bash", "-c",
            f'assetfinder --subs-only {target} 2>/dev/null | anew {subs_file} > /dev/null; echo "[+] Assetfinder done: $(wc -l < {subs_file}) total subs"'],
            "Fast subdomain discovery"),

        ("1e. crt.sh", ["bash", "-c",
            f'curl -sk "https://crt.sh/?q=%25.{target}&output=json" 2>/dev/null | python3 -c "import json,sys; [print(e[\'name_value\'].replace(\'*.\',\'\')) for e in json.load(sys.stdin)]" 2>/dev/null | sort -u | anew {subs_file} > /dev/null; echo "[+] crt.sh done: $(wc -l < {subs_file}) total"'],
            "Certificate transparency logs"),

        # ── Phase 2: DNS Resolution ────────────────────────────────
        ("2a. DNS Resolution (dnsx)", ["bash", "-c",
            f'dnsx -l {subs_file} -silent -a -resp -o {resolved} 2>/dev/null || echo "[!] dnsx not found, skipping resolution" && echo "[+] Resolved: $(wc -l < {resolved} 2>/dev/null || echo 0)"'],
            "Bulk DNS resolution to find live subdomains"),

        # ── Phase 3: HTTP Probing + Tech Detection ─────────────────
        ("3a. httpx probe + tech detect", ["bash", "-c",
            f'httpx -l {subs_file} -silent -title -status-code -tech-detect -follow-redirects -o {live_file} 2>/dev/null || httpx-toolkit -l {subs_file} -silent -title -status-code -tech-detect -o {live_file} 2>/dev/null; echo "[+] Live hosts: $(wc -l < {live_file} 2>/dev/null || echo 0)"'],
            "HTTP probe all subdomains, detect tech stack"),

        ("3b. Save tech-specific files", ["bash", "-c",
            f'''python3 -c "
import os, json
from pathlib import Path
tech_dir = Path('{proj_dir}/tech'); tech_dir.mkdir(exist_ok=True)
tech_map = {{'wordpress':'wordpress','joomla':'joomla','nginx':'nginx','apache':'apache','iis':'iis',
             'php':'php','laravel':'laravel','django':'django','spring':'spring','java':'java',
             'jenkins':'jenkins','grafana':'grafana','aws':'aws','azure':'azure','cloudflare':'cloudflare',
             'react':'react','angular':'angular','wordpress.com':'wordpress'}}
files = {{}}
try:
    with open('{live_file}') as f: lines = f.readlines()
    for line in lines:
        url = line.split()[0] if line.split() else ''
        ll = line.lower()
        matched = False
        for kw, cat in tech_map.items():
            if kw in ll:
                files.setdefault(cat, []).append(url)
                matched = True
        if not matched: files.setdefault('other', []).append(url)
    for tech, urls in files.items():
        if urls:
            p = tech_dir / f'{{tech}}.txt'
            open(p,'w').write('\n'.join(set(urls)))
            print(f'[+] {{tech}}: {{len(set(urls))}} hosts saved to {{p}}')
except Exception as e: print(f'[!] {{e}}')
" 2>&1'''],
            "Categorize subdomains by detected tech stack into separate files"),

        # ── Phase 4: URL Discovery ─────────────────────────────────
        ("4a. GAU - Get All URLs", ["bash", "-c",
            f'echo {target} | gau --threads 10 2>/dev/null | anew {urls_file} > /dev/null; echo "[+] GAU URLs: $(wc -l < {urls_file} 2>/dev/null || echo 0)"'],
            "Fetch all known URLs from Wayback Machine + OTX + Common Crawl"),

        ("4b. Waybackurls", ["bash", "-c",
            f'echo {target} | waybackurls 2>/dev/null | anew {urls_file} > /dev/null; echo "[+] Total URLs: $(wc -l < {urls_file} 2>/dev/null || echo 0)"'],
            "Fetch archived URLs from Wayback Machine"),

        ("4c. Katana crawl", ["bash", "-c",
            f'katana -u https://{target} -d 3 -jc -silent 2>/dev/null | anew {urls_file} > /dev/null; echo "[+] Katana crawl done: $(wc -l < {urls_file}) total URLs"'],
            "Active JS-aware web crawling"),

        ("4d. Extract parameters", ["bash", "-c",
            f'cat {urls_file} 2>/dev/null | grep -E "\\?.*=" | sort -u > {params_file}; echo "[+] URLs with params: $(wc -l < {params_file})"'],
            "Extract all URLs with parameters for testing"),

        # ── Phase 5: Smart Vulnerability Scanning ─────────────────
        ("5a. Nuclei (critical/high)", ["bash", "-c",
            f'nuclei -l {live_file} -t cves/ -t vulnerabilities/ -t misconfiguration/ -t exposures/ -severity high,critical -c 50 -silent -o {nuclei_out} 2>/dev/null; echo "[+] Nuclei vulns: $(wc -l < {nuclei_out} 2>/dev/null || echo 0)"'],
            "Template-based vulnerability scanning on all live hosts"),

        ("5b. XSS scan (Dalfox)", ["bash", "-c",
            f'cat {params_file} 2>/dev/null | head -100 | dalfox pipe --silence 2>/dev/null | tee {xss_out}; echo "[+] XSS findings: $(wc -l < {xss_out} 2>/dev/null || echo 0)"'],
            "XSS parameter scanning with Dalfox"),

        ("5c. SQLi candidates (GF)", ["bash", "-c",
            f'cat {urls_file} 2>/dev/null | gf sqli 2>/dev/null | sort -u > {sqli_out}; echo "[+] SQLi candidates: $(wc -l < {sqli_out} 2>/dev/null || echo 0)"'],
            "Extract SQL injection candidate URLs using GF patterns"),

        ("5d. Takeover check (Subzy)", ["bash", "-c",
            f'subzy run --targets {subs_file} --hide-fails --concurrency 10 2>/dev/null | grep -v "\\.\\." | head -50; echo "[+] Takeover check done"'],
            "Check all subdomains for takeover vulnerability"),

        # ── Phase 6: Summary ───────────────────────────────────────
        ("6. Generate Summary", ["bash", "-c",
            f'''echo "
╔══════════════════════════════════════════════╗
║   SMART RECON SUMMARY — {target}
╠══════════════════════════════════════════════╣
║  Subdomains    : $(wc -l < {subs_file} 2>/dev/null || echo 0)
║  Live Hosts    : $(wc -l < {live_file} 2>/dev/null || echo 0)
║  Total URLs    : $(wc -l < {urls_file} 2>/dev/null || echo 0)
║  Param URLs    : $(wc -l < {params_file} 2>/dev/null || echo 0)
║  Nuclei Vulns  : $(wc -l < {nuclei_out} 2>/dev/null || echo 0)
║  XSS Found     : $(wc -l < {xss_out} 2>/dev/null || echo 0)
║  SQLi Targets  : $(wc -l < {sqli_out} 2>/dev/null || echo 0)
╚══════════════════════════════════════════════╝
"'''],
            "Generate recon summary"),
    ]
    return steps


def analyze_tech_for_attacks(tech_files: dict) -> list:
    """
    Given detected tech files, return prioritized attack suggestions.
    Returns list of dicts: {tech, hosts, attacks, severity}
    """
    from modules.recon.oneliners import get_tech_specific_oneliners
    suggestions = []

    ATTACK_MAP = {
        "wordpress": {
            "severity": "HIGH",
            "attacks": [
                "WPScan for vulnerable plugins/themes",
                "Check /wp-json/wp/v2/users for user enum",
                "Test xmlrpc.php for brute force",
                "Look for outdated plugins via Nuclei",
                "Try /wp-admin/ with common credentials",
            ]
        },
        "laravel": {
            "severity": "CRITICAL",
            "attacks": [
                "Check /.env for APP_KEY exposure",
                "Test Laravel debug mode (APP_DEBUG=true)",
                "PHP deserialization via Laravel gadgets",
                "Check /storage/logs/laravel.log",
            ]
        },
        "spring": {
            "severity": "CRITICAL",
            "attacks": [
                "Check /actuator/env /actuator/heapdump",
                "Log4Shell if Spring Boot < 2.6.1",
                "Spring4Shell (CVE-2022-22965)",
                "Spring Cloud Gateway SPEL injection",
            ]
        },
        "jenkins": {
            "severity": "CRITICAL",
            "attacks": [
                "Check /script endpoint for Groovy RCE",
                "Check unauthenticated /api/json",
                "Jenkins RCE via Groovy console",
                "Check for CVE-2024-23897 (LFI)",
            ]
        },
        "django": {
            "severity": "HIGH",
            "attacks": [
                "Check DEBUG=True for stack traces",
                "Test admin interface /admin/",
                "Check for SSTI in template errors",
                "Django secret key exposure in .env",
            ]
        },
        "nodejs": {
            "severity": "HIGH",
            "attacks": [
                "Prototype pollution in JSON params",
                "Command injection via child_process",
                "SSTI in EJS/Pug/Handlebars templates",
                "Path traversal in express.static",
            ]
        },
        "php": {
            "severity": "HIGH",
            "attacks": [
                "LFI via php:// wrappers",
                "PHP deserialization gadgets",
                "RFI if allow_url_include=On",
                "PHAR deserialization attacks",
            ]
        },
        "nginx": {
            "severity": "MEDIUM",
            "attacks": [
                "Nginx alias traversal (alias off-by-slash)",
                "CRLF injection in proxy headers",
                "Check for nginx off-by-slash misconfig",
                "HTTP smuggling via proxy config",
            ]
        },
        "grafana": {
            "severity": "HIGH",
            "attacks": [
                "CVE-2021-43798 - Grafana LFI",
                "Check default credentials admin/admin",
                "SSRF via datasource URLs",
                "API key exposure in dashboards",
            ]
        },
        "elastic": {
            "severity": "CRITICAL",
            "attacks": [
                "Unauthenticated Elasticsearch API",
                "curl http://TARGET:9200/_cat/indices",
                "Data exfil via _search API",
                "Kibana CVE-2019-7609 RCE",
            ]
        },
        "aws": {
            "severity": "CRITICAL",
            "attacks": [
                "S3 bucket misconfiguration (list/read/write)",
                "SSRF to 169.254.169.254 metadata",
                "AWS key exposure in JS/config files",
                "Cognito misconfig for auth bypass",
            ]
        },
        "cloudflare": {
            "severity": "MEDIUM",
            "attacks": [
                "Find real IP via historical DNS/Shodan",
                "Direct IP access bypassing WAF",
                "SSL cert SAN enumeration",
            ]
        },
    }

    for tech, filepath in tech_files.items():
        if tech in ATTACK_MAP and os.path.isfile(filepath):
            with open(filepath) as f:
                hosts = [l.strip() for l in f if l.strip()]
            info = ATTACK_MAP[tech]
            suggestions.append({
                "tech":      tech.upper(),
                "severity":  info["severity"],
                "hosts":     hosts,
                "host_count": len(hosts),
                "attacks":   info["attacks"],
                "oneliners": get_tech_specific_oneliners(tech, hosts[0].split("//")[-1].split("/")[0] if hosts else "TARGET"),
                "file":      filepath,
            })

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    suggestions.sort(key=lambda x: sev_order.get(x["severity"], 99))
    return suggestions


def get_attack_surface_summary(project: str, target: str) -> dict:
    """Scan all result files and build attack surface summary."""
    proj_dir = LOGS_DIR / project
    summary = {
        "target": target,
        "subdomains": 0, "live_hosts": 0,
        "total_urls": 0, "param_urls": 0,
        "vulns": 0, "xss": 0, "sqli_candidates": 0,
        "tech_breakdown": {},
        "tech_files": {},
    }
    for key, fname in [
        ("subdomains", f"{target}_subs.txt"),
        ("live_hosts", f"{target}_httpx.txt"),
        ("total_urls", f"{target}_urls.txt"),
        ("param_urls", f"{target}_params.txt"),
        ("vulns",      f"{target}_nuclei.txt"),
        ("xss",        f"{target}_xss.txt"),
        ("sqli_candidates", f"{target}_sqli_candidates.txt"),
    ]:
        p = proj_dir / fname
        if p.exists():
            try:
                summary[key] = sum(1 for _ in open(p) if _.strip())
            except Exception:
                pass

    tech_dir = proj_dir / "tech"
    if tech_dir.exists():
        for f in tech_dir.glob("*.txt"):
            lines = sum(1 for _ in open(f) if _.strip())
            if lines:
                summary["tech_breakdown"][f.stem] = lines
                summary["tech_files"][f.stem] = str(f)

    return summary
