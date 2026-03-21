"""
TeamCyberOps Suite v4 — URL Discovery (Production Grade)
Wayback Machine · CommonCrawl · GAU · Katana · JS Crawling · Python fallback
"""
import json, urllib.request, urllib.parse, re, subprocess, threading
import concurrent.futures, os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"

def _tool(name):
    import shutil; return shutil.which(name) is not None

def _run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception: return ""

def _save(project, filename, lines):
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    p = d / filename; p.write_text('\n'.join(sorted(set(l.strip() for l in lines if l.strip()))))
    return len(lines)

# ── Wayback Machine ──────────────────────────────────────────────
def wayback_urls(domain, log_cb=None, limit=50000):
    log = log_cb or (lambda m,t='': None)
    log(f"[Wayback] Fetching URLs for {domain}", "info")
    all_urls = set()
    # API v2 (fast, JSON)
    try:
        url = (f"http://web.archive.org/cdx/search/cdx"
               f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
               f"&limit={limit}&filter=statuscode:200")
        req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        for entry in data[1:]:  # skip header
            all_urls.add(entry[0])
        log(f"[Wayback] {len(all_urls)} URLs", "ok")
    except Exception as e:
        log(f"[Wayback] Error: {e}", "err")
    # Also try waybackurls tool
    if _tool("waybackurls"):
        out = _run(["waybackurls", domain], 60)
        all_urls.update(l.strip() for l in out.splitlines() if l.strip().startswith("http"))
    return list(all_urls)

# ── Common Crawl ─────────────────────────────────────────────────
def commoncrawl_urls(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[CommonCrawl] Fetching index for {domain}", "info")
    all_urls = set()
    indexes = ["CC-MAIN-2024-10", "CC-MAIN-2023-50", "CC-MAIN-2023-23"]
    for index in indexes[:2]:
        try:
            url = (f"https://index.commoncrawl.org/{index}-index"
                   f"?url=*.{domain}/*&output=json&limit=5000")
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
            with urllib.request.urlopen(req, timeout=25) as r:
                for line in r.read().decode("utf-8","replace").splitlines():
                    try:
                        entry = json.loads(line)
                        all_urls.add(entry.get("url",""))
                    except Exception: pass
        except Exception as e:
            log(f"[CommonCrawl] {index}: {str(e)[:40]}", "dim")
    log(f"[CommonCrawl] {len(all_urls)} URLs", "ok" if all_urls else "dim")
    return list(all_urls)

# ── GAU ──────────────────────────────────────────────────────────
def gau_fetch(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if not _tool("gau"):
        log("[gau] Not installed", "dim"); return []
    log(f"[gau] Fetching URLs", "info")
    out = _run(["gau", "--threads", "10", domain], 120)
    urls = [l.strip() for l in out.splitlines() if l.strip().startswith("http")]
    log(f"[gau] {len(urls)} URLs", "ok" if urls else "dim")
    return urls

# ── Katana crawler ───────────────────────────────────────────────
def katana_crawl(target, project, depth=3, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    out_file = str(LOGS_DIR / project / "katana.txt")
    if not _tool("katana"):
        log("[katana] Not installed — Python crawler", "dim")
        return python_crawl(target, project, depth, log_cb=log)
    log(f"[katana] Crawling {target} (depth={depth})", "info")
    out = _run(["katana", "-u", target, "-d", str(depth), "-silent",
                "-o", out_file, "-jc", "-ef", "png,jpg,gif,svg,css"], 300)
    try:
        urls = [l.strip() for l in open(out_file) if l.strip()]
        log(f"[katana] {len(urls)} URLs", "ok" if urls else "dim")
        return urls
    except Exception: return []

# ── Python Web Crawler (fallback) ───────────────────────────────
def python_crawl(target, project, max_depth=2, max_urls=500, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[Crawler] Python crawl: {target} (depth={max_depth})", "info")
    from urllib.parse import urljoin, urlparse
    visited = set(); queue = [target]; found_urls = set()
    base_domain = urlparse(target).netloc

    for depth in range(max_depth):
        next_queue = []
        for url in queue:
            if url in visited or len(found_urls) > max_urls: continue
            visited.add(url)
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    body = r.read(30000).decode("utf-8","replace")
                # Extract links
                for href in re.findall(r'href=["\']([^"\']+)["\']', body):
                    abs_url = urljoin(url, href)
                    parsed = urlparse(abs_url)
                    if parsed.netloc == base_domain and abs_url not in visited:
                        found_urls.add(abs_url)
                        next_queue.append(abs_url)
                # Extract JS URLs
                for src in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body):
                    found_urls.add(urljoin(url, src))
                # Extract API endpoints from JS
                for ep in re.findall(r'["\']/(api/[^"\'?#\s]{3,60})["\']', body):
                    found_urls.add(f"{parsed.scheme}://{base_domain}/{ep}")
            except Exception: pass
        queue = next_queue[:100]
        log(f"  [Crawler] Depth {depth+1}: {len(found_urls)} URLs", "dim")

    result = list(found_urls)
    _save(project, "katana.txt", result)
    log(f"[Crawler] {len(result)} URLs found", "ok" if result else "dim")
    return result

# ── JavaScript URL Extractor ─────────────────────────────────────
def extract_from_js(js_urls, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[JS Extract] Analyzing {len(js_urls)} JS files", "info")
    endpoints = set()
    secrets = []

    JS_URL_PATTERNS = [
        r'"(/(?:api|v\d|rest|graphql|auth)[^"?#\s]{2,80})"',
        r"'(/(?:api|v\d|rest|graphql|auth)[^'?#\s]{2,80})'",
        r'`(/(?:api|v\d|rest|graphql|auth)[^`?#\s]{2,80})`',
        r'(?:url|endpoint|path|route)\s*[:=]\s*["\']([^"\']{10,80})["\']',
        r'axios\.[a-z]+\(["\']([^"\']{5,80})["\']',
        r'fetch\(["\']([^"\']{5,80})["\']',
    ]
    SECRET_PATTERNS = {
        "API Key":   r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
        "Token":     r'["\']?(?:token|access_token|auth_token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
        "AWS Key":   r'(AKIA[0-9A-Z]{16})',
        "GitHub":    r'(gh[pousr]_[A-Za-z0-9_]{36})',
        "Google":    r'(AIza[0-9A-Za-z\-_]{35})',
    }

    def _analyze_js(js_url):
        try:
            req = urllib.request.Request(js_url, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                code = r.read(500000).decode("utf-8","replace")
            for pat in JS_URL_PATTERNS:
                for m in re.finditer(pat, code):
                    endpoints.add(m.group(1))
            for sec_name, pat in SECRET_PATTERNS.items():
                for m in re.finditer(pat, code, re.I):
                    secrets.append({"type":sec_name,"value":m.group(1)[:40],"file":js_url})
                    log(f"  [SECRET] {sec_name} in {js_url.split('/')[-1]}", "ok")
        except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(_analyze_js, js_urls[:50]))

    log(f"[JS Extract] {len(endpoints)} endpoints, {len(secrets)} secrets", "ok" if endpoints or secrets else "dim")
    return {"endpoints": list(endpoints), "secrets": secrets}

# ── URL Categorizer ──────────────────────────────────────────────
def categorize_urls(urls):
    categories = {
        "Admin":   [], "API":      [], "Login":    [], "Upload":   [],
        "Config":  [], "Backup":   [], "Debug":    [], "Params":   [],
        "Static":  [], "Other":    [],
    }
    for url in urls:
        lower = url.lower()
        if any(k in lower for k in ["/admin","/dashboard","/panel","/manage","/cp"]): categories["Admin"].append(url)
        elif any(k in lower for k in ["/api/","/v1/","/v2/","/rest/","/graphql","/rpc"]): categories["API"].append(url)
        elif any(k in lower for k in ["/login","/signin","/auth","/oauth","/sso"]): categories["Login"].append(url)
        elif any(k in lower for k in ["/upload","/files","/media","/images","/attachments"]): categories["Upload"].append(url)
        elif any(k in lower for k in [".env","config","settings","application."]): categories["Config"].append(url)
        elif any(k in lower for k in ["backup","dump","export",".sql",".bak"]): categories["Backup"].append(url)
        elif any(k in lower for k in ["/debug","test","dev","staging","phpinfo"]): categories["Debug"].append(url)
        elif "?" in url: categories["Params"].append(url)
        elif any(url.endswith(ext) for ext in [".css",".js",".png",".jpg",".gif",".ico",".woff"]): categories["Static"].append(url)
        else: categories["Other"].append(url)
    return categories

# ── Full URL harvest ─────────────────────────────────────────────
def full_url_harvest(domain, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"\n{'='*50}", "dim")
    log(f"[*] URL HARVEST: {domain}", "info")
    log(f"{'='*50}\n", "dim")
    all_urls = set()

    wb = wayback_urls(domain, log)
    cc = commoncrawl_urls(domain, log)
    gu = gau_fetch(domain, log)
    all_urls.update(wb); all_urls.update(cc); all_urls.update(gu)
    _save(project, "wayback_urls.txt", list(all_urls))

    ka = katana_crawl(f"https://{domain}", project, log_cb=log)
    all_urls.update(ka)

    final = sorted(u for u in all_urls if u and u.startswith("http"))
    _save(project, "all_urls.txt", final)

    # Extract JS URLs and analyze
    js_urls = [u for u in final if u.endswith(".js") and "min.js" not in u][:50]
    if js_urls:
        js_result = extract_from_js(js_urls, project, log)
        _save(project, "js_endpoints.txt", js_result["endpoints"])
        if js_result["secrets"]:
            _save(project, "js_secrets.txt",
                  [f"{s['type']}: {s['value']} in {s['file']}" for s in js_result["secrets"]])

    # Extract parameters
    params = set()
    for url in final:
        parsed = urllib.parse.urlparse(url)
        for k in urllib.parse.parse_qs(parsed.query): params.add(k)
    _save(project, "parameters.txt", sorted(params))

    # Categorize
    cats = categorize_urls(final)
    _save(project, "urls_categorized.json",
          [json.dumps({"category":k,"urls":v,"count":len(v)}) for k,v in cats.items() if v])

    log(f"\n[✓] TOTAL: {len(final)} unique URLs", "ok")
    log(f"[*] Admin: {len(cats['Admin'])}  API: {len(cats['API'])}  Login: {len(cats['Login'])}  Params: {len(cats['Params'])}", "info")
    log(f"[✓] Saved: logs/{project}/all_urls.txt", "ok")
    return {"total":len(final),"urls":final,"categories":cats,"parameters":list(params)}


# ── Command builder wrappers required by main.py ─────────────────────────────

def build_cmd_gau(domain: str, output_file: str = "") -> list:
    cmd = f'gau {domain} --mc 200,301,302,403'
    if output_file:
        cmd += f' | tee {output_file}'
    cmd += ' 2>&1'
    return ['bash', '-c', cmd +
        ' || echo "[!] gau not installed: go install github.com/lc/gau/v2/cmd/gau@latest"']

def build_cmd_waybackurls(domain: str, output_file: str = "") -> list:
    cmd = f'echo {domain} | waybackurls'
    if output_file:
        cmd += f' | tee {output_file}'
    cmd += ' 2>&1'
    return ['bash', '-c', cmd +
        ' || echo "[!] waybackurls not installed: go install github.com/tomnomnom/waybackurls@latest"']

def build_cmd_katana(target: str, depth: int = 3, output_file: str = "") -> list:
    cmd = f'katana -u {target} -d {depth} -silent'
    if output_file:
        cmd += f' -o {output_file}'
    cmd += ' 2>&1'
    return ['bash', '-c', cmd +
        ' || echo "[!] katana not installed: go install github.com/projectdiscovery/katana/cmd/katana@latest"']

def build_cmd_hakrawler(target: str) -> list:
    return ['bash', '-c',
        f'echo {target} | hakrawler -u 2>&1 || '
        f'echo "[!] hakrawler not installed: go install github.com/hakluke/hakrawler@latest"']

def build_cmd_gospider(target: str, depth: int = 3) -> list:
    return ['bash', '-c',
        f'gospider -s {target} -d {depth} -c 10 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" 2>&1 || '
        f'echo "[!] gospider not installed: go install github.com/jaeles-project/gospider@latest"']

def build_cmd_subzy(targets_file: str) -> list:
    return ['bash', '-c',
        f'subzy run --targets {targets_file} --concurrency 100 --hide_fails --verify_ssl 2>&1 || '
        f'echo "[!] subzy not installed: go install github.com/LukaSikic/subzy@latest"']

def build_cmd_subjack(targets_file: str, fingerprints: str = "") -> list:
    cmd = f'subjack -w {targets_file} -t 100 -timeout 30 -o /tmp/subjack_results.txt -ssl'
    if fingerprints:
        cmd += f' -c {fingerprints}'
    cmd += ' 2>&1'
    return ['bash', '-c', cmd +
        ' || echo "[!] subjack not installed: go install github.com/haccer/subjack@latest"']

def build_cmd_arjun(target: str, method: str = "GET,POST",
                    wordlist: str = "", threads: int = 10) -> list:
    cmd = f'arjun -u {target} -m {method} -t {threads}'
    if wordlist:
        cmd += f' -w {wordlist}'
    cmd += ' 2>&1'
    return ['bash', '-c', cmd +
        ' || echo "[!] arjun not installed: pip3 install arjun"']

def dedupe_urls(urls: list) -> list:
    """Remove duplicate URLs keeping unique path+params combos."""
    import re as _re
    seen = set()
    result = []
    for url in urls:
        # Normalize: strip fragments, sort params
        url = url.split('#')[0].strip()
        if not url:
            continue
        # Create canonical key: path without param values
        key = _re.sub(r'=[^&]+', '=', url)
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result

def filter_interesting_urls(urls: list) -> dict:
    """Filter URLs into interesting categories for testing."""
    import re as _re
    categories = {
        'params':     [],
        'dynamic':    [],
        'sensitive':  [],
        'api':        [],
        'redirect':   [],
        'upload':     [],
        'sqli':       [],
        'lfi':        [],
    }
    sqli_params  = _re.compile(r'[?&](id|uid|user|cat|item|product|page|num|order|sort)=', _re.I)
    lfi_params   = _re.compile(r'[?&](file|path|page|doc|folder|root|include|dir|load)=', _re.I)
    redir_params = _re.compile(r'[?&](url|redirect|next|return|goto|dest|target|to|redir)=', _re.I)
    api_path     = _re.compile(r'/api/|/v\d+/|\.json|/graphql', _re.I)
    upload_path  = _re.compile(r'upload|import|attach|file', _re.I)
    sensitive    = _re.compile(r'\.(env|bak|sql|zip|tar|log|config|pem|key|secret)$', _re.I)
    dynamic      = _re.compile(r'\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)', _re.I)

    for url in urls:
        if '?' in url or '&' in url:
            categories['params'].append(url)
        if dynamic.search(url):
            categories['dynamic'].append(url)
        if sensitive.search(url):
            categories['sensitive'].append(url)
        if api_path.search(url):
            categories['api'].append(url)
        if redir_params.search(url):
            categories['redirect'].append(url)
        if upload_path.search(url):
            categories['upload'].append(url)
        if sqli_params.search(url):
            categories['sqli'].append(url)
        if lfi_params.search(url):
            categories['lfi'].append(url)
    return categories
