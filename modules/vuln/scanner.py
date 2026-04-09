"""
TeamCyberOps Suite v4 — Vulnerability Scanner (Production Grade)
Nuclei · Nikto · Dalfox · SQLMap · Custom Checks · Python fallbacks
"""
import json, subprocess, re, urllib.request, urllib.parse, threading
import concurrent.futures, socket, ssl, time, os
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
CFG_PATH = BASE_DIR / "config.json"
LOGS_DIR = BASE_DIR / "logs"
NUCLEI_TEMPLATES = BASE_DIR / "nuclei-templates"

def _cfg():
    try:
        with open(CFG_PATH) as f: return json.load(f)
    except Exception: return {}

def _tool(name):
    import shutil; return shutil.which(name) is not None

def _run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception: return ""

def _save(project, filename, content):
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    (d / filename).write_text(content if isinstance(content,str) else '\n'.join(content))

def _req(url, method="GET", data=None, headers=None, timeout=10):
    h = {"User-Agent":"Mozilla/5.0 (TeamCyberOps/4)",**(headers or {})}
    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status":r.status,"body":r.read(5000).decode("utf-8","replace"),
                    "headers":dict(r.headers),"ok":True}
    except urllib.error.HTTPError as e:
        return {"status":e.code,"body":e.read(500).decode("utf-8","replace"),
                "headers":dict(e.headers),"ok":False}
    except Exception as ex:
        return {"status":None,"error":str(ex),"body":"","ok":False}

# ── NUCLEI ───────────────────────────────────────────────────────
def nuclei_scan(target, project, templates=None, severity="low,medium,high,critical",
                rate=100, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    out_file = str(LOGS_DIR / project / "nuclei.txt")
    json_out = str(LOGS_DIR / project / "nuclei.json")

    if not _tool("nuclei"):
        log("[nuclei] Not installed — running Python checks", "warn")
        return python_vuln_checks(target, project, log_cb=log)

    log(f"[nuclei] Scanning {target} (severity={severity})", "info")
    cmd = ["nuclei", "-u", target, "-severity", severity,
           "-c", str(rate), "-silent", "-no-color",
           "-o", out_file, "-json", "-json-export", json_out]

    # Use local templates if available
    if NUCLEI_TEMPLATES.exists() and any(NUCLEI_TEMPLATES.rglob("*.yaml")):
        cmd += ["-t", str(NUCLEI_TEMPLATES)]
    else:
        cmd += ["-tags", "cve,misconfig,exposure,rce,sqli,xss,ssrf,lfi"]

    if templates:
        for t in templates: cmd += ["-t", t]

    log(f"[nuclei] Command: {' '.join(cmd[:6])}...", "dim")
    out = _run(cmd, 600)

    findings = []
    for line in out.splitlines():
        if "[" in line and "]" in line:
            log(f"  {line}", "ok" if "critical" in line.lower() or "high" in line.lower() else "warn")
            findings.append(line)

    # Parse JSON results
    results = []
    try:
        if os.path.isfile(json_out):
            for line in open(json_out):
                try:
                    d = json.loads(line)
                    results.append({
                        "template_id": d.get("template-id",""),
                        "name":        d.get("info",{}).get("name",""),
                        "severity":    d.get("info",{}).get("severity","info").upper(),
                        "url":         d.get("matched-at",""),
                        "description": d.get("info",{}).get("description",""),
                        "tags":        d.get("info",{}).get("tags",[]),
                    })
                except Exception: pass
    except Exception: pass

    log(f"[nuclei] {len(results)} findings", "ok" if results else "dim")
    return results

# ── CUSTOM PYTHON VULNERABILITY CHECKS ───────────────────────────
EXPOSED_FILES = [
    ("/.env",                  "Environment Variables",    "CRITICAL"),
    ("/.git/HEAD",             "Git Repository Exposed",   "HIGH"),
    ("/.git/config",           "Git Config Exposed",       "HIGH"),
    ("/web.config",            "Web Config Exposed",       "HIGH"),
    ("/wp-config.php",         "WordPress Config",         "CRITICAL"),
    ("/config.php",            "PHP Config",               "HIGH"),
    ("/phpinfo.php",           "PHP Info",                 "MEDIUM"),
    ("/info.php",              "PHP Info",                 "MEDIUM"),
    ("/server-status",         "Apache Server Status",     "MEDIUM"),
    ("/server-info",           "Apache Server Info",       "MEDIUM"),
    ("/actuator",              "Spring Actuator",          "HIGH"),
    ("/actuator/env",          "Spring Actuator Env",      "CRITICAL"),
    ("/actuator/health",       "Spring Health",            "LOW"),
    ("/debug",                 "Debug Endpoint",           "HIGH"),
    ("/console",               "Console Exposed",          "CRITICAL"),
    ("/swagger-ui.html",       "Swagger UI",               "MEDIUM"),
    ("/api/swagger.json",      "API Swagger",              "MEDIUM"),
    ("/openapi.json",          "OpenAPI Spec",             "MEDIUM"),
    ("/.htaccess",             "Htaccess Exposed",         "MEDIUM"),
    ("/backup.zip",            "Backup File",              "CRITICAL"),
    ("/backup.sql",            "Database Backup",          "CRITICAL"),
    ("/db.sql",                "Database Dump",            "CRITICAL"),
    ("/dump.sql",              "Database Dump",            "CRITICAL"),
    ("/.aws/credentials",      "AWS Credentials",          "CRITICAL"),
    ("/crossdomain.xml",       "Cross-Domain Policy",      "LOW"),
    ("/robots.txt",            "Robots.txt",               "INFO"),
    ("/.DS_Store",             "DS_Store Leaked",          "LOW"),
    ("/Makefile",              "Makefile Exposed",         "LOW"),
    ("/package.json",          "Package.json Exposed",     "LOW"),
    ("/composer.json",         "Composer Config",          "LOW"),
    ("/.dockerignore",         "Docker Config",            "LOW"),
    ("/docker-compose.yml",    "Docker Compose",           "HIGH"),
    ("/Dockerfile",            "Dockerfile Exposed",       "LOW"),
    ("/graphql",               "GraphQL Endpoint",         "MEDIUM"),
    ("/api/graphql",           "GraphQL API",              "MEDIUM"),
    ("/__debug__",             "Debug Django",             "HIGH"),
    ("/_profiler",             "Symfony Profiler",         "HIGH"),
    ("/trace",                 "Trace Endpoint",           "MEDIUM"),
    ("/.git-credentials",      "Git Credentials",          "CRITICAL"),
    ("/config.yml",            "YAML Config",              "HIGH"),
    ("/config.yaml",           "YAML Config",              "HIGH"),
    ("/settings.py",           "Django Settings",          "HIGH"),
    ("/application.properties","Spring Config",            "HIGH"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS",                    "MEDIUM"),
    "Content-Security-Policy":   ("Missing CSP",                     "MEDIUM"),
    "X-Frame-Options":           ("Missing Clickjacking Protection",  "MEDIUM"),
    "X-Content-Type-Options":    ("Missing MIME Sniffing Protection", "LOW"),
    "Referrer-Policy":           ("Missing Referrer Policy",         "LOW"),
    "Permissions-Policy":        ("Missing Permissions Policy",       "LOW"),
}

INJECTION_TESTS = [
    ("SQLi Error",    "?id=1'",          ["SQL syntax","mysql_fetch","You have an error","ORA-","PostgreSQL","SQLITE_ERROR"],"HIGH"),
    ("SQLi Boolean",  "?id=1 AND 1=1",   ["200"],"MEDIUM"),
    ("XSS Reflect",   "?q=<b>xsstest",   ["<b>xsstest"],"HIGH"),
    ("Path Traversal","?file=../../etc/passwd",["root:x:","bin/bash","www-data"],"HIGH"),
    ("SSTI",          "?name={{7*7}}",    ["49"],"HIGH"),
    ("CRLF Inject",   "?url=%0d%0aCRLF-Test:1",["CRLF-Test"],"HIGH"),
    ("Open Redirect", "?url=https://evil.com",  [],"MEDIUM"),
]

def python_vuln_checks(target, project, log_cb=None):
    """Comprehensive Python-based vulnerability checks — no tools needed."""
    log = log_cb or (lambda m,t='': None)
    base = target.rstrip("/")
    if not base.startswith("http"): base = "https://" + base
    log(f"[Python Checks] {base}", "info")
    findings = []

    # 1. Exposed sensitive files
    log("\n[*] Checking exposed files...", "dim")
    def _check_file(path_sev):
        path, name, sev = path_sev
        r = _req(base + path, timeout=6)
        if r.get("status") in (200, 403):
            findings.append({"name":name,"url":base+path,"status":r["status"],"severity":sev})
            log(f"  [{r['status']}] {name}: {base+path}", "ok" if sev in ("CRITICAL","HIGH") else "warn")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(_check_file, EXPOSED_FILES))

    # 2. Security headers
    log("\n[*] Checking security headers...", "dim")
    r = _req(base)
    if r.get("headers"):
        for header, (issue, sev) in SECURITY_HEADERS.items():
            present = any(k.lower() == header.lower() for k in r["headers"])
            if not present:
                findings.append({"name":issue,"url":base,"severity":sev,"type":"Missing Header"})
                log(f"  [!] {issue}", "warn")
            else:
                log(f"  [+] {header}: present", "dim")

    # 3. Basic injection tests
    log("\n[*] Testing injection vectors...", "dim")
    for name, param, indicators, sev in INJECTION_TESTS:
        test_url = base + param
        try:
            r2 = _req(test_url, timeout=8)
            body = r2.get("body","")
            if indicators:
                if any(ind.lower() in body.lower() for ind in indicators):
                    findings.append({"name":name,"url":test_url,"severity":sev,"type":"Injection"})
                    log(f"  [!] {name}: {test_url}", "ok")
            elif r2.get("status") in (301,302,303):
                loc = r2.get("headers",{}).get("Location","")
                if "evil.com" in loc:
                    findings.append({"name":name,"url":test_url,"severity":sev,"type":"Redirect"})
                    log(f"  [!] {name}: redirects to {loc}", "ok")
        except Exception: pass

    # 4. SSL/TLS checks
    log("\n[*] Checking SSL/TLS...", "dim")
    try:
        import ssl as _ssl
        host = urllib.parse.urlparse(base).netloc.split(":")[0]
        ctx = _ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (exp - datetime.utcnow()).days
                if days_left < 30:
                    findings.append({"name":f"SSL Expiring in {days_left} days","url":base,"severity":"HIGH","type":"SSL"})
                    log(f"  [!] SSL expires in {days_left} days", "warn")
                else:
                    log(f"  [+] SSL valid, expires in {days_left} days", "dim")
        # Check old protocols
        for proto in [_ssl.PROTOCOL_TLSv1, _ssl.PROTOCOL_TLSv1_1] if hasattr(_ssl,'PROTOCOL_TLSv1') else []:
            try:
                old_ctx = _ssl.SSLContext(proto)
                old_ctx.check_hostname = False; old_ctx.verify_mode = _ssl.CERT_NONE
                with socket.create_connection((host,443),timeout=3) as s2:
                    with old_ctx.wrap_socket(s2,server_hostname=host): pass
                findings.append({"name":"Old TLS Protocol Accepted","url":base,"severity":"MEDIUM","type":"SSL"})
                log(f"  [!] Old TLS protocol accepted", "warn")
            except Exception: pass
    except Exception: pass

    # 5. HTTP methods
    log("\n[*] Checking dangerous HTTP methods...", "dim")
    for method in ["PUT","DELETE","TRACE","OPTIONS"]:
        try:
            r3 = _req(base, method=method, timeout=5)
            if r3.get("status") in (200,201,204,405):
                if method == "TRACE" and "TRACE" in r3.get("body","").upper():
                    findings.append({"name":f"TRACE Method Enabled (XST)","url":base,"severity":"LOW","type":"HTTP Method"})
                    log(f"  [!] TRACE method enabled", "warn")
                elif method in ("PUT","DELETE") and r3.get("status") in (200,201,204):
                    findings.append({"name":f"{method} Method Allowed","url":base,"severity":"MEDIUM","type":"HTTP Method"})
                    log(f"  [!] {method} allowed", "warn")
                else:
                    log(f"  [i] {method}: {r3.get('status')}", "dim")
        except Exception: pass

    _save(project, "vuln_checks.txt",
          [f"[{f['severity']}] {f['name']}: {f['url']}" for f in findings])
    log(f"\n[✓] {len(findings)} vulnerabilities found", "ok" if findings else "dim")
    return findings

# ── XSS Scanner ──────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<details open ontoggle=alert(1)>',
    '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
]

def scan_xss(urls, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if _tool("dalfox"):
        log("[dalfox] Running XSS scan", "info")
        if isinstance(urls, list):
            tmp = str(LOGS_DIR / project / "_xss_urls.txt")
            (LOGS_DIR/project).mkdir(parents=True,exist_ok=True)
            open(tmp,'w').write('\n'.join(urls))
            out = _run(["dalfox","file",tmp,"--silence","--skip-mining-dom"], 300)
        else:
            out = _run(["dalfox","url",urls,"--silence"], 120)
        findings = [l for l in out.splitlines() if "POC" in l.upper() or "FOUND" in l.upper() or "[V]" in l]
        for f in findings: log(f"  [XSS] {f}", "ok")
        return findings

    # Python fallback
    log("[XSS] dalfox not found — Python XSS check", "warn")
    findings = []
    url_list = urls if isinstance(urls, list) else [urls]
    for url in url_list[:50]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            params = {"q": ["test"], "search": ["test"], "id": ["1"]}
        for param in list(params.keys())[:3]:
            for payload in XSS_PAYLOADS[:4]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                try:
                    r = _req(test_url, timeout=6)
                    if payload in r.get("body","") or urllib.parse.quote(payload) in r.get("body",""):
                        findings.append({"url":test_url,"param":param,"payload":payload,"type":"Reflected XSS"})
                        log(f"  [XSS] Reflected in {param}: {test_url[:60]}", "ok")
                except Exception: pass
    return findings

# ── SQLi Scanner ─────────────────────────────────────────────────
SQLI_ERRORS = [
    "SQL syntax","mysql_fetch","You have an error","ORA-","PostgreSQL",
    "SQLITE_ERROR","Microsoft SQL","Unclosed quotation","ODBC SQL",
    "DB2 SQL","Dynamic SQL","SQL Server","syntax error","mysql error",
    "Warning: mysql","Zend_Db","pg_query","mysql_real_escape_string",
]

def scan_sqli(urls, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if _tool("sqlmap"):
        log("[sqlmap] Running SQL injection scan", "info")
        url_list = urls if isinstance(urls,list) else [urls]
        results = []
        for url in url_list[:10]:
            if "?" in url:
                out = _run(["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2",
                            "--output-dir", str(LOGS_DIR/project/"sqlmap"), "-q"], 300)
                if "injectable" in out.lower() or "Parameter" in out:
                    log(f"  [SQLi] FOUND: {url[:60]}", "ok")
                    results.append({"url":url,"tool":"sqlmap"})
        return results

    # Python fallback
    log("[SQLi] sqlmap not found — Python SQLi check", "warn")
    findings = []
    url_list = urls if isinstance(urls,list) else [urls]
    payloads = ["'","''","' OR '1'='1","' OR 1=1--","' AND SLEEP(5)--","1; DROP TABLE--"]
    for url in url_list[:30]:
        parsed = urllib.parse.urlparse(url)
        for param in list(urllib.parse.parse_qs(parsed.query).keys())[:3]:
            for payload in payloads:
                test = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(payload)}"
                try:
                    t0 = time.time()
                    r = _req(test, timeout=8)
                    elapsed = time.time()-t0
                    body = r.get("body","")
                    if any(e.lower() in body.lower() for e in SQLI_ERRORS):
                        findings.append({"url":test,"param":param,"type":"Error-Based SQLi","payload":payload})
                        log(f"  [SQLi] Error-based: {param} in {url[:50]}", "ok")
                    elif elapsed > 4.5 and "SLEEP" in payload:
                        findings.append({"url":test,"param":param,"type":"Time-Based SQLi","elapsed":elapsed})
                        log(f"  [SQLi] Time-based ({elapsed:.1f}s): {param}", "ok")
                except Exception: pass
    return findings

# ── NIKTO checks ─────────────────────────────────────────────────
def nikto_scan(target, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if not _tool("nikto"):
        log("[nikto] Not installed — skipping", "warn"); return []
    out_file = str(LOGS_DIR / project / "nikto.txt")
    log(f"[nikto] Scanning {target}", "info")
    out = _run(["nikto", "-h", target, "-o", out_file, "-Format", "txt", "-C", "all", "-Tuning", "13457x"], 300)
    findings = [l for l in out.splitlines() if l.startswith("+") and "OSVDB" not in l]
    for f in findings[:20]: log(f"  {f}", "warn")
    log(f"[nikto] {len(findings)} findings", "ok" if findings else "dim")
    return findings

# ── Full vulnerability scan ──────────────────────────────────────
def full_scan(target, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"\n{'='*50}", "dim")
    log(f"[*] FULL VULN SCAN: {target}", "info")
    log(f"{'='*50}\n", "dim")
    all_findings = []
    all_findings.extend(python_vuln_checks(target, project, log))
    all_findings.extend(nuclei_scan(target, project, log_cb=log) or [])
    nikto_results = nikto_scan(target, project, log)
    log(f"\n[✓] Total findings: {len(all_findings)}", "ok" if all_findings else "dim")
    return all_findings

def build_cmd_nuclei(target=None, input_file=None, templates=None,
                     severity="low,medium,high,critical", output_file=None, rate="100"):
    cmd = ["nuclei", "-severity", severity, "-c", rate, "-silent", "-no-color"]
    if target: cmd += ["-u", target]
    elif input_file: cmd += ["-l", input_file]
    if templates:
        for t in templates: cmd += ["-t", t]
    elif NUCLEI_TEMPLATES.exists():
        cmd += ["-t", str(NUCLEI_TEMPLATES)]
    else:
        cmd += ["-tags", "cve,misconfig,exposure,tech,vulnerability"]
    if output_file: cmd += ["-o", output_file]
    return cmd
