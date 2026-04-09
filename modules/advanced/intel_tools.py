"""
TeamCyberOps Suite v4 — Intelligence Tools
Shodan/Censys Auto-Exploit · Mass Vuln Scanner · Source Code Analyzer · API Tester
"""
import urllib.request, urllib.parse, json, re, threading, os, base64
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"


def _req(url, method="GET", data=None, headers=None, timeout=12):
    hdrs = {"User-Agent":"Mozilla/5.0",**(headers or {})}
    if data:
        hdrs.setdefault("Content-Type","application/json")
    try:
        body = json.dumps(data).encode() if isinstance(data,dict) else (data.encode() if isinstance(data,str) else data)
        r = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return {"status":resp.status,"body":resp.read(5000).decode("utf-8","replace"),"headers":dict(resp.headers),"ok":True}
    except urllib.error.HTTPError as e:
        return {"status":e.code,"body":e.read(500).decode("utf-8","replace"),"headers":dict(e.headers),"ok":False}
    except Exception as ex:
        return {"status":None,"error":str(ex),"body":"","ok":False}


# ── SHODAN AUTO-EXPLOIT ──────────────────────────────────────────
SHODAN_EXPLOITABLE = {
    "elasticsearch": {"check_path":"/","indicator":'"cluster_name"',"severity":"CRITICAL","desc":"Elasticsearch open (unauthenticated access)"},
    "mongodb":       {"check_path":"","port":27017,"indicator":"MongoDB","severity":"CRITICAL","desc":"MongoDB exposed (no auth)"},
    "redis":         {"port":6379,"cmd":"INFO","indicator":"redis_version","severity":"CRITICAL","desc":"Redis exposed (no auth)"},
    "jenkins":       {"check_path":"/api/json","indicator":'"jobs"',"severity":"HIGH","desc":"Jenkins API accessible"},
    "docker_api":    {"check_path":"/info","port":2375,"indicator":'"DockerRootDir"',"severity":"CRITICAL","desc":"Docker API exposed"},
    "kubernetes":    {"check_path":"/api/v1/namespaces","port":8080,"indicator":'"kind":"NamespaceList"',"severity":"CRITICAL","desc":"K8s API unauthenticated"},
    "phpmyadmin":    {"check_path":"/phpmyadmin/","indicator":"phpMyAdmin","severity":"HIGH","desc":"phpMyAdmin exposed"},
    "grafana":       {"check_path":"/api/org","indicator":'"id"',"severity":"HIGH","desc":"Grafana API accessible"},
    "kibana":        {"check_path":"/api/status","indicator":'"version"',"severity":"HIGH","desc":"Kibana exposed"},
}

def shodan_auto_exploit(target_host, shodan_api_key="", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] Shodan auto-exploit: {target_host}", "info")
    
    # First get Shodan data if API key provided
    shodan_data = {}
    if shodan_api_key:
        try:
            r = _req(f"https://api.shodan.io/shodan/host/{target_host}?key={shodan_api_key}")
            if r.get("ok"):
                shodan_data = json.loads(r["body"])
                ports = [d.get("port") for d in shodan_data.get("data",[])]
                log(f"[*] Shodan: {len(ports)} open ports", "info")
        except Exception: pass
    
    # Test each service
    for service, cfg in SHODAN_EXPLOITABLE.items():
        port = cfg.get("port", 80)
        path = cfg.get("check_path","")
        url = f"http://{target_host}:{port}{path}"
        try:
            r = _req(url, timeout=6)
            if r.get("body") and cfg["indicator"] in r["body"]:
                results.append({
                    "service": service,
                    "url": url,
                    "severity": cfg["severity"],
                    "description": cfg["desc"],
                    "response_preview": r["body"][:200],
                })
                log(f"[!] [{cfg['severity']}] {service}: {cfg['desc']}", "ok")
        except Exception: pass
    
    log(f"[✓] Found {len(results)} exploitable services", "ok" if results else "dim")
    return {"target":target_host,"findings":results,"shodan_data":shodan_data}


# ── MASS VULNERABILITY SCANNER ───────────────────────────────────
MASS_CHECKS = [
    {"name":"Admin Panel",     "path":"/admin/",           "indicator":["admin","login","dashboard"],"sev":"HIGH"},
    {"name":"phpMyAdmin",      "path":"/phpmyadmin/",       "indicator":["phpMyAdmin","mysql"],"sev":"HIGH"},
    {"name":"Exposed .env",    "path":"/.env",              "indicator":["APP_KEY","DB_PASSWORD","SECRET"],"sev":"CRITICAL"},
    {"name":"Exposed .git",    "path":"/.git/HEAD",         "indicator":["ref:","HEAD"],"sev":"HIGH"},
    {"name":"Git Config",      "path":"/.git/config",       "indicator":["[core]","[remote"],"sev":"HIGH"},
    {"name":"AWS Credentials", "path":"/.aws/credentials",  "indicator":["aws_access_key"],"sev":"CRITICAL"},
    {"name":"Docker API",      "path":"/v1.41/info",        "indicator":["DockerRootDir"],"sev":"CRITICAL"},
    {"name":"Swagger UI",      "path":"/swagger-ui.html",   "indicator":["Swagger UI","swagger"],"sev":"MEDIUM"},
    {"name":"API Docs",        "path":"/api/docs",          "indicator":["openapi","swagger"],"sev":"MEDIUM"},
    {"name":"Laravel Debug",   "path":"/",                  "indicator":["Whoops! There was an error"],"sev":"MEDIUM"},
    {"name":"Debug Mode",      "path":"/debug",             "indicator":["debug","stack trace","traceback"],"sev":"MEDIUM"},
    {"name":"Server Status",   "path":"/server-status",     "indicator":["Apache Server Status","requests currently"],"sev":"MEDIUM"},
    {"name":"Backup File",     "path":"/backup.zip",        "indicator":[],"status_ok":200,"sev":"HIGH"},
    {"name":"DB Backup",       "path":"/db.sql",            "indicator":[],"status_ok":200,"sev":"CRITICAL"},
    {"name":"Config Backup",   "path":"/config.bak",        "indicator":[],"status_ok":200,"sev":"HIGH"},
    {"name":"Robots.txt",      "path":"/robots.txt",        "indicator":["Disallow"],"sev":"INFO"},
    {"name":"Sitemap",         "path":"/sitemap.xml",       "indicator":["<url>","<loc>"],"sev":"INFO"},
]

def mass_scan(targets, log_cb=None):
    """Scan multiple targets for common vulnerabilities."""
    log = log_cb or (lambda m,t='': None)
    all_results = {}
    log(f"[*] Mass scan: {len(targets)} targets, {len(MASS_CHECKS)} checks each", "info")
    
    def _scan_target(target):
        target_results = []
        base = target.rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base
        for check in MASS_CHECKS:
            try:
                url = base + check["path"]
                r = _req(url, timeout=6)
                if not r.get("body") and not r.get("status"): continue
                body = r.get("body","")
                status = r.get("status", 0)
                # Check indicators
                indicators_found = [ind for ind in check.get("indicator",[]) if ind.lower() in body.lower()]
                status_match = check.get("status_ok") and status == check["status_ok"]
                if indicators_found or status_match:
                    target_results.append({
                        "check": check["name"],
                        "url": url,
                        "severity": check["sev"],
                        "indicators": indicators_found,
                        "status": status,
                    })
                    log(f"  [{check['sev']}] {target}: {check['name']}", "ok" if check["sev"] in ("CRITICAL","HIGH") else "warn")
            except Exception: pass
        if target_results:
            all_results[target] = target_results
            log(f"[+] {target}: {len(target_results)} findings", "ok")
    
    threads = [threading.Thread(target=_scan_target, args=(t,), daemon=True) for t in targets]
    for th in threads: th.start()
    for th in threads: th.join()
    
    total = sum(len(v) for v in all_results.values())
    log(f"[✓] Mass scan done: {total} total findings across {len(all_results)} targets", "ok" if total else "dim")
    return {"targets":targets,"results":all_results,"total":total}


# ── SOURCE CODE ANALYZER (GitHub SAST) ──────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":    r'(?:aws.{0,20})?["\'][0-9a-zA-Z/+]{40}["\']',
    "GitHub Token":      r'ghp_[0-9a-zA-Z]{36}',
    "GitHub OAuth":      r'gho_[0-9a-zA-Z]{36}',
    "Slack Token":       r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
    "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "Stripe Key":        r'sk_(?:live|test)_[0-9a-zA-Z]{24}',
    "Twilio":            r'SK[0-9a-fA-F]{32}',
    "SendGrid":          r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    "JWT Token":         r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
    "Private Key":       r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "Database URL":      r'(?:mysql|postgres|mongodb|redis)://[^\s"\']{10,}',
    "Password in Code":  r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,30}["\']',
    "Secret in Code":    r'(?:secret|api_key|token)\s*=\s*["\'][^"\']{6,40}["\']',
    "Generic Token":     r'(?:Bearer |bearer )[a-zA-Z0-9\-_\.]{20,}',
}

VULN_PATTERNS = {
    "SQL Injection (raw)":   r'(?:execute|query)\s*\(\s*["\'].*%s.*["\']',
    "Command Injection":     r'(?:os\.system|subprocess\.call|eval)\s*\(.*\+',
    "Path Traversal":        r'open\([^)]*\+[^)]*\)',
    "Hardcoded IP":          r'\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "Debug Mode On":         r'DEBUG\s*=\s*True',
    "Insecure Deserialize":  r'pickle\.loads|yaml\.load\(',
    "Weak Crypto":           r'hashlib\.md5|hashlib\.sha1|DES\.',
    "SSL Verify Off":        r'verify\s*=\s*False',
    "Eval Usage":            r'\beval\s*\(',
}

def analyze_source_code(code_content, filename="unknown", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    findings = {"secrets":[],"vulnerabilities":[],"info":[]}
    log(f"[*] Analyzing: {filename} ({len(code_content)} chars)", "info")
    
    lines = code_content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                findings["secrets"].append({"type":name,"line":lineno,"content":line.strip()[:100]})
                log(f"[!] SECRET [{name}] L{lineno}: {line.strip()[:60]}", "ok")
        for name, pattern in VULN_PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                findings["vulnerabilities"].append({"type":name,"line":lineno,"content":line.strip()[:100]})
                log(f"[?] VULN [{name}] L{lineno}: {line.strip()[:60]}", "warn")
    
    total = len(findings["secrets"]) + len(findings["vulnerabilities"])
    log(f"[✓] Analysis done: {len(findings['secrets'])} secrets, {len(findings['vulnerabilities'])} vuln patterns", 
        "ok" if total else "dim")
    return {"filename":filename,"findings":findings,"total":total}


def analyze_github_repo(repo_url, github_token="", log_cb=None):
    """Fetch and analyze a GitHub repository for secrets/vulns."""
    log = log_cb or (lambda m,t='': None)
    all_findings = []
    
    # Parse repo URL
    match = re.search(r'github\.com/([^/]+)/([^/]+?)(?:\.git)?$', repo_url)
    if not match:
        log("[-] Invalid GitHub URL", "err"); return {"error":"Invalid URL"}
    
    owner, repo = match.group(1), match.group(2)
    log(f"[*] Scanning GitHub repo: {owner}/{repo}", "info")
    
    headers = {"Accept":"application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    # Get file tree
    try:
        r = _req(f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
                 headers=headers)
        if not r.get("ok"):
            log(f"[-] GitHub API error: {r.get('status')}", "err"); return {"error":"API error"}
        
        tree = json.loads(r["body"]).get("tree",[])
        code_files = [f for f in tree if f.get("type")=="blob" and
                      any(f["path"].endswith(ext) for ext in
                          [".py",".js",".ts",".php",".rb",".java",".go",".env",".json",".yml",".yaml",".xml",".config"])]
        
        log(f"[*] Found {len(code_files)} code files to scan", "info")
        
        for i, fobj in enumerate(code_files[:30]):  # limit to 30 files
            try:
                fc = _req(f"https://api.github.com/repos/{owner}/{repo}/contents/{fobj['path']}",
                          headers=headers)
                if fc.get("ok"):
                    content_data = json.loads(fc["body"])
                    if content_data.get("encoding") == "base64":
                        content = base64.b64decode(content_data["content"]).decode("utf-8","replace")
                        result = analyze_source_code(content, fobj["path"], log)
                        if result["total"] > 0:
                            all_findings.append(result)
            except Exception: pass
            
            if (i+1) % 5 == 0:
                log(f"  [{i+1}/{min(len(code_files),30)}] Scanning...", "dim")
    
    except Exception as e:
        log(f"[-] Error: {e}", "err")
        return {"error":str(e)}
    
    total = sum(f["total"] for f in all_findings)
    log(f"[✓] Repo scan done: {total} findings in {len(all_findings)} files", "ok" if total else "dim")
    return {"repo":f"{owner}/{repo}","files_scanned":min(len(code_files),30),"findings":all_findings,"total":total}


# ── API SECURITY TESTER (Swagger) ───────────────────────────────
def parse_swagger(swagger_url_or_json, log_cb=None):
    """Parse Swagger/OpenAPI spec and extract endpoints."""
    log = log_cb or (lambda m,t='': None)
    spec = None
    if isinstance(swagger_url_or_json, str) and swagger_url_or_json.startswith("http"):
        try:
            r = _req(swagger_url_or_json)
            spec = json.loads(r["body"])
            log(f"[✓] Swagger spec loaded from {swagger_url_or_json}", "ok")
        except Exception as e:
            log(f"[-] Failed to load spec: {e}", "err"); return None
    elif isinstance(swagger_url_or_json, dict):
        spec = swagger_url_or_json
    
    if not spec: return None
    
    endpoints = []
    # OpenAPI 3.x
    base_url = ""
    if "servers" in spec:
        base_url = spec["servers"][0].get("url","")
    elif "host" in spec:
        scheme = spec.get("schemes",["https"])[0]
        base_url = f"{scheme}://{spec['host']}{spec.get('basePath','')}"
    
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method in ("get","post","put","delete","patch","options"):
                params = []
                for p in details.get("parameters",[]):
                    params.append({"name":p.get("name"),"in":p.get("in"),"required":p.get("required",False)})
                endpoints.append({
                    "method":method.upper(), "path":path,
                    "url": base_url + path,
                    "summary": details.get("summary",""),
                    "params": params,
                    "auth": bool(details.get("security")),
                })
    
    log(f"[✓] Parsed {len(endpoints)} endpoints from Swagger spec", "ok")
    return {"base_url":base_url,"endpoints":endpoints,"total":len(endpoints)}


def test_api_endpoint(endpoint, auth_header="", log_cb=None):
    """Test a single API endpoint for common issues."""
    log = log_cb or (lambda m,t='': None)
    results = []
    url = endpoint.get("url","")
    method = endpoint.get("method","GET")
    if not url: return results
    
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    
    # 1. No auth test
    r_no_auth = _req(url, method)
    if r_no_auth.get("status") == 200 and endpoint.get("auth"):
        results.append({"type":"Auth Bypass","url":url,"detail":"Authenticated endpoint accessible without token"})
        log(f"[!] Auth bypass: {url}", "ok")
    
    # 2. IDOR test (replace IDs)
    if re.search(r'/\d+', url):
        idor_urls = [re.sub(r'/\d+', f'/{i}', url) for i in range(1,4)]
        for iu in idor_urls:
            r = _req(iu, method, headers=headers)
            if r.get("status") == 200:
                results.append({"type":"Potential IDOR","url":iu,"status":200})
    
    # 3. Method override
    for override in ["PUT","DELETE","PATCH"]:
        if method != override:
            r = _req(url, override, headers=headers)
            if r.get("status") in (200,201,204):
                results.append({"type":"Method Override","url":url,"method":override,"status":r["status"]})
                log(f"[?] Method {override} allowed on {url}", "warn")
    
    return results
