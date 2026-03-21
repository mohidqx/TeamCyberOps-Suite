"""
TeamCyberOps Suite v4 — 2FA/MFA Bypass Tester
Tests all known 2FA bypass techniques
Pure Python — no external dependencies
"""
import urllib.request, urllib.parse, json, re, time, threading, hashlib
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def _req(url, method="GET", data=None, headers=None, timeout=10) -> dict:
    """Simple HTTP request helper."""
    hdrs = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json",
            **(headers or {})}
    try:
        body_bytes = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp_body = r.read(2000).decode('utf-8', errors='replace')
            resp_hdrs = dict(r.headers)
            return {"status": r.status, "body": resp_body,
                    "headers": resp_hdrs, "ok": True}
    except urllib.error.HTTPError as e:
        body = e.read(500).decode('utf-8', errors='replace')
        return {"status": e.code, "body": body, "headers": dict(e.headers), "ok": False}
    except Exception as ex:
        return {"status": None, "error": str(ex), "ok": False}


# ═══ TEST 1: OTP in Response ════════════════════════════════════
def test_otp_in_response(login_url: str, username: str, password: str,
                          log_cb=None) -> dict:
    """Check if OTP is leaked in login/2FA response."""
    log     = log_cb or (lambda m, t='': None)
    result  = {"technique": "OTP Leakage in Response", "vulnerable": False, "findings": []}
    log(f"  [*] Testing OTP leakage in response...", "info")
    r = _req(login_url, "POST", {"username": username, "password": password})
    if not r.get('ok') and not r.get('body'):
        result["error"] = r.get('error', 'Request failed'); return result
    body    = r.get('body', '')
    headers = r.get('headers', {})
    # Check for OTP patterns in response
    otp_patterns = [
        (r'"otp"\s*:\s*"?(\d{4,8})"?',      "OTP in JSON body"),
        (r'"code"\s*:\s*"?(\d{4,8})"?',     "Code in JSON body"),
        (r'"token"\s*:\s*"?(\d{4,8})"?',    "Token in JSON body"),
        (r'"pin"\s*:\s*"?(\d{4,8})"?',      "PIN in JSON body"),
        (r'value="(\d{4,8})"',               "OTP in HTML input"),
        (r'otp=(\d{4,8})',                   "OTP in URL/body"),
    ]
    for pattern, label in otp_patterns:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            result["vulnerable"] = True
            result["findings"].append({"label": label, "value": m.group(1)})
            log(f"  [!] {label}: {m.group(1)}", "ok")
    # Check headers
    for header_name in ['X-OTP', 'X-Code', 'X-Token', 'X-PIN', 'X-2FA']:
        if header_name.lower() in {k.lower(): v for k, v in headers.items()}:
            result["vulnerable"] = True
            result["findings"].append({"label": f"OTP in header {header_name}",
                                       "value": headers.get(header_name, "")})
            log(f"  [!] OTP in header {header_name}", "ok")
    if not result["vulnerable"]:
        log("  [-] No OTP leakage detected in response", "dim")
    return result


# ═══ TEST 2: Response Manipulation ══════════════════════════════
def test_response_manipulation(verify_url: str, wrong_otp: str = "000000",
                                 log_cb=None) -> dict:
    """Test if manipulating 2FA response bypasses verification."""
    log    = log_cb or (lambda m, t='': None)
    result = {"technique": "Response Manipulation", "vulnerable": False, "tests": []}
    log(f"  [*] Testing response manipulation...", "info")
    # Send wrong OTP and check what fields appear in response
    r = _req(verify_url, "POST", {"otp": wrong_otp, "code": wrong_otp})
    body = r.get('body', '')
    # Find boolean/status fields to flip
    fields = {
        "success":    re.search(r'"success"\s*:\s*(false|true)', body, re.I),
        "verified":   re.search(r'"verified"\s*:\s*(false|true)', body, re.I),
        "2fa_passed": re.search(r'"2fa_passed"\s*:\s*(false|true)', body, re.I),
        "valid":      re.search(r'"valid"\s*:\s*(false|true)', body, re.I),
        "error":      re.search(r'"error"\s*:\s*true', body, re.I),
    }
    for field, match in fields.items():
        if match:
            current_val = match.group(1) if match.lastindex else "true"
            flip_val    = "true" if current_val.lower() == "false" else "false"
            result["tests"].append({
                "field": field,
                "current": current_val,
                "flip_to": flip_val,
                "instruction": f'Intercept response → change "{field}": {current_val} → "{field}": {flip_val}'
            })
            log(f"  [?] Found field '{field}': {current_val} — try flipping to {flip_val}", "warn")
    # Check HTTP status bypass
    result["tests"].append({
        "field": "HTTP Status",
        "instruction": f"Intercept response (HTTP {r.get('status','?')}) → change to 200",
        "current": str(r.get('status','?'))
    })
    if result["tests"]:
        result["note"] = "Use Burp Suite or HTTP Replayer tab to intercept and modify responses"
    return result


# ═══ TEST 3: Rate Limit Check ════════════════════════════════════
def test_rate_limit(otp_url: str, attempts: int = 15,
                    log_cb=None) -> dict:
    """Check if 2FA OTP brute-force is rate limited."""
    log    = log_cb or (lambda m, t='': None)
    result = {"technique": "Rate Limit Check", "vulnerable": False,
              "locked_at": None, "attempts_before_lock": 0}
    log(f"  [*] Testing rate limiting ({attempts} attempts)...", "info")
    test_codes = ["000000","111111","123456","999999","123123",
                  "000001","000002","000003","000004","000005",
                  "111112","111113","111114","111115","111116"][:attempts]
    statuses = []
    for i, code in enumerate(test_codes):
        r = _req(otp_url, "POST", {"otp": code, "code": code})
        status = r.get('status', 0)
        statuses.append(status)
        if status == 429:
            result["locked_at"]             = i + 1
            result["attempts_before_lock"]  = i
            log(f"  [-] Rate limited at attempt {i+1} (HTTP 429)", "dim")
            break
        if status in (200, 400, 401, 403):
            log(f"  [?] Attempt {i+1}: HTTP {status}", "dim")
        time.sleep(0.3)

    if not result.get("locked_at") and len(statuses) >= attempts:
        result["vulnerable"] = True
        result["message"]    = (f"No rate limiting after {attempts} attempts! "
                                 f"OTP brute-force likely possible.")
        log(f"  [!] No rate limit after {attempts} attempts!", "ok")
    return result


# ═══ TEST 4: OTP Reuse ═══════════════════════════════════════════
def test_otp_reuse(verify_url: str, valid_otp: str,
                    session_cookie: str = "", log_cb=None) -> dict:
    """Check if a valid OTP can be reused after first use."""
    log    = log_cb or (lambda m, t='': None)
    result = {"technique": "OTP Reuse", "vulnerable": False}
    log(f"  [*] Testing OTP reuse with code: {valid_otp}...", "info")
    headers = {}
    if session_cookie:
        headers["Cookie"] = session_cookie
    # First use
    r1 = _req(verify_url, "POST", {"otp": valid_otp}, headers=headers)
    # Second use (immediate reuse)
    r2 = _req(verify_url, "POST", {"otp": valid_otp}, headers=headers)
    result["first_use"]  = {"status": r1.get('status'), "body": r1.get('body','')[:100]}
    result["second_use"] = {"status": r2.get('status'), "body": r2.get('body','')[:100]}
    if r1.get('status') == 200 and r2.get('status') == 200:
        result["vulnerable"] = True
        result["message"]    = "OTP accepted twice! Not invalidated after first use."
        log(f"  [!] OTP REUSE WORKS — same code accepted twice!", "ok")
    else:
        log(f"  [-] OTP properly invalidated after first use", "dim")
    return result


# ═══ TEST 5: Skip 2FA Step ═══════════════════════════════════════
def test_skip_2fa(endpoints: dict, session_cookie: str = "",
                  log_cb=None) -> dict:
    """Test if 2FA step can be skipped by directly accessing post-2FA endpoint."""
    log    = log_cb or (lambda m, t='': None)
    result = {"technique": "Skip 2FA Step", "tests": []}
    log(f"  [*] Testing 2FA step bypass...", "info")
    headers = {}
    if session_cookie:
        headers["Cookie"] = session_cookie
    for label, url in endpoints.items():
        r = _req(url, headers=headers)
        test = {"endpoint": url, "label": label,
                "status": r.get('status')}
        if r.get('status') == 200:
            # Check if we got actual content or were redirected to login
            body = r.get('body','')
            redirected = 'login' in body.lower() or '2fa' in body.lower()
            test["vulnerable"]  = not redirected
            test["redirected"]  = redirected
            if not redirected:
                log(f"  [!] Bypassed 2FA at: {url}", "ok")
        result["tests"].append(test)
    return result


# ═══ TEST 6: Backup Code Patterns ═══════════════════════════════
COMMON_BACKUP_PATTERNS = [
    # Sequential
    "00000001","00000002","00000003",
    # Common defaults
    "12345678","87654321","11111111","00000000",
    # Hex-like
    "aabbccdd","deadbeef","cafebabe",
    # Date-based (today)
]

def generate_backup_code_wordlist(username: str = "", created_date: str = "") -> list:
    """Generate likely backup codes for testing."""
    codes = list(COMMON_BACKUP_PATTERNS)
    if created_date:
        # Date-based codes
        clean = created_date.replace('-','').replace('/','')
        codes.extend([clean, clean[::-1], clean + "00", "00" + clean])
    if username:
        # Username-based
        h = hashlib.md5(username.encode()).hexdigest()
        codes.extend([h[:8], h[8:16], h[-8:]])
    return codes[:100]


def run_full_audit(config: dict, log_cb=None) -> dict:
    """Run all 2FA bypass tests."""
    log     = log_cb or (lambda m, t='': None)
    results = {"timestamp": datetime.now().isoformat(), "config": config, "tests": []}
    tests   = [
        ("OTP in Response",      lambda: test_otp_in_response(
            config.get('login_url',''), config.get('username',''), config.get('password',''), log)),
        ("Response Manipulation", lambda: test_response_manipulation(
            config.get('verify_url',''), log_cb=log)),
        ("Rate Limiting",        lambda: test_rate_limit(
            config.get('verify_url',''), log_cb=log)),
    ]
    for name, fn in tests:
        log(f"\n  ── {name} {'─'*(46-len(name))}", "warn")
        try:
            r = fn()
            results["tests"].append({"name": name, "result": r})
            if r.get("vulnerable"):
                log(f"  🔴 VULNERABLE: {name}", "ok")
        except Exception as e:
            results["tests"].append({"name": name, "error": str(e)})
    results["vulnerable_count"] = sum(1 for t in results["tests"]
                                       if t.get("result",{}).get("vulnerable"))
    return results
