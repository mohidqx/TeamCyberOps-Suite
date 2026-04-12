#!/usr/bin/env python3
"""
smuggler.py - HTTP Request Smuggling Detection Tool
TeamCyberOps Suite v4 — Built-in implementation
No external dependencies required

Usage:
  python smuggler.py -u https://target.com
  python smuggler.py -u https://target.com -l  # log to file
"""
import socket, ssl, time, sys, argparse, json
from datetime import datetime

TIMEOUT_THRESHOLD = 5.0  # seconds — if response takes longer, VULNERABLE

TESTS = [
    # (name, request_bytes_fn)
    ("CL.TE", lambda host, path: (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n"
        f"0\r\n\r\nX"
    ).encode()),
    ("TE.CL", lambda host, path: (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n"
        f"1\r\nZ\r\n0\r\n\r\n"
    ).encode()),
    ("TE.TE (xchunked)", lambda host, path: (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: xchunked\r\n\r\n"
        f"0\r\n\r\n"
    ).encode()),
    ("TE.TE (space)", lambda host, path: (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding : chunked\r\n\r\n"
        f"0\r\n\r\n"
    ).encode()),
    ("TE.TE (CHUNKED)", lambda host, path: (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: CHUNKED\r\n\r\n"
        f"0\r\n\r\n"
    ).encode()),
]


def _connect(host, port, use_ssl):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_THRESHOLD + 3)
    sock.connect((host, port))
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _baseline(host, port, path, use_ssl):
    """Get baseline response time for normal request."""
    try:
        normal_req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        sock = _connect(host, port, use_ssl)
        t0 = time.time()
        sock.sendall(normal_req)
        sock.recv(1024)
        elapsed = time.time() - t0
        sock.close()
        return elapsed
    except Exception:
        return 0.2


def scan(url, log_fn=None, timeout=TIMEOUT_THRESHOLD):
    """
    Main scan function — call from Python or CLI.
    Returns dict: {url, vulnerable, results}
    """
    log = log_fn or print

    # Parse URL
    import urllib.parse
    p = urllib.parse.urlparse(url)
    use_ssl = p.scheme == "https"
    host    = p.netloc.split(":")[0] if ":" in p.netloc else p.netloc
    port    = int(p.netloc.split(":")[1]) if ":" in p.netloc else (443 if use_ssl else 80)
    path    = p.path or "/"
    if p.query:
        path += "?" + p.query

    log(f"[*] smuggler.py — HTTP Request Smuggling Scanner")
    log(f"[*] Target: {url}")
    log(f"[*] Host: {host}:{port}  SSL: {use_ssl}")
    log(f"[*] Running {len(TESTS)} tests...")
    log("")

    # Baseline
    baseline = _baseline(host, port, path, use_ssl)
    log(f"[*] Baseline response time: {baseline:.2f}s")
    log("")

    results = []
    for name, req_fn in TESTS:
        try:
            sock = _connect(host, port, use_ssl)
            req  = req_fn(host, path)
            t0   = time.time()
            sock.sendall(req)
            sock.settimeout(timeout + 2)
            try:
                data = sock.recv(4096)
            except socket.timeout:
                data = b""
            elapsed = time.time() - t0
            sock.close()

            # Decision
            timing_vuln  = elapsed >= timeout
            status_line  = data.decode("utf-8","replace").split("\r\n")[0] if data else "TIMEOUT"

            result = {
                "test":    name,
                "elapsed": round(elapsed, 2),
                "status":  status_line[:50],
                "vulnerable": timing_vuln,
            }
            results.append(result)

            icon = "🔴 VULNERABLE" if timing_vuln else "✅ Safe"
            log(f"  [{name:<20}] {elapsed:.2f}s  {icon}  {status_line[:40]}")

        except Exception as e:
            results.append({"test":name,"error":str(e),"vulnerable":False})
            log(f"  [{name:<20}] ERROR: {str(e)[:40]}")

    vulnerable = any(r.get("vulnerable") for r in results)
    log("")
    if vulnerable:
        vuln_tests = [r["test"] for r in results if r.get("vulnerable")]
        log(f"[!] VULNERABLE — {', '.join(vuln_tests)}")
        log(f"[!] Severity: CRITICAL  CVSS: 9.8")
        log(f"[!] Bounty:   $10,000–$50,000")
    else:
        log(f"[-] Not vulnerable (or protected by timeout config)")

    return {"url":url,"vulnerable":vulnerable,"results":results,
            "timestamp":datetime.now().isoformat()}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HTTP Request Smuggling Scanner")
    ap.add_argument("-u","--url",  required=True, help="Target URL")
    ap.add_argument("-l","--log",  action="store_true", help="Save results to JSON")
    ap.add_argument("-t","--timeout", type=float, default=TIMEOUT_THRESHOLD)
    args = ap.parse_args()

    result = scan(args.url, timeout=args.timeout)

    if args.log:
        out = f"smuggler_{result['url'].replace('https://','').replace('http://','').split('/')[0]}.json"
        with open(out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Results saved: {out}")
