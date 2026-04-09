"""
TeamCyberOps Suite v4 — Tor-Anonymized Recon Engine
All intelligence gathered via Tor SOCKS5 (127.0.0.1:9050)
Exit nodes: RU/TR/AE/LB/IR
Methods:
  - Certificate Transparency (crt.sh) subdomain enumeration
  - DNS reconnaissance (A, MX, TXT, NS, SPF, DMARC)
  - WHOIS / ASN mapping
  - HTTP header analysis
  - EXIF metadata extraction
  - JavaScript source analysis
  - ArcGIS REST API enumeration
  - AWS infrastructure identification
  - News aggregation
"""
import json, re, socket, urllib.request, urllib.parse, urllib.error
import subprocess, threading, time, ssl, base64, struct
from pathlib import Path
from datetime import datetime
from typing import Optional

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

TOR_HOST  = "127.0.0.1"
TOR_PORT  = 9050
TOR_PROXY = f"socks5://{TOR_HOST}:{TOR_PORT}"
PREFERRED_EXIT_COUNTRIES = ["RU", "TR", "AE", "LB", "IR"]


class TorSOCKS5Handler(urllib.request.BaseHandler):
    def __init__(self, host=TOR_HOST, port=TOR_PORT):
        self.tor_host = host
        self.tor_port = port

    def _connect_tor(self, dest_host: str, dest_port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((self.tor_host, self.tor_port))
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            raise ConnectionError("Tor SOCKS5 handshake failed")
        host_bytes = dest_host.encode()
        sock.sendall(
            b"\x05\x01\x00\x03" +
            bytes([len(host_bytes)]) +
            host_bytes +
            struct.pack(">H", dest_port)
        )
        resp = sock.recv(10)
        if resp[1] != 0x00:
            raise ConnectionError(f"Tor SOCKS5 connect failed: {resp[1]:#x}")
        return sock

    def http_open(self, req):
        return self._open(req, False)

    def https_open(self, req):
        return self._open(req, True)

    def _open(self, req, use_ssl: bool):
        host = req.host
        port = 443 if use_ssl else 80
        if ":" in host:
            host, port = host.rsplit(":", 1)
            port = int(port)
        try:
            sock = self._connect_tor(host, port)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            selector = req.selector or "/"
            headers  = dict(req.headers)
            headers.setdefault("Host", req.host)
            headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0")
            headers.setdefault("Accept", "text/html,application/json,*/*;q=0.8")
            headers.setdefault("Connection", "close")
            method = req.get_method()
            data   = req.data
            request_line = f"{method} {selector} HTTP/1.1\r\n"
            header_str   = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            if data:
                header_str += f"Content-Length: {len(data)}\r\n"
            raw = (request_line + header_str + "\r\n").encode()
            if data:
                raw += data if isinstance(data, bytes) else data.encode()
            sock.sendall(raw)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 10 * 1024 * 1024:
                    break
            sock.close()
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                raise urllib.error.URLError("Malformed HTTP response")
            header_section = response[:header_end].decode("utf-8", errors="replace")
            body = response[header_end + 4:]
            lines   = header_section.split("\r\n")
            status  = int(lines[0].split(" ")[1]) if len(lines[0].split(" ")) > 1 else 200
            headers_dict = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers_dict[k.lower()] = v
            if headers_dict.get("transfer-encoding", "").lower() == "chunked":
                body = self._decode_chunked(body)
            if headers_dict.get("content-encoding", "") == "gzip":
                import gzip
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass

            class FakeResponse:
                def __init__(self, b, s, h):
                    self._body = b; self.status = s; self._headers = h
                    self.url = req.full_url
                def read(self): return self._body
                def getheader(self, k, d=""): return self._headers.get(k.lower(), d)
                def getheaders(self): return list(self._headers.items())
                def __enter__(self): return self
                def __exit__(self, *_): pass

            return FakeResponse(body, status, headers_dict)
        except Exception as e:
            raise urllib.error.URLError(f"Tor connection error: {e}")

    def _decode_chunked(self, data: bytes) -> bytes:
        out = b""
        while data:
            end = data.find(b"\r\n")
            if end == -1: break
            try:
                size = int(data[:end], 16)
            except Exception:
                break
            if size == 0: break
            out  += data[end + 2: end + 2 + size]
            data  = data[end + 2 + size + 2:]
        return out


def build_tor_opener():
    handler = TorSOCKS5Handler()
    opener  = urllib.request.OpenerDirector()
    opener.add_handler(handler)
    opener.add_handler(urllib.request.UnknownHandler())
    return opener


def tor_get(url: str, timeout: int = 20, headers: dict = None) -> dict:
    try:
        _check_tor()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        opener = build_tor_opener()
        resp   = opener._open(req)
        body   = resp.read()
        return {"ok": True, "body": body, "status": resp.status,
                "headers": dict(resp.getheaders()), "url": url, "error": None}
    except Exception as e:
        return {"ok": False, "body": b"", "status": 0,
                "headers": {}, "url": url, "error": str(e)}


def _check_tor() -> bool:
    try:
        s = socket.create_connection((TOR_HOST, TOR_PORT), timeout=3)
        s.close()
        return True
    except Exception:
        return False


def get_tor_ip() -> str:
    try:
        r = tor_get("https://check.torproject.org/api/ip", timeout=15)
        if r["ok"]:
            data = json.loads(r["body"])
            return data.get("IP", "unknown")
    except Exception:
        pass
    return "unknown"


def rotate_tor_identity():
    try:
        s = socket.create_connection(("127.0.0.1", 9051), timeout=5)
        s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
        s.close()
        time.sleep(2)
        return True
    except Exception:
        return False


# ── CERTIFICATE TRANSPARENCY ──────────────────────────────────

def ct_crtsh(domain: str, use_tor: bool = True) -> dict:
    url    = f"https://crt.sh/?q=%25.{domain}&output=json"
    result = {"source": "crt.sh", "subdomains": [], "count": 0, "error": None}
    try:
        if use_tor:
            r = tor_get(url, timeout=25)
            if not r["ok"]: raise Exception(r["error"])
            data = json.loads(r["body"])
        else:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name and not name.startswith("*"):
                    subs.add(name.lower())
        result["subdomains"] = sorted(list(subs))
        result["count"]      = len(subs)
    except Exception as e:
        result["error"] = str(e)
    return result


def ct_certspotter(domain: str, use_tor: bool = True) -> dict:
    url    = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    result = {"source": "certspotter", "subdomains": [], "count": 0, "error": None}
    try:
        if use_tor:
            r = tor_get(url, timeout=20)
            if not r["ok"]: raise Exception(r["error"])
            data = json.loads(r["body"])
        else:
            with urllib.request.urlopen(url, timeout=15) as r:
                data = json.loads(r.read())
        subs = set()
        for entry in data:
            for name in entry.get("dns_names", []):
                name = name.lstrip("*.")
                if domain in name:
                    subs.add(name.lower())
        result["subdomains"] = sorted(list(subs))
        result["count"]      = len(subs)
    except Exception as e:
        result["error"] = str(e)
    return result


def ct_hackertarget(domain: str, use_tor: bool = True) -> dict:
    url    = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    result = {"source": "hackertarget", "subdomains": [], "ips": {}, "count": 0, "error": None}
    try:
        if use_tor:
            r = tor_get(url, timeout=20)
            if not r["ok"]: raise Exception(r["error"])
            text = r["body"].decode("utf-8", errors="replace")
        else:
            with urllib.request.urlopen(url, timeout=15) as r:
                text = r.read().decode()
        subs = set(); ips = {}
        for line in text.strip().splitlines():
            if "," in line:
                sub, ip = line.split(",", 1)
                sub = sub.strip().lower()
                if domain in sub:
                    subs.add(sub)
                    ips[sub] = ip.strip()
        result["subdomains"] = sorted(list(subs))
        result["ips"]        = ips
        result["count"]      = len(subs)
    except Exception as e:
        result["error"] = str(e)
    return result


def merge_ct_results(*results) -> dict:
    all_subs = set(); sources = {}
    for r in results:
        src = r.get("source", "unknown")
        for sub in r.get("subdomains", []):
            all_subs.add(sub)
            sources.setdefault(sub, []).append(src)
    return {
        "all_unique":  sorted(list(all_subs)),
        "count":       len(all_subs),
        "per_source":  {r.get("source", "?"): r.get("subdomains", []) for r in results},
        "source_map":  sources,
    }


# ── DNS RECONNAISSANCE ────────────────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA"]


def dns_full_recon(domain: str) -> dict:
    results = {
        "domain": domain, "records": {}, "spf": None, "dmarc": None,
        "dkim": [], "zone_transfer_possible": False, "interesting": [], "error": None,
    }

    def _dig(qtype: str, name: str = None) -> list:
        try:
            target = name or domain
            out = subprocess.run(["dig", "+short", target, qtype],
                                  capture_output=True, text=True, timeout=10)
            return [l.strip() for l in out.stdout.strip().splitlines() if l.strip()]
        except Exception:
            return []

    for rtype in DNS_RECORD_TYPES:
        records = _dig(rtype)
        if records:
            results["records"][rtype] = records

    txt_records = results["records"].get("TXT", [])
    for txt in txt_records:
        if "v=spf1" in txt:
            results["spf"] = txt
            results["interesting"].append(f"SPF: {txt[:120]}")

    dmarc = _dig("TXT", f"_dmarc.{domain}")
    if dmarc:
        results["dmarc"] = dmarc[0]
        results["interesting"].append(f"DMARC: {dmarc[0][:120]}")
        if "p=none" in dmarc[0]:
            results["interesting"].append("⚠ DMARC policy=none — email spoofing possible!")

    dkim_selectors = ["default", "google", "mail", "k1", "selector1", "selector2",
                      "email", "dkim", "s1", "s2", "mandrill", "mailchimp"]
    for sel in dkim_selectors:
        rec = _dig("TXT", f"{sel}._domainkey.{domain}")
        if rec:
            results["dkim"].append({"selector": sel, "record": rec[0][:80]})

    ns_records = results["records"].get("NS", [])
    for ns in ns_records[:3]:
        ns = ns.rstrip(".")
        try:
            out = subprocess.run(["dig", f"@{ns}", domain, "AXFR"],
                                  capture_output=True, text=True, timeout=8)
            if "Transfer failed" not in out.stdout and len(out.stdout) > 200:
                results["zone_transfer_possible"] = True
                results["interesting"].append(f"🔴 ZONE TRANSFER POSSIBLE via {ns}!")
                break
        except Exception:
            pass

    a_records = results["records"].get("A", [])
    for ip in a_records:
        if ip.startswith(("10.", "172.", "192.168.")):
            results["interesting"].append(f"⚠ Internal IP in DNS: {ip}")

    if not results["spf"]:
        results["interesting"].append("⚠ No SPF record — email spoofing possible")
    if not results["dmarc"]:
        results["interesting"].append("⚠ No DMARC record — phishing possible")

    return results


def dns_brute_force(domain: str, wordlist: list = None, threads: int = 50) -> dict:
    if wordlist is None:
        wordlist = [
            "www","mail","ftp","admin","dev","staging","beta","api","test","vpn",
            "remote","git","jenkins","grafana","monitor","app","portal","secure",
            "login","cdn","media","static","internal","corp","intranet","dashboard",
            "support","help","blog","shop","store","m","mobile","wap","ns1","ns2",
            "mx","smtp","pop","imap","webmail","autoconfig","autodiscover","wiki",
            "jira","confluence","bitbucket","gitlab","svn","dev2","stage","stg",
            "uat","qa","prod","production","backup","bk","old","new","v1","v2",
            "api2","api3","cloud","aws","azure","k8s","kubernetes","docker",
        ]
    found = []; lock = threading.Lock(); semaphore = threading.Semaphore(threads)

    def check(sub):
        with semaphore:
            fqdn = f"{sub}.{domain}"
            try:
                ips = socket.gethostbyname_ex(fqdn)[2]
                with lock:
                    found.append({"subdomain": fqdn, "ips": ips})
            except Exception:
                pass

    threads_list = [threading.Thread(target=check, args=(sub,), daemon=True) for sub in wordlist]
    for t in threads_list: t.start()
    for t in threads_list: t.join(timeout=15)
    return {"domain": domain, "found": found, "count": len(found)}


# ── WHOIS / ASN ───────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    result = {"domain": domain, "registrar": None, "created": None, "expires": None,
              "updated": None, "nameservers": [], "registrant": None, "emails": [],
              "raw": "", "error": None}
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        raw = out.stdout; result["raw"] = raw[:3000]
        patterns = {
            "registrar":  r"(?i)registrar:\s*(.+)",
            "created":    r"(?i)(?:creation date|created):\s*(.+)",
            "expires":    r"(?i)(?:expir(?:y|ation) date|expires):\s*(.+)",
            "updated":    r"(?i)(?:updated date|last updated):\s*(.+)",
            "registrant": r"(?i)registrant(?:\s+name)?:\s*(.+)",
        }
        for key, pat in patterns.items():
            m = re.search(pat, raw)
            if m: result[key] = m.group(1).strip()
        ns_matches = re.findall(r"(?i)name server:\s*(.+)", raw)
        result["nameservers"] = [ns.strip().lower() for ns in ns_matches[:6]]
        emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw)))
        result["emails"] = emails[:10]
    except Exception as e:
        result["error"] = str(e)
    return result


def asn_full_recon(domain_or_ip: str) -> dict:
    result = {"query": domain_or_ip, "ip": None, "org": None, "asn": None,
              "country": None, "city": None, "ranges": [], "domains": [], "error": None}
    try:
        ip = domain_or_ip
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_or_ip):
            try:
                ip = socket.gethostbyname(domain_or_ip)
            except Exception:
                pass
        result["ip"] = ip
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "TeamCyberOps/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        result["org"]      = data.get("org", "")
        result["asn"]      = data.get("org", "").split(" ")[0] if data.get("org") else ""
        result["country"]  = data.get("country", "")
        result["city"]     = data.get("city", "")
        result["hostname"] = data.get("hostname", "")
        asn = result["asn"]
        if asn:
            try:
                bgp_url = f"https://bgp.he.net/{asn}#_prefixes"
                req2 = urllib.request.Request(bgp_url, headers={"User-Agent": "TeamCyberOps/2.0"})
                with urllib.request.urlopen(req2, timeout=10) as r2:
                    html = r2.read().decode("utf-8", errors="replace")
                cidrs = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", html)
                result["ranges"] = list(set(cidrs[:100]))
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


# ── HTTP HEADER ANALYSIS ──────────────────────────────────────

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    "X-XSS-Protection", "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
]

INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
    "X-Backend-Server", "X-Forwarded-For", "X-Real-IP",
]


def analyze_http_headers(url: str, use_tor: bool = False) -> dict:
    result = {
        "url": url, "via_tor": use_tor, "headers": {}, "security": {},
        "tech_disclosure": [], "missing_security": [], "cookie_issues": [],
        "cdn_waf": [], "findings": [], "score": 0, "error": None,
    }
    try:
        if use_tor:
            r = tor_get(url, timeout=20)
            if not r["ok"]: raise Exception(r["error"])
            headers = {k.lower(): v for k, v in r["headers"].items()}
            raw_headers = r["headers"]
        else:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0")
            with urllib.request.urlopen(req, timeout=15) as r:
                raw_headers = dict(r.getheaders())
                headers     = {k.lower(): v for k, v in raw_headers.items()}
        result["headers"] = raw_headers
        for sh in SECURITY_HEADERS:
            val = headers.get(sh.lower(), "")
            if val:
                result["security"][sh] = val; result["score"] += 1
            else:
                result["missing_security"].append(sh)
                result["findings"].append(f"⚠ Missing: {sh}")
        for ih in INFO_HEADERS:
            val = headers.get(ih.lower(), "")
            if val:
                result["tech_disclosure"].append(f"{ih}: {val}")
                result["findings"].append(f"ℹ Tech disclosed: {ih}: {val}")
        cdn_waf_signatures = {
            "cloudflare":     ["cf-ray", "cf-cache-status", "server: cloudflare"],
            "akamai":         ["x-check-cacheable", "x-akamai-transformed"],
            "fastly":         ["x-served-by", "x-cache-hits", "x-fastly"],
            "aws-cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "imperva":        ["x-iinfo", "visid_incap"],
            "sucuri":         ["x-sucuri-id"],
            "f5-bigip":       ["x-wa-info", "bigip"],
        }
        all_headers_str = " ".join([f"{k}: {v}".lower() for k, v in headers.items()])
        for cdn, sigs in cdn_waf_signatures.items():
            if any(sig in all_headers_str for sig in sigs):
                result["cdn_waf"].append(cdn)
                result["findings"].append(f"🛡 CDN/WAF detected: {cdn.upper()}")
        for h_name, h_val in headers.items():
            if "set-cookie" in h_name:
                cookie_issues = []
                if "httponly" not in h_val.lower(): cookie_issues.append("Missing HttpOnly")
                if "secure"   not in h_val.lower(): cookie_issues.append("Missing Secure")
                if "samesite" not in h_val.lower(): cookie_issues.append("Missing SameSite")
                if cookie_issues:
                    result["cookie_issues"].append({"cookie": h_val[:60], "issues": cookie_issues})
                    result["findings"].append(f"🍪 Cookie issue: {', '.join(cookie_issues)}")
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            result["findings"].append("🔴 CORS: Access-Control-Allow-Origin: * (Wildcard)")
        elif acao:
            result["findings"].append(f"ℹ CORS origin: {acao}")
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            if "max-age=0" in hsts: result["findings"].append("⚠ HSTS disabled (max-age=0)")
            elif "includesubdomains" not in hsts.lower(): result["findings"].append("⚠ HSTS missing includeSubDomains")
        else:
            result["findings"].append("⚠ No HSTS header")
    except Exception as e:
        result["error"] = str(e)
    return result


# ── EXIF METADATA ─────────────────────────────────────────────

def extract_exif_from_url(image_url: str, use_tor: bool = False) -> dict:
    result = {
        "url": image_url, "exif": {}, "gps": None, "software": None,
        "author": None, "camera": None, "findings": [], "error": None,
    }
    import tempfile, os
    try:
        if use_tor:
            r = tor_get(image_url, timeout=20)
            if not r["ok"]: raise Exception(r["error"])
            img_data = r["body"]
        else:
            with urllib.request.urlopen(image_url, timeout=15) as r:
                img_data = r.read()
        ext = image_url.split(".")[-1].split("?")[0][:5] or "jpg"
        with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
            tmp.write(img_data); tmp_path = tmp.name
        try:
            out = subprocess.run(["exiftool", "-json", tmp_path],
                                  capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                data = json.loads(out.stdout)
                if data:
                    exif = data[0]; result["exif"] = exif
                    lat = exif.get("GPSLatitude"); lon = exif.get("GPSLongitude")
                    if lat and lon:
                        result["gps"] = {"lat": lat, "lon": lon}
                        result["findings"].append(f"🗺 GPS: {lat}, {lon}")
                        result["findings"].append(f"Maps: https://maps.google.com/?q={lat},{lon}")
                    for key in ["Software", "Creator", "Author", "Artist"]:
                        if key in exif:
                            result["software"] = exif[key]
                            result["findings"].append(f"💻 {key}: {exif[key]}")
                    make  = exif.get("Make",""); model = exif.get("Model","")
                    if make or model:
                        result["camera"] = f"{make} {model}".strip()
                        result["findings"].append(f"📷 Camera: {result['camera']}")
                    for ts_key in ["DateTimeOriginal","CreateDate","ModifyDate"]:
                        if ts_key in exif:
                            result["findings"].append(f"📅 {ts_key}: {exif[ts_key]}")
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        result["error"] = str(e)
    return result


def extract_exif_from_domain(domain: str, use_tor: bool = False, max_images: int = 10) -> dict:
    result = {"domain": domain, "images": [], "findings": [], "gps_found": [], "error": None}
    try:
        url = f"https://{domain}" if not domain.startswith("http") else domain
        if use_tor:
            r = tor_get(url, timeout=20)
            if not r["ok"]: raise Exception(r["error"])
            html = r["body"].decode("utf-8", errors="replace")
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                html = r.read().decode("utf-8", errors="replace")
        img_urls  = re.findall(r'<img[^>]+src=["\'](["\']+)["\']', html, re.IGNORECASE)
        img_urls += re.findall(r'https?://[^\s"\'<>]+\.(?:jpg|jpeg|png|tiff|webp)', html, re.IGNORECASE)
        abs_imgs  = []
        for img in img_urls[:max_images]:
            if img.startswith("http"):       abs_imgs.append(img)
            elif img.startswith("//"):       abs_imgs.append("https:" + img)
            elif img.startswith("/"):        abs_imgs.append(f"https://{domain}{img}")
        for img_url in abs_imgs[:max_images]:
            exif_r = extract_exif_from_url(img_url, use_tor=use_tor)
            if exif_r.get("findings"):
                result["images"].append(exif_r)
                result["findings"].extend(exif_r["findings"])
                if exif_r.get("gps"):
                    result["gps_found"].append({"url": img_url, "gps": exif_r["gps"]})
    except Exception as e:
        result["error"] = str(e)
    return result


# ── JAVASCRIPT SOURCE ANALYSIS ────────────────────────────────

JS_PATTERNS = {
    "api_endpoints":    r"""(?:['""`])((?:/[a-zA-Z0-9_\-./]+)+(?:\?[a-zA-Z0-9_=&]+)?)(?:['""`])""",
    "fetch_calls":      r"""fetch\s*\(['""`]([^'""`]+)['""`]""",
    "axios_calls":      r"""axios\.[a-z]+\s*\(['""`]([^'""`]+)['""`]""",
    "xhr_open":         r"""\.open\s*\(['""`][A-Z]+['""`]\s*,\s*['""`]([^'""`]+)['""`]""",
    "api_key":          r"""(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['""`]([A-Za-z0-9_\-]{20,})['""`]""",
    "aws_key":          r"""AKIA[0-9A-Z]{16}""",
    "private_key":      r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""",
    "jwt_token":        r"""eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+""",
    "github_token":     r"""gh[pousr]_[A-Za-z0-9_]{36}""",
    "google_api":       r"""AIza[0-9A-Za-z\-_]{35}""",
    "stripe_key":       r"""(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}""",
    "password_var":     r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['""`]([^'""`]{6,50})['""`]""",
    "secret_var":       r"""(?i)(?:secret|token)\s*[:=]\s*['""`]([A-Za-z0-9_\-]{16,})['""`]""",
    "internal_url":     r"""https?://(?:10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)[^\s'""`]+""",
    "localhost_url":    r"""https?://(?:localhost|127\.0\.0\.1)[^\s'""`]*""",
    "graphql_endpoint": r"""['""`](/graphql[^'""`]*)['""`]""",
    "swagger_endpoint": r"""['""`](/(?:swagger|api-docs|openapi)[^'""`]*)['""`]""",
}


def analyze_js_source(js_content: str, source_url: str = "") -> dict:
    result = {"source": source_url, "endpoints": [], "secrets": [],
              "internals": [], "config": [], "all_findings": [], "risk_score": 0}
    content = js_content
    for ptype, pattern in JS_PATTERNS.items():
        matches = re.findall(pattern, content)
        matches = [m.strip() for m in matches if len(m) > 3]
        matches = list(set(matches))[:50]
        for match in matches:
            finding = {"type": ptype, "value": match[:200]}
            if ptype in ("api_endpoints","fetch_calls","axios_calls","xhr_open","graphql_endpoint","swagger_endpoint"):
                if match not in result["endpoints"]:
                    result["endpoints"].append(match); result["all_findings"].append(finding)
            elif ptype in ("api_key","aws_key","private_key","jwt_token","github_token","google_api","stripe_key","password_var","secret_var"):
                result["secrets"].append(finding); result["all_findings"].append(finding); result["risk_score"] += 10
            elif ptype in ("internal_url","localhost_url"):
                result["internals"].append(match); result["all_findings"].append(finding); result["risk_score"] += 5
            else:
                result["config"].append(finding); result["all_findings"].append(finding); result["risk_score"] += 2
    return result


def crawl_js_files(domain: str, use_tor: bool = False, depth: int = 2) -> dict:
    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    result   = {"domain": domain, "js_files": [], "all_endpoints": set(),
                 "all_secrets": [], "all_internals": set(), "total_findings": 0, "error": None}
    visited_js = set()

    def _fetch(url):
        if use_tor:
            r = tor_get(url, timeout=20)
            return r["body"].decode("utf-8", errors="replace") if r["ok"] else ""
        else:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    return r.read().decode("utf-8", errors="replace")
            except Exception:
                return ""

    def _find_js_urls(html, base):
        urls = re.findall(r'<script[^>]+src=["\'](["\']+)["\']', html, re.I)
        result2 = []
        for u in urls:
            if u.startswith("http"):   result2.append(u)
            elif u.startswith("//"):   result2.append("https:" + u)
            elif u.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(base)
                result2.append(f"{parsed.scheme}://{parsed.netloc}{u}")
        return result2

    try:
        html    = _fetch(base_url)
        js_urls = _find_js_urls(html, base_url)
        common_paths = ["/static/js/main.js","/js/app.js","/bundle.js","/main.js",
                        "/app.js","/vendor.js","/assets/js/main.js","/dist/bundle.js"]
        for path in common_paths:
            js_urls.append(base_url.rstrip("/") + path)
        for js_url in list(set(js_urls))[:30]:
            if js_url in visited_js: continue
            visited_js.add(js_url)
            js_content = _fetch(js_url)
            if not js_content or len(js_content) < 50: continue
            analysis = analyze_js_source(js_content, js_url)
            if analysis["endpoints"] or analysis["secrets"] or analysis["internals"]:
                result["js_files"].append({
                    "url": js_url, "size": len(js_content),
                    "endpoints": analysis["endpoints"], "secrets": analysis["secrets"],
                    "internals": list(analysis["internals"]), "risk": analysis["risk_score"],
                })
                result["all_endpoints"].update(analysis["endpoints"])
                result["all_secrets"].extend(analysis["secrets"])
                result["all_internals"].update(analysis["internals"])
        result["all_endpoints"] = list(result["all_endpoints"])
        result["all_internals"] = list(result["all_internals"])
        result["total_findings"] = (len(result["all_endpoints"]) +
                                    len(result["all_secrets"]) + len(result["all_internals"]))
    except Exception as e:
        result["error"] = str(e)
    return result


# ── ARCGIS ────────────────────────────────────────────────────

def enumerate_arcgis(domain: str, use_tor: bool = False) -> dict:
    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    result   = {"domain": domain, "endpoints": [], "services": [],
                 "layers": [], "findings": [], "error": None}

    def _get(url):
        full = url if url.startswith("http") else base_url + url
        if use_tor:
            r = tor_get(full + "?f=json", timeout=15)
            return json.loads(r["body"]) if r["ok"] else None
        else:
            try:
                req = urllib.request.Request(full + "?f=json", headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=12) as r:
                    return json.loads(r.read())
            except Exception:
                return None

    arcgis_paths = ["/arcgis/rest/services", "/ArcGIS/rest/services",
                    "/server/rest/services", "/gis/rest/services"]
    try:
        for path in arcgis_paths:
            data = _get(path)
            if data is None: continue
            if "services" in data:
                result["endpoints"].append(path)
                services = data["services"]
                result["findings"].append(f"✅ ArcGIS found: {path} ({len(services)} services)")
                for svc in services[:20]:
                    svc_name = svc.get("name",""); svc_type = svc.get("type","")
                    svc_url  = f"{path}/{svc_name}/{svc_type}"
                    result["services"].append({"name": svc_name, "type": svc_type, "url": svc_url})
                    svc_data = _get(svc_url)
                    if svc_data and "layers" in svc_data:
                        for layer in svc_data.get("layers",[])[:10]:
                            layer_info = {"service": svc_name, "layer_id": layer.get("id"),
                                          "layer_name": layer.get("name",""),
                                          "layer_url": f"{svc_url}/{layer.get('id')}"}
                            result["layers"].append(layer_info)
                            result["findings"].append(f"📊 Layer: {svc_name}/{layer.get('name','')} — {svc_url}/{layer.get('id')}")
    except Exception as e:
        result["error"] = str(e)
    return result


# ── AWS INFRASTRUCTURE ────────────────────────────────────────

AWS_INDICATORS = {
    "s3_bucket":      r"([a-zA-Z0-9\-_.]+)\.s3(?:[-.](?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d)?\.amazonaws\.com",
    "cloudfront":     r"([a-zA-Z0-9]+)\.cloudfront\.net",
    "elasticbeanstalk": r"([a-zA-Z0-9\-]+)\.elasticbeanstalk\.com",
    "ec2":            r"ec2-(\d+-\d+-\d+-\d+)\.compute(?:-\d)?\.amazonaws\.com",
    "lambda_url":     r"([a-zA-Z0-9]+)\.lambda-url\.([a-z0-9\-]+)\.on\.aws",
    "api_gateway":    r"([a-zA-Z0-9]+)\.execute-api\.([a-z0-9\-]+)\.amazonaws\.com",
    "cognito":        r"([a-zA-Z0-9\-]+)\.auth\.([a-z0-9\-]+)\.amazoncognito\.com",
}


def identify_aws_infrastructure(domain: str, use_tor: bool = False) -> dict:
    result = {"domain": domain, "aws_assets": [], "s3_buckets": [],
              "regions": set(), "services": set(), "findings": [], "error": None}

    def _check_text(text, src):
        for asset_type, pattern in AWS_INDICATORS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                asset_name = match[0] if isinstance(match, tuple) else match
                finding    = {"type": asset_type, "name": asset_name, "source": src}
                if finding not in result["aws_assets"]:
                    result["aws_assets"].append(finding)
                    result["services"].add(asset_type)
                    result["findings"].append(f"☁ {asset_type}: {asset_name} (from {src})")
                if asset_type == "s3_bucket": result["s3_buckets"].append(asset_name)

    try:
        try:
            out = subprocess.run(["dig", "+short", domain, "CNAME"], capture_output=True, text=True, timeout=8)
            _check_text(out.stdout, "DNS CNAME")
        except Exception:
            pass
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            for ip in ips:
                first_octet = int(ip.split(".")[0])
                if first_octet in [3,13,18,34,52,54]:
                    result["findings"].append(f"☁ Likely AWS IP: {ip} ({domain})")
        except Exception:
            pass
        url = f"https://{domain}" if not domain.startswith("http") else domain
        if use_tor:
            r = tor_get(url, timeout=20)
            body = r["body"].decode("utf-8", errors="replace") if r["ok"] else ""
            headers_str = " ".join([f"{k}: {v}" for k, v in r["headers"].items()])
        else:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body        = resp.read().decode("utf-8", errors="replace")
                    headers_str = " ".join([f"{k}: {v}" for k, v in resp.getheaders()])
            except Exception:
                body = ""; headers_str = ""
        _check_text(body, "HTML")
        _check_text(headers_str, "HTTP Headers")
        company = domain.split(".")[0]
        s3_patterns = [
            f"https://{company}.s3.amazonaws.com/",
            f"https://{company}-backup.s3.amazonaws.com/",
            f"https://{company}-assets.s3.amazonaws.com/",
        ]
        for s3_url in s3_patterns:
            try:
                req = urllib.request.Request(s3_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as r2:
                    bucket = re.search(r"https://([^.]+)\.s3", s3_url)
                    if bucket:
                        result["s3_buckets"].append(bucket.group(1))
                        result["findings"].append(f"🪣 PUBLIC S3 BUCKET: {s3_url}")
            except urllib.error.HTTPError as e:
                if e.code in [403]:
                    bucket = re.search(r"https://([^.]+)\.s3", s3_url)
                    if bucket:
                        result["s3_buckets"].append(bucket.group(1))
                        result["findings"].append(f"🪣 S3 Bucket exists (private/403): {s3_url}")
            except Exception:
                pass
        result["regions"]  = list(result["regions"])
        result["services"] = list(result["services"])
    except Exception as e:
        result["error"] = str(e)
    return result


# ── NEWS AGGREGATION ──────────────────────────────────────────

def aggregate_news(company_or_domain: str, use_tor: bool = False) -> dict:
    result = {"query": company_or_domain, "articles": [],
              "security_mentions": [], "tech_mentions": [], "error": None}
    company = company_or_domain.split(".")[0]
    query   = urllib.parse.quote(company)

    def _fetch(url):
        if use_tor:
            r = tor_get(url, timeout=15)
            return r["body"].decode("utf-8", errors="replace") if r["ok"] else ""
        else:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=12) as r:
                    return r.read().decode("utf-8", errors="replace")
            except Exception:
                return ""

    gnews_url = f"https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"
    gnews_xml = _fetch(gnews_url)
    if gnews_xml:
        titles = re.findall(r"<title><!\[CDATA\[(.+?)\]\]></title>", gnews_xml)
        links  = re.findall(r"<link>(.+?)</link>", gnews_xml)
        dates  = re.findall(r"<pubDate>(.+?)</pubDate>", gnews_xml)
        for i, title in enumerate(titles[1:15]):
            article = {"source": "Google News", "title": title,
                       "url": links[i+1] if i+1 < len(links) else "",
                       "date": dates[i] if i < len(dates) else ""}
            result["articles"].append(article)
            sec_words = ["breach","hack","vulnerability","CVE","leak","attack","exploit","security","ransomware"]
            if any(w.lower() in title.lower() for w in sec_words):
                result["security_mentions"].append(article)
            tech_words = ["AWS","Azure","Kubernetes","Docker","Spring","WordPress","Jenkins"]
            if any(w.lower() in title.lower() for w in tech_words):
                result["tech_mentions"].append(article)

    hn_url  = f"https://hn.algolia.com/api/v1/search?query={query}&tags=story&hitsPerPage=5"
    hn_raw  = _fetch(hn_url)
    if hn_raw:
        try:
            hn_data = json.loads(hn_raw)
            for hit in hn_data.get("hits", [])[:5]:
                result["articles"].append({
                    "source": "HackerNews", "title": hit.get("title",""),
                    "url": hit.get("url",""), "date": hit.get("created_at","")
                })
        except Exception:
            pass
    return result


# ── FULL PIPELINE ─────────────────────────────────────────────

def deep_recon_pipeline(domain: str, use_tor: bool = True, log_cb=None) -> dict:
    def log(msg, tag="info"):
        if log_cb: log_cb(f"[DEEP RECON] {msg}", tag)
        else: print(f"[DEEP RECON] {msg}")

    results = {
        "domain": domain, "timestamp": datetime.now().isoformat(),
        "via_tor": use_tor, "ct_results": {}, "dns": {}, "whois": {},
        "asn": {}, "headers": {}, "js_analysis": {}, "arcgis": {},
        "aws": {}, "news": {}, "summary": [],
    }

    tasks = [
        ("CT crt.sh",       lambda: ct_crtsh(domain, use_tor),                    "ct_crtsh"),
        ("CT HackerTarget", lambda: ct_hackertarget(domain, use_tor),             "ct_hackertarget"),
        ("DNS Recon",       lambda: dns_full_recon(domain),                        "dns"),
        ("WHOIS",           lambda: whois_lookup(domain),                          "whois"),
        ("ASN Mapping",     lambda: asn_full_recon(domain),                        "asn"),
        ("HTTP Headers",    lambda: analyze_http_headers(f"https://{domain}", use_tor), "headers"),
        ("JS Analysis",     lambda: crawl_js_files(domain, use_tor),               "js_analysis"),
        ("ArcGIS Enum",     lambda: enumerate_arcgis(domain, use_tor),             "arcgis"),
        ("AWS Infra",       lambda: identify_aws_infrastructure(domain, use_tor),  "aws"),
        ("News Intel",      lambda: aggregate_news(domain, use_tor),               "news"),
    ]

    completed = {}; lock = threading.Lock(); errors = []

    def run_task(name, fn, key):
        log(f"Starting: {name}", "info")
        try:
            res = fn()
            with lock: completed[key] = res
            log(f"Done: {name}", "ok")
        except Exception as e:
            with lock: errors.append(f"{name}: {e}")
            log(f"Error in {name}: {e}", "err")

    threads = [threading.Thread(target=run_task, args=(n, f, k), daemon=True) for n, f, k in tasks]
    for t in threads: t.start()
    for t in threads: t.join(timeout=60)

    results.update(completed)
    ct1 = completed.get("ct_crtsh", {}); ct2 = completed.get("ct_hackertarget", {})
    merged = merge_ct_results(ct1, ct2)
    results["ct_results"] = merged

    sub_count  = merged.get("count", 0)
    dns_issues = completed.get("dns", {}).get("interesting", [])
    js_secrets = len(completed.get("js_analysis", {}).get("all_secrets", []))
    aws_count  = len(completed.get("aws", {}).get("aws_assets", []))
    s3_public  = [f for f in completed.get("aws", {}).get("findings", []) if "PUBLIC" in f]

    results["summary"] = [
        f"Subdomains found: {sub_count}", f"DNS issues: {len(dns_issues)}",
        f"JS secrets found: {js_secrets}", f"AWS assets: {aws_count}",
        f"Public S3 buckets: {len(s3_public)}",
    ]
    if dns_issues: results["summary"].extend(dns_issues[:3])
    if s3_public:  results["summary"].extend(s3_public[:3])

    out_path = LOGS_DIR / f"{domain}_deep_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        log(f"Report saved: {out_path}", "ok")
    except Exception:
        pass

    return results


def tor_status() -> dict:
    reachable = _check_tor(); ip = None; country = None
    if reachable:
        ip = get_tor_ip()
        try:
            geo_url = f"https://ipinfo.io/{ip}/json"
            r = tor_get(geo_url, timeout=10)
            if r["ok"]:
                geo = json.loads(r["body"])
                country = geo.get("country", "")
        except Exception:
            pass
    return {"tor_running": reachable, "exit_ip": ip, "exit_country": country,
            "proxy": TOR_PROXY, "preferred_exits": PREFERRED_EXIT_COUNTRIES}
