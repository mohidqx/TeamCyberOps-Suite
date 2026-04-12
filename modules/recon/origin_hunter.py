"""
TeamCyberOps Suite v4 — Origin Hunter (Production Grade)
WAF Detection · Origin IP Discovery · CDN Bypass · SSL Certificate Analysis
"""
import socket, ssl, urllib.request, urllib.parse, re, subprocess
import concurrent.futures, threading, json
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"

def _req(url, headers=None, timeout=8):
    h = {"User-Agent":"Mozilla/5.0",**(headers or {})}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status":r.status,"headers":dict(r.headers),"body":r.read(2000).decode("utf-8","replace"),"ok":True}
    except urllib.error.HTTPError as e:
        return {"status":e.code,"headers":dict(e.headers),"body":"","ok":False}
    except Exception as ex:
        return {"status":None,"error":str(ex),"body":"","ok":False}

WAF_SIGS = {
    "Cloudflare":   ["cf-ray","cloudflare","__cfduid","cf-cache-status"],
    "Akamai":       ["x-akamai","akamaighost","x-check-cacheable","x-akamai-request-id"],
    "Imperva":      ["x-iinfo","incapsula","visid_incap","incap_ses"],
    "AWS WAF":      ["x-amzn-requestid","awswaf","x-amz-cf-id"],
    "Fastly":       ["x-fastly-request-id","x-served-by","fastly"],
    "Sucuri":       ["x-sucuri-id","x-sucuri-cache","sucuri"],
    "Barracuda":    ["barra_counter_session","barracuda_"],
    "F5 Big-IP":    ["bigipserver","x-waf-status","ts="],
    "Fortinet":     ["fortigate","fortiweb","x-fortigate"],
    "ModSecurity":  ["mod_security","server: modsecurity"],
    "Nginx WAF":    ["x-nf-request-id"],
    "Azure FrontDoor": ["x-azure-ref","x-fd-healthid"],
    "Google Cloud": ["x-cloud-trace-context","via: 1.1 google"],
    "Varnish":      ["x-varnish","via: varnish"],
    "Squid":        ["x-squid-error","via: squid"],
}

CDN_SIGNATURES = {
    "Cloudflare":   ["104.16.","104.17.","104.18.","172.64.","172.65.","172.66.","172.67."],
    "Akamai":       ["23.192.","23.193.","23.194.","23.195.","23.196.","23.197.","23.198.","23.199."],
    "AWS CloudFront": ["13.32.","13.33.","13.35.","13.224.","13.225.","13.226.","13.227.","52.84."],
    "Fastly":       ["23.235.","23.236.","23.237.","23.238.","23.239.","151.101."],
    "Google CDN":   ["34.96.","34.149.","142.250.","172.217.","216.58."],
    "Azure CDN":    ["13.107.","23.100.","23.101."],
}

def detect_waf(host, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    detected_wafs = []
    detected_cdns = []

    # 1. Normal request
    for scheme in ["https","http"]:
        r = _req(f"{scheme}://{host}", timeout=8)
        if not r.get("headers"): continue
        hdrs_str = '\n'.join(f"{k.lower()}: {v.lower()}" for k,v in r["headers"].items())

        for waf, sigs in WAF_SIGS.items():
            if any(s in hdrs_str for s in sigs):
                if waf not in detected_wafs:
                    detected_wafs.append(waf)
                    log(f"  [WAF] {waf}", "warn")
        break

    # 2. Malicious payload test (triggers WAF)
    payload_url = f"https://{host}/?q=<script>alert(1)</script>&id=1'+OR+1=1--"
    r2 = _req(payload_url, timeout=6)
    if r2.get("status") in (403, 406, 412, 429, 503):
        hdrs2 = '\n'.join(f"{k.lower()}: {v.lower()}" for k,v in (r2.get("headers") or {}).items())
        for waf, sigs in WAF_SIGS.items():
            if waf not in detected_wafs and any(s in hdrs2 for s in sigs):
                detected_wafs.append(waf); log(f"  [WAF+] {waf} (block response)", "warn")
        if not detected_wafs and r2["status"] in (403,406):
            detected_wafs.append("Unknown WAF"); log("  [WAF] Unknown WAF (block 403/406)", "warn")

    # 3. Resolve IP and check CDN ranges
    try:
        ip = socket.gethostbyname(host)
        for cdn, ranges in CDN_SIGNATURES.items():
            if any(ip.startswith(r) for r in ranges):
                detected_cdns.append(f"{cdn} ({ip})")
                log(f"  [CDN] {cdn} IP: {ip}", "info")
    except Exception: pass

    if not detected_wafs: log("  No WAF detected", "dim")
    return {"host":host, "wafs":detected_wafs, "cdns":detected_cdns}

def resolve_subdomains(subdomains, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[Resolve] {len(subdomains)} subdomains", "info")
    resolved = {}; lock = threading.Lock()

    def _resolve(sub):
        sub = sub.strip().split()[0]  # handle "sub has address IP" format
        try:
            ip = socket.gethostbyname(sub)
            with lock:
                resolved[sub] = ip
                log(f"  {sub} → {ip}", "dim")
        except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_resolve, subdomains))

    # Save results
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    lookup_lines = [f"{sub} has address {ip}" for sub,ip in sorted(resolved.items())]
    ip_lines = sorted(set(resolved.values()))
    (d/"subdomain_lookup.txt").write_text('\n'.join(lookup_lines))
    (d/"resolved_ips.txt").write_text('\n'.join(ip_lines))
    log(f"[Resolve] {len(resolved)} resolved", "ok")
    return {"resolved":resolved, "ips":ip_lines}

def ssl_cert_scan(host, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[SSL] Certificate scan: {host}", "info")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Extract SANs
                sans = []
                for typ, val in cert.get("subjectAltName",[]):
                    if typ == "DNS": sans.append(val)
                subject = dict(x[0] for x in cert.get("subject",[]))
                result = {
                    "host":      host,
                    "cn":        subject.get("commonName",""),
                    "org":       subject.get("organizationName",""),
                    "sans":      sans,
                    "issuer":    dict(x[0] for x in cert.get("issuer",[])).get("organizationName",""),
                    "not_before":cert.get("notBefore",""),
                    "not_after": cert.get("notAfter",""),
                    "version":   ssock.version(),
                }
                log(f"  [SSL] CN: {result['cn']} | SANs: {len(sans)} | Issuer: {result['issuer']}", "ok")
                for san in sans[:10]: log(f"    {san}", "dim")
                return result
    except Exception as e:
        log(f"  [SSL] Error: {e}", "err"); return {"error":str(e)}

def find_origin_ips(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[Origin] Hunting for real IP behind CDN: {domain}", "info")
    candidates = {}

    # 1. Direct DNS
    try:
        ips = socket.getaddrinfo(domain, None)
        for ip in set(r[4][0] for r in ips):
            candidates[ip] = "DNS"
            log(f"  [DNS] {ip}", "dim")
    except Exception: pass

    # 2. Historical DNS (SecurityTrails, Shodan)
    try:
        r = _req(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r["ok"]:
            for ip in re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', r["body"]):
                if not _is_cdn_ip(ip): candidates[ip] = "HackerTarget"
    except Exception: pass

    # 3. SSL cert SANs → check each SAN directly
    ssl_info = ssl_cert_scan(domain, log)
    for san in ssl_info.get("sans",[]):
        san = san.lstrip("*.")
        try:
            ip = socket.gethostbyname(san)
            if ip not in candidates: candidates[ip] = f"SAN: {san}"
        except Exception: pass

    # 4. MX record IPs
    try:
        out = subprocess.run(["dig","+short","MX",domain],
                              capture_output=True,text=True,timeout=5).stdout
        for mx in out.strip().splitlines():
            mx_host = mx.split()[-1] if mx.split() else ""
            if mx_host:
                try: candidates[socket.gethostbyname(mx_host)] = f"MX:{mx_host}"
                except Exception: pass
    except Exception: pass

    # Filter out CDN IPs
    origins = {ip:src for ip,src in candidates.items() if not _is_cdn_ip(ip)}
    cdn_ips = {ip:src for ip,src in candidates.items() if _is_cdn_ip(ip)}
    log(f"[Origin] {len(origins)} potential origin IPs, {len(cdn_ips)} CDN IPs filtered", "ok" if origins else "warn")
    for ip,src in origins.items():
        log(f"  [ORIGIN] {ip} (via {src})", "ok")
    return {"origin_ips":origins,"cdn_ips":cdn_ips,"ssl":ssl_info}

def _is_cdn_ip(ip):
    for cdn, ranges in CDN_SIGNATURES.items():
        if any(ip.startswith(r) for r in ranges): return True
    return False
