"""
TeamCyberOps Suite v4 — OSINT Intelligence Engine (Production Grade)
Email · ASN/BGP · Favicon Hash · Certificate Monitor · DNS History · Shodan · People Intel
"""
import json, re, urllib.request, urllib.parse, socket, hashlib, base64
import concurrent.futures, threading
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"

def _cfg():
    try:
        with open(BASE_DIR/"config.json") as f: return json.load(f)
    except Exception: return {}

def _req(url, headers=None, timeout=15):
    h = {"User-Agent":"TeamCyberOps/4 Security Scanner",**(headers or {})}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status":r.status,"body":r.read(50000).decode("utf-8","replace"),"ok":True}
    except Exception as e:
        return {"status":None,"error":str(e),"body":"","ok":False}

# ── EMAIL INTELLIGENCE ───────────────────────────────────────────
def hunter_email_search(domain, api_key="", limit=20, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    if not api_key:
        try: api_key = _cfg().get("api_keys",{}).get("hunter","")
        except Exception: pass
    if not api_key:
        log("[Hunter.io] No API key — using free Phonebook instead", "warn")
        return phonebook_email_search(domain, log_cb=log)
    try:
        url = (f"https://api.hunter.io/v2/domain-search"
               f"?domain={urllib.parse.quote(domain)}&limit={limit}&api_key={api_key}")
        r = _req(url)
        if not r["ok"]: return {"error": r.get("error","")}
        data = json.loads(r["body"])
        emails = data.get("data",{}).get("emails",[])
        result = {
            "domain":   domain,
            "org":      data.get("data",{}).get("organization",""),
            "pattern":  data.get("data",{}).get("pattern",""),
            "total":    data.get("data",{}).get("total",0),
            "emails":   [{"email":e.get("value",""),"name":f"{e.get('first_name','')} {e.get('last_name','')}".strip(),
                          "position":e.get("position",""),"confidence":e.get("confidence",0),
                          "type":e.get("type","")} for e in emails],
        }
        log(f"[Hunter.io] {len(emails)}/{result['total']} emails (pattern: {result['pattern']})", "ok")
        return result
    except Exception as e:
        log(f"[Hunter.io] Error: {e}", "err"); return {"error":str(e)}

def phonebook_email_search(domain, log_cb=None):
    """IntelligenceX Phonebook (no key needed for basic search)."""
    log = log_cb or (lambda m,t='': None)
    emails = set()
    try:
        # WHOIS/scrape approach
        r = _req(f"https://emailrep.io/query/{urllib.parse.quote(domain)}")
        if r["ok"]:
            data = json.loads(r["body"])
            for entry in data.get("results",[]):
                if "@" in entry.get("email",""): emails.add(entry["email"])
    except Exception: pass
    # Common email patterns
    try:
        r2 = _req(f"https://api.hackertarget.com/findemail/?q={domain}")
        if r2["ok"]:
            for line in r2["body"].splitlines():
                if "@" in line and domain in line: emails.add(line.strip())
    except Exception: pass
    result_emails = [{"email":e,"confidence":50} for e in sorted(emails)]
    log(f"[Email Search] {len(result_emails)} emails", "ok" if result_emails else "dim")
    return {"domain":domain,"emails":result_emails,"total":len(result_emails)}

# ── WHOIS ────────────────────────────────────────────────────────
def whois_lookup(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[WHOIS] {domain}", "info")
    # RDAP API (modern WHOIS replacement)
    try:
        tld = domain.split(".")[-1]
        rdap_url = f"https://rdap.org/domain/{domain}"
        r = _req(rdap_url)
        if r["ok"]:
            data = json.loads(r["body"])
            registrant = {}
            for entity in data.get("entities",[]):
                for role in entity.get("roles",[]):
                    if role == "registrant":
                        vcard = entity.get("vcardArray",[None,None])[1] or []
                        for item in vcard:
                            if item[0] == "fn": registrant["name"] = item[3]
                            elif item[0] == "org": registrant["org"] = item[3]
                            elif item[0] == "email": registrant["email"] = item[3]
            events = {e.get("eventAction",""): e.get("eventDate","")
                      for e in data.get("events",[])}
            result = {
                "domain":        domain,
                "registrant":    registrant,
                "registered":    events.get("registration",""),
                "updated":       events.get("last changed",""),
                "expires":       events.get("expiration",""),
                "nameservers":   [n.get("ldhName","") for n in data.get("nameservers",[])],
                "status":        data.get("status",[]),
            }
            log(f"[WHOIS] Registrant: {registrant.get('org') or registrant.get('name','Unknown')}", "ok")
            return result
    except Exception: pass
    # Fallback: whois API
    try:
        r2 = _req(f"https://api.hackertarget.com/whois/?q={domain}")
        return {"domain":domain,"raw":r2["body"][:2000]}
    except Exception:
        return {"domain":domain,"error":"WHOIS lookup failed"}

# ── ASN / IP INTELLIGENCE ────────────────────────────────────────
def asn_lookup(domain_or_ip, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    ip = domain_or_ip
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_or_ip):
        try: ip = socket.gethostbyname(domain_or_ip)
        except Exception: pass
    log(f"[ASN] Looking up {ip}", "info")
    try:
        r = _req(f"https://ipinfo.io/{ip}/json")
        if not r["ok"]: return {"error":"ipinfo.io failed"}
        data = json.loads(r["body"])
        asn = data.get("org","").split()[0].replace("AS","") if data.get("org","") else ""
        result = {
            "ip":       ip,
            "hostname": data.get("hostname",""),
            "org":      data.get("org",""),
            "asn":      asn,
            "country":  data.get("country",""),
            "region":   data.get("region",""),
            "city":     data.get("city",""),
            "timezone": data.get("timezone",""),
        }
        log(f"[ASN] {ip} → {data.get('org','')} ({data.get('country','')})", "ok")
        return result
    except Exception as e:
        log(f"[ASN] Error: {e}", "err"); return {"error":str(e)}

def get_ip_ranges(asn, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[BGPView] Getting IP ranges for AS{asn}", "info")
    try:
        r = _req(f"https://api.bgpview.io/asn/{asn}/prefixes")
        if not r["ok"]: return []
        data = json.loads(r["body"])
        prefixes = []
        for p in data.get("data",{}).get("ipv4_prefixes",[]):
            prefixes.append({
                "prefix":  p.get("prefix",""),
                "name":    p.get("name",""),
                "country": p.get("country_code",""),
            })
            log(f"  [+] {p.get('prefix','')} [{p.get('name','')}]", "dim")
        log(f"[BGPView] {len(prefixes)} IPv4 ranges", "ok")
        return prefixes
    except Exception as e:
        log(f"[BGPView] Error: {e}", "err"); return []

def reverse_dns_scan(ip_range, sample_size=20, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    import ipaddress
    log(f"[rDNS] Scanning {ip_range} (sample={sample_size})", "info")
    results = {}; lock = threading.Lock()

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        hosts = list(network.hosts())[:sample_size]
    except Exception: return {}

    def _reverse(ip):
        try:
            host = socket.gethostbyaddr(str(ip))[0]
            with lock: results[str(ip)] = host
            log(f"  [rDNS] {ip} → {host}", "dim")
        except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_reverse, hosts))
    log(f"[rDNS] {len(results)} resolved", "ok" if results else "dim")
    return results

# ── FAVICON HASH ─────────────────────────────────────────────────
FAVICON_PATHS = [
    "/favicon.ico","/favicon.png","/favicon.gif","/apple-touch-icon.png",
    "/assets/favicon.ico","/images/favicon.ico","/static/favicon.ico",
    "/public/favicon.ico","/img/favicon.ico","/icons/favicon.ico",
]

def murmurhash3(data):
    """MurmurHash3 — same as Shodan uses."""
    data = base64.b64encode(data)
    nblocks = len(data) // 4; h1 = 0
    c1, c2 = 0xcc9e2d51, 0x1b873593
    for i in range(nblocks):
        k1 = int.from_bytes(data[i*4:(i+1)*4], 'little')
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[nblocks*4:]
    k1 = 0
    if len(tail) >= 3: k1 ^= tail[2] << 16
    if len(tail) >= 2: k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= len(data)
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return -(h1 & 0x80000000) | (h1 & 0x7fffffff)  # signed 32-bit

def favicon_recon(domain, shodan_key="", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[Favicon] Scanning {domain}", "info")
    results = []
    for path in FAVICON_PATHS:
        for scheme in ["https","http"]:
            url = f"{scheme}://{domain}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    if r.status == 200:
                        data = r.read()
                        if len(data) > 100:
                            hash_val = murmurhash3(data)
                            md5_val  = hashlib.md5(data).hexdigest()
                            result = {"url":url,"path":path,"hash":hash_val,"md5":md5_val,"size":len(data)}
                            results.append(result)
                            log(f"  [✓] {url} — Shodan hash: {hash_val}", "ok")
                            # Shodan search
                            if shodan_key:
                                shodan_r = _req(f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{hash_val}&minify=true")
                                if shodan_r["ok"]:
                                    shodan_data = json.loads(shodan_r["body"])
                                    count = shodan_data.get("total",0)
                                    result["shodan_count"] = count
                                    if count > 0:
                                        log(f"  [Shodan] {count} servers with same favicon!", "ok")
                                        result["shodan_ips"] = [m.get("ip_str") for m in shodan_data.get("matches",[])][:10]
                            break
            except Exception: pass
    log(f"[Favicon] Found {len(results)} favicons", "ok" if results else "dim")
    return results

# ── DNS HISTORY & PASSIVE DNS ────────────────────────────────────
def dns_history(domain, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[DNS History] {domain}", "info")
    records = {}
    # Current DNS
    record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
    for rtype in record_types:
        try:
            import subprocess
            out = subprocess.run(["dig","+short",domain,rtype],
                                  capture_output=True, text=True, timeout=5).stdout
            if out.strip():
                records[rtype] = out.strip().splitlines()
                log(f"  [DNS] {rtype}: {out.strip()[:60]}", "dim")
        except Exception:
            # Python fallback
            try:
                if rtype == "A":
                    ip = socket.gethostbyname(domain)
                    records["A"] = [ip]; log(f"  [DNS] A: {ip}", "dim")
                elif rtype == "MX":
                    _, _, mxlist = socket.getaddrinfo(f"mail.{domain}", None)
                    records["MX"] = [str(m) for m in mxlist[:3]] if mxlist else []
            except Exception: pass

    # HackerTarget DNS lookup (historical)
    try:
        r = _req(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r["ok"]: records["_hackertarget"] = r["body"][:500]
    except Exception: pass

    # PassiveDNS via Security Trails (free tier)
    try:
        r2 = _req(f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                   headers={"APIKEY": _cfg().get("api_keys",{}).get("securitytrails","")})
        if r2["ok"]:
            data = json.loads(r2["body"])
            records["_history"] = [r.get("values",[]) for r in data.get("records",[])][:10]
    except Exception: pass

    log(f"[DNS] {len(records)} record types found", "ok")
    return {"domain":domain,"records":records}

# ── CLOUD ASSET DISCOVERY ────────────────────────────────────────
def discover_cloud_assets(company_name, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[Cloud] Discovering assets for {company_name}", "info")
    name = company_name.lower().replace(" ","-").replace(".","-")
    assets = {"s3":[],"azure":[],"gcp":[],"cloudfront":[],"github":[]}
    perms = [name, f"{name}-prod", f"{name}-dev", f"{name}-staging",
             f"{name}-backup", f"{name}-assets", f"{name}-data",
             f"{name}-static", f"{name}-api", f"{name}-cdn"]

    def _check_s3(bucket):
        for url in [f"https://{bucket}.s3.amazonaws.com/",
                    f"https://s3.amazonaws.com/{bucket}/"]:
            try:
                r = _req(url, timeout=5)
                if r["status"] in (200,403):
                    assets["s3"].append({"bucket":bucket,"url":url,"status":r["status"],
                                          "public":r["status"]==200 and "Contents" in r["body"]})
                    log(f"  [S3] {bucket}: {'PUBLIC' if r['status']==200 else 'EXISTS(403)'}", "ok")
                    return
            except Exception: pass

    def _check_azure(sub):
        for suf in [".blob.core.windows.net",".azurewebsites.net",".azurefd.net"]:
            url = f"https://{sub}{suf}/"
            try:
                r = _req(url, timeout=5)
                if r["status"] not in (None,):
                    assets["azure"].append({"name":sub+suf,"url":url,"status":r["status"]})
                    log(f"  [Azure] {sub+suf}: {r['status']}", "ok")
                    return
            except Exception: pass

    def _check_gcp(bucket):
        url = f"https://storage.googleapis.com/{bucket}/"
        try:
            r = _req(url, timeout=5)
            if r["status"] in (200,403):
                assets["gcp"].append({"bucket":bucket,"url":url,"status":r["status"]})
                log(f"  [GCP] {bucket}: {r['status']}", "ok")
        except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_check_s3, perms))
        list(ex.map(_check_azure, perms))
        list(ex.map(_check_gcp, perms))

    total = sum(len(v) for v in assets.values())
    log(f"[Cloud] {total} cloud assets found", "ok" if total else "dim")
    return assets

# ── FULL OSINT RUN ───────────────────────────────────────────────
def full_osint(domain, project, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"\n{'='*50}", "dim")
    log(f"[*] FULL OSINT: {domain}", "info")
    log(f"{'='*50}\n", "dim")
    cfg = _cfg()
    api_keys = cfg.get("api_keys",{})
    results = {}

    results["whois"]   = whois_lookup(domain, log)
    results["dns"]     = dns_history(domain, log)
    results["emails"]  = hunter_email_search(domain, api_keys.get("hunter",""), log_cb=log)
    results["asn"]     = asn_lookup(domain, log)
    results["favicon"] = favicon_recon(domain, api_keys.get("shodan",""), log)
    results["cloud"]   = discover_cloud_assets(domain, log)

    if results["asn"].get("asn"):
        results["ip_ranges"] = get_ip_ranges(results["asn"]["asn"], log)

    # Save results
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    (d / "osint_full.json").write_text(json.dumps(results, indent=2, default=str))
    emails = [e["email"] for e in results.get("emails",{}).get("emails",[])]
    if emails: (d / "emails.txt").write_text('\n'.join(emails))
    favicons = results.get("favicon",[])
    if favicons:
        (d / "favicon_recon.txt").write_text('\n'.join(
            f"Hash: {f['hash']} | URL: {f['url']} | Shodan: {f.get('shodan_count',0)}" for f in favicons))
    if results.get("ip_ranges"):
        (d / "ip_ranges.txt").write_text('\n'.join(p["prefix"] for p in results["ip_ranges"]))

    log(f"\n[✓] OSINT complete — saved to logs/{project}/osint_full.json", "ok")
    return results


# ── Wrapper functions required by main.py ────────────────────────────────────

def passive_all_sources(domain: str, log_cb=None) -> dict:
    """Run all passive OSINT sources and merge results."""
    log = log_cb or (lambda m, t='': None)
    results = {}
    log(f"[*] Running full passive OSINT on {domain}", "info")
    try:
        results['emails']      = hunter_email_search(domain, log_cb=log_cb)
        results['whois']       = whois_lookup(domain, log_cb=log_cb)
        results['asn']         = asn_lookup(domain, log_cb=log_cb)
        results['dns_history'] = dns_history(domain, log_cb=log_cb)
        results['cloud']       = discover_cloud_assets(domain, log_cb=log_cb)
    except Exception as e:
        log(f"[!] Passive OSINT error: {e}", "err")
    return results

def bgp_lookup(asn: str, log_cb=None) -> dict:
    """BGP prefix lookup for an ASN."""
    log = log_cb or (lambda m, t='': None)
    import urllib.request, json
    try:
        asn_clean = str(asn).strip().upper().replace('AS', '')
        url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        prefixes = [p.get('prefix','') for p in data.get('data',{}).get('ipv4_prefixes',[])]
        log(f"[+] ASN{asn_clean}: {len(prefixes)} IPv4 prefixes", "ok")
        return {'asn': asn_clean, 'prefixes': prefixes, 'raw': data}
    except Exception as e:
        log(f"[!] BGP lookup error: {e}", "err")
        return {'asn': asn, 'prefixes': [], 'error': str(e)}

def get_favicon_hash(url: str, log_cb=None) -> dict:
    """Fetch favicon and compute MurmurHash3 for Shodan search."""
    log = log_cb or (lambda m, t='': None)
    import urllib.request, base64
    try:
        favicon_url = url.rstrip('/') + '/favicon.ico'
        req = urllib.request.Request(favicon_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = r.read()
        b64 = base64.encodebytes(data).decode()
        h = murmurhash3(b64)
        log(f"[+] Favicon hash: {h} — Shodan: http.favicon.hash:{h}", "ok")
        return {'url': favicon_url, 'hash': h, 'shodan_query': f'http.favicon.hash:{h}'}
    except Exception as e:
        log(f"[!] Favicon error: {e}", "err")
        return {'url': url, 'hash': None, 'error': str(e)}

def check_s3_bucket(bucket_name: str, log_cb=None) -> dict:
    """Check if an S3 bucket is publicly accessible."""
    log = log_cb or (lambda m, t='': None)
    import urllib.request
    results = {'bucket': bucket_name, 'accessible': False, 'urls': []}
    urls_to_try = [
        f"https://{bucket_name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket_name}/",
        f"https://{bucket_name}.storage.googleapis.com/",
    ]
    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=6) as r:
                body = r.read(500).decode('utf-8', errors='replace')
                if '<ListBucketResult' in body or '<Contents>' in body:
                    log(f"[🔴] OPEN BUCKET: {url}", "ok")
                    results['accessible'] = True
                    results['urls'].append(url)
                else:
                    log(f"[~] Exists but not listable: {url}", "warn")
        except Exception:
            pass
    if not results['accessible']:
        log(f"[-] Bucket not publicly accessible: {bucket_name}", "dim")
    return results

def search_leaks_online(domain: str, log_cb=None) -> list:
    """Search for credential leaks mentioning the domain."""
    log = log_cb or (lambda m, t='': None)
    import urllib.request, urllib.parse
    links = []
    try:
        query = urllib.parse.quote(f'site:pastebin.com OR site:raidforums.com "{domain}" password')
        log(f"[*] Searching leaks for {domain}...", "info")
        log(f"[*] Manual search: https://www.google.com/search?q={query}", "dim")
        log(f"[*] Try: https://haveibeenpwned.com/DomainSearch", "info")
        log(f"[*] Try: https://dehashed.com/search?query={domain}", "info")
        links = [
            f"https://www.google.com/search?q={query}",
            f"https://haveibeenpwned.com/DomainSearch",
        ]
    except Exception as e:
        log(f"[!] Leak search error: {e}", "err")
    return links

def check_hibp_domain(domain: str, log_cb=None) -> dict:
    """Check Have I Been Pwned for domain breaches (requires API key in config)."""
    log = log_cb or (lambda m, t='': None)
    import urllib.request, json
    try:
        from pathlib import Path
        import json as _json
        cfg_path = Path(__file__).parent.parent.parent / 'config.json'
        cfg = _json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        api_key = cfg.get('api_keys', {}).get('hibp_api_key', '')
        if not api_key:
            log("[!] HIBP API key not set. Add 'hibp_api_key' to config.json", "warn")
            log("[*] Get key at: https://haveibeenpwned.com/API/Key", "info")
            return {'domain': domain, 'breaches': [], 'error': 'No API key'}
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        req = urllib.request.Request(url, headers={
            'hibp-api-key': api_key, 'User-Agent': 'TeamCyberOps-Suite'
        })
        with urllib.request.urlopen(req, timeout=10) as r:
            breaches = json.loads(r.read().decode())
        log(f"[+] HIBP: {len(breaches)} breached emails found for {domain}", "ok")
        return {'domain': domain, 'breaches': breaches}
    except Exception as e:
        log(f"[!] HIBP error: {e}", "err")
        return {'domain': domain, 'breaches': [], 'error': str(e)}
