"""
TeamCyberOps Suite v4 — DEEP RECURSIVE RECON ENGINE
Based on hunt.sh logic, upgraded to maximum intelligence gathering.
For every subdomain found: DNS deep-dive, ASN, WAF, HTTP, takeover, zone transfer, etc.
Pure Python + shell tools with complete fallbacks.
"""
import subprocess, socket, json, re, os, shutil, time, threading
import urllib.request, urllib.parse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  DNS UTILITIES
# ══════════════════════════════════════════════════════════════

DNS_RECORD_TYPES = ['A','AAAA','MX','TXT','NS','CNAME','SRV','CAA','SOA','PTR','DNSKEY','DS']
TAKEOVER_SIGNATURES = {
    'AWS S3':           ['NoSuchBucket','The specified bucket does not exist'],
    'AWS CloudFront':   ['The request could not be satisfied','CloudFront'],
    'GitHub Pages':     ["There isn't a GitHub Pages site here",'githubapp.com'],
    'Heroku':           ['No such app','herokuapp.com','There is no app configured'],
    'Fastly':           ['Fastly error: unknown domain'],
    'Shopify':          ["Sorry, this shop is currently unavailable",'myshopify.com'],
    'Zendesk':          ['Help Center Closed','zendesk.com'],
    'HubSpot':          ['Domain not found','hs-sites.com'],
    'Ghost':            ['The thing you were looking for is no longer here'],
    'Surge.sh':         ["project not found",'surge.sh'],
    'Tumblr':           ['Whatever you were looking for doesn\'t live here'],
    'Wordpress':        ['Do you want to register','wordpress.com'],
    'Webflow':          ['The page you are looking for doesn\'t exist or has been moved'],
    'Azure':            ['404 Web Site not found','azurewebsites.net','azure.com'],
    'Pantheon':         ['404 error unknown site!'],
    'Strikingly':       ['page not found','strike.so'],
    'Fly.io':           ['502: Application failed to start','fly.dev'],
}

RFC1918 = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^169\.254\.'),  # APIPA — also interesting
]

CLOUD_CNAME_PATTERNS = {
    'AWS S3':           ['.s3.amazonaws.com','.s3-website'],
    'AWS CloudFront':   ['.cloudfront.net'],
    'AWS ELB':          ['.elb.amazonaws.com','.elasticbeanstalk.com'],
    'Azure':            ['.azurewebsites.net','.trafficmanager.net','.blob.core.windows.net'],
    'GitHub Pages':     ['.github.io','.githubapp.com'],
    'Heroku':           ['.herokudns.com','.herokuapp.com'],
    'Fastly':           ['.fastly.net','.fastlylb.net'],
    'Shopify':          ['.myshopify.com','.shopifypreview.com'],
    'HubSpot':          ['.hubspot.com','.hs-sites.com'],
    'Zendesk':          ['.zendesk.com','.zopim.com'],
    'Fly.io':           ['.fly.dev'],
    'Surge.sh':         ['.surge.sh'],
    'Webflow':          ['.webflow.io'],
    'Netlify':          ['.netlify.app','.netlify.com'],
    'Render':           ['.onrender.com'],
    'Vercel':           ['.vercel.app','.now.sh'],
}


def _run(cmd, timeout=30, capture=True):
    """Run command, return stdout string or empty."""
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        return r.stdout.strip() if capture else ''
    except Exception:
        return ''


def dig_record(host, rtype, timeout=8):
    """Query DNS record using dig or Python fallback."""
    if shutil.which('dig'):
        out = _run(['dig', '+short', host, rtype, '+time=4', '+tries=2'], timeout=timeout)
        return [l.strip() for l in out.splitlines() if l.strip()] if out else []
    # Python fallback
    try:
        if rtype == 'A':
            results = socket.getaddrinfo(host, None, socket.AF_INET)
            return list(set(r[4][0] for r in results))
        elif rtype == 'AAAA':
            results = socket.getaddrinfo(host, None, socket.AF_INET6)
            return list(set(r[4][0] for r in results))
    except Exception:
        pass
    return []


def resolve_ip(host):
    """Get primary A record IP."""
    ips = dig_record(host, 'A')
    return ips[0] if ips else None


def is_internal_ip(ip):
    """Check if IP is RFC1918/private."""
    return any(p.match(ip) for p in RFC1918)


def detect_cname_takeover(host, cname_value):
    """Check if CNAME points to unclaimed cloud service."""
    findings = []
    cname_lower = cname_value.lower()
    for provider, patterns in CLOUD_CNAME_PATTERNS.items():
        for p in patterns:
            if p.lower() in cname_lower:
                findings.append({'provider': provider, 'cname': cname_value, 'pattern': p})
    return findings


def zone_transfer_check(host):
    """Attempt DNS zone transfer on all nameservers."""
    results = []
    ns_records = dig_record(host, 'NS')
    for ns in ns_records:
        ns = ns.rstrip('.')
        if shutil.which('dig'):
            out = _run(['dig', 'axfr', host, f'@{ns}', '+time=5'], timeout=15)
            if out and 'Transfer failed' not in out and 'REFUSED' not in out:
                lines = [l for l in out.splitlines() if l.strip() and not l.startswith(';')]
                if lines:
                    results.append({'ns': ns, 'records': lines, 'vulnerable': True})
    return results


def whois_asn(ip):
    """Get ASN info for IP via Team Cymru or whois."""
    if not ip: return {}
    # Method 1: Team Cymru
    if shutil.which('whois'):
        out = _run(['whois', '-h', 'whois.cymru.com', f' -v {ip}'], timeout=10)
        if out:
            lines = [l for l in out.splitlines() if not l.startswith('AS')]
            for line in lines:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 5:
                    return {
                        'asn':     parts[0],
                        'ip':      parts[1],
                        'prefix':  parts[2],
                        'country': parts[3],
                        'org':     parts[4] if len(parts)>4 else '',
                    }
    # Method 2: ipinfo.io API
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent':'TeamCyberOps/4.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read())
            return {
                'asn':     d.get('org','').split()[0] if d.get('org') else '',
                'ip':      ip,
                'country': d.get('country',''),
                'org':     d.get('org',''),
                'city':    d.get('city',''),
                'region':  d.get('region',''),
                'hostname':d.get('hostname',''),
            }
    except Exception:
        pass
    return {'ip': ip}


def http_fingerprint(host, timeout=10):
    """HTTP probe: headers, title, tech, WAF, redirect chain."""
    results = {'host': host, 'status': None, 'title': '', 'headers': {},
               'waf': None, 'cdn': None, 'redirect': None,
               'server': '', 'x_powered_by': '', 'technologies': []}
    for scheme in ['https', 'http']:
        url = f"{scheme}://{host}"
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
                'Accept': 'text/html,application/xhtml+xml,*/*',
                'Accept-Language': 'en-US,en;q=0.9',
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                results['status']  = resp.status
                results['scheme']  = scheme
                results['url']     = url
                hdrs = dict(resp.headers)
                results['headers'] = {k.lower(): v for k, v in hdrs.items()}
                results['server']  = hdrs.get('Server','')
                results['x_powered_by'] = hdrs.get('X-Powered-By','')

                body = resp.read(8192).decode('utf-8', errors='replace')
                # Title
                m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
                results['title'] = m.group(1).strip()[:120] if m else ''
                # WAF detection
                results['waf'] = _detect_waf(hdrs, body)
                # CDN detection
                results['cdn'] = _detect_cdn(hdrs)
                # Tech fingerprinting
                results['technologies'] = _detect_tech(hdrs, body)
                break
        except urllib.error.HTTPError as e:
            results['status'] = e.code
            results['scheme'] = scheme
            break
        except Exception:
            continue
    return results


def _detect_waf(headers, body=''):
    """Detect WAF from headers and body."""
    WAF_SIGNATURES = {
        'Cloudflare':      ['cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare'],
        'AWS WAF':         ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-request-id'],
        'Akamai':          ['akamai-grn', 'x-akamai-transformed', 'x-check-cacheable'],
        'Fastly':          ['x-served-by', 'x-cache', 'fastly'],
        'Imperva/Incapsula':['x-iinfo', 'incap_ses', 'visid_incap'],
        'F5 BIG-IP':       ['bigipserver', 'f5-bigip', 'ts0'],
        'Sucuri':          ['x-sucuri-id', 'x-sucuri-cache'],
        'Barracuda':       ['barracuda_'],
        'Fortinet':        ['fortigate'],
        'ModSecurity':     ['mod_security', 'modsecurity'],
    }
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in h_lower or sig.lower() in body_lower:
                return waf
    return None


def _detect_cdn(headers):
    CDN_HEADERS = {
        'Cloudflare': 'cf-ray', 'Fastly': 'x-served-by',
        'Akamai': 'x-akamai-transformed', 'AWS CloudFront': 'x-amz-cf-id',
        'Varnish': 'x-varnish', 'Nginx': 'x-nginx-cache',
        'Sucuri': 'x-sucuri-id',
    }
    h_lower = {k.lower(): v for k, v in headers.items()}
    for cdn, header in CDN_HEADERS.items():
        if header.lower() in h_lower:
            return cdn
    return None


def _detect_tech(headers, body):
    """Quick technology detection from headers and page source."""
    tech = []
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()
    TECH_SIGS = {
        'WordPress':   ['wp-content', 'wp-includes', '/wp-json/'],
        'Drupal':      ['drupal.js', 'sites/default/files', 'drupal-settings-json'],
        'Joomla':      ['/components/com_', 'joomla'],
        'Laravel':     ['laravel_session', 'laravel'],
        'Django':      ['csrfmiddlewaretoken', '__django'],
        'Rails':       ['_rails_', 'authenticity_token'],
        'React':       ['__react', 'react-dom', 'data-reactroot'],
        'Angular':     ['ng-version', 'ng-controller', 'angular.js'],
        'Vue.js':      ['__vue__', 'vue-router', 'v-bind'],
        'jQuery':      ['jquery.min.js', 'jquery-'],
        'Bootstrap':   ['bootstrap.min.css', 'bootstrap.min.js'],
        'Nginx':       ['nginx' in str(h_lower.get('server',''))],
        'Apache':      ['apache' in str(h_lower.get('server',''))],
        'IIS':         ['iis' in str(h_lower.get('server',''))],
        'PHP':         ['.php', 'x-powered-by: php', 'phpsessid'],
        'ASP.NET':     ['asp.net', '__viewstate', 'x-aspnet-version'],
        'Node.js':     ['node.js', 'express', 'x-powered-by: express'],
        'GraphQL':     ['/graphql', 'graphql'],
        'Swagger UI':  ['swagger-ui', 'swagger.json'],
        'Jenkins':     ['x-jenkins', 'jenkins'],
        'Tomcat':      ['apache-coyote', 'tomcat'],
    }
    for t_name, sigs in TECH_SIGS.items():
        for sig in sigs:
            if isinstance(sig, bool):
                if sig: tech.append(t_name)
            elif sig.lower() in body_lower or sig.lower() in str(h_lower):
                if t_name not in tech:
                    tech.append(t_name)
                break
    return tech


def security_headers_check(headers):
    """Check for missing/misconfigured security headers."""
    issues = []
    h_lower = {k.lower(): v for k, v in headers.items()}
    SECURITY_HEADERS = {
        'strict-transport-security': ('HSTS missing', 'CRITICAL'),
        'content-security-policy':   ('CSP missing', 'HIGH'),
        'x-frame-options':           ('X-Frame-Options missing — Clickjacking possible', 'MEDIUM'),
        'x-content-type-options':    ('X-Content-Type-Options missing', 'LOW'),
        'referrer-policy':           ('Referrer-Policy missing', 'LOW'),
        'permissions-policy':        ('Permissions-Policy missing', 'LOW'),
        'x-xss-protection':          ('X-XSS-Protection missing', 'INFO'),
    }
    for header, (desc, severity) in SECURITY_HEADERS.items():
        if header not in h_lower:
            issues.append({'header': header, 'issue': desc, 'severity': severity})
        else:
            # Check HSTS value
            if header == 'strict-transport-security':
                val = h_lower[header]
                if 'max-age' in val:
                    m = re.search(r'max-age=(\d+)', val)
                    if m and int(m.group(1)) < 15768000:
                        issues.append({'header': header, 'issue': 'HSTS max-age < 6 months', 'severity': 'MEDIUM'})
                if 'includesubdomains' not in val.lower():
                    issues.append({'header': header, 'issue': 'HSTS missing includeSubDomains', 'severity': 'LOW'})
    # Check for dangerous headers
    DANGEROUS = {
        'x-powered-by':     ('Tech disclosure via X-Powered-By', 'INFO'),
        'server':           ('Server version disclosure', 'INFO'),
        'x-aspnet-version': ('ASP.NET version disclosure', 'INFO'),
        'x-aspnetmvc-version': ('ASP.NET MVC version disclosure', 'INFO'),
    }
    for header, (desc, severity) in DANGEROUS.items():
        if header in h_lower:
            issues.append({'header': header, 'issue': desc,
                           'value': h_lower[header], 'severity': severity})
    return issues


def check_subdomain_takeover_http(host):
    """Check HTTP response for subdomain takeover signatures."""
    findings = []
    try:
        for scheme in ['https','http']:
            try:
                req = urllib.request.Request(f"{scheme}://{host}",
                    headers={'User-Agent': 'TeamCyberOps/4.0'})
                with urllib.request.urlopen(req, timeout=8) as r:
                    body = r.read(4096).decode('utf-8', errors='replace')
                    for provider, sigs in TAKEOVER_SIGNATURES.items():
                        for sig in sigs:
                            if sig.lower() in body.lower():
                                findings.append({
                                    'provider': provider,
                                    'signature': sig,
                                    'scheme': scheme,
                                    'host': host,
                                })
                break
            except Exception:
                continue
    except Exception:
        pass
    return findings


def spf_dmarc_check(domain):
    """Check SPF and DMARC records."""
    result = {'spf': None, 'dmarc': None, 'issues': []}
    # SPF
    txt_records = dig_record(domain, 'TXT')
    for r in txt_records:
        if 'v=spf1' in r.lower():
            result['spf'] = r
            if '+all' in r:
                result['issues'].append({'type':'SPF', 'severity':'CRITICAL',
                    'issue': 'SPF uses +all — allows ANY server to send as this domain'})
            elif '~all' in r:
                result['issues'].append({'type':'SPF', 'severity':'MEDIUM',
                    'issue': 'SPF uses ~all (softfail) — consider -all (hardfail)'})
            break
    if not result['spf']:
        result['issues'].append({'type':'SPF', 'severity':'HIGH',
            'issue': 'No SPF record — email spoofing possible'})
    # DMARC
    dmarc_records = dig_record(f'_dmarc.{domain}', 'TXT')
    for r in dmarc_records:
        if 'v=dmarc1' in r.lower():
            result['dmarc'] = r
            if 'p=none' in r.lower():
                result['issues'].append({'type':'DMARC', 'severity':'HIGH',
                    'issue': 'DMARC policy is p=none — no enforcement, only monitoring'})
            break
    if not result['dmarc']:
        result['issues'].append({'type':'DMARC', 'severity':'HIGH',
            'issue': 'No DMARC record — phishing/spoofing not blocked'})
    return result


def port_scan_quick(ip, ports=None):
    """Quick port check using socket connect (no nmap required)."""
    if not ip: return {}
    ports = ports or [21,22,23,25,53,80,110,143,443,445,465,587,993,995,
                      1433,1521,2375,2376,3000,3306,3389,4848,5000,5432,
                      5900,6379,7001,8080,8443,8888,9200,9300,11211,27017]
    open_ports = {}
    def _check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((ip, port))
            s.close()
            return port, r == 0
        except Exception:
            return port, False
    with ThreadPoolExecutor(max_workers=50) as ex:
        for port, is_open in ex.map(lambda p: _check(p), ports):
            if is_open:
                open_ports[port] = _port_service(port)
    return open_ports


def _port_service(port):
    SERVICES = {
        21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
        110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',465:'SMTPS',
        587:'SMTP',993:'IMAPS',995:'POP3S',1433:'MSSQL',1521:'Oracle',
        2375:'Docker',2376:'Docker-TLS',3000:'Dev',3306:'MySQL',
        3389:'RDP',4848:'GlassFish',5000:'Flask/Dev',5432:'PostgreSQL',
        5900:'VNC',6379:'Redis',7001:'WebLogic',8080:'HTTP-Alt',
        8443:'HTTPS-Alt',8888:'Jupyter',9200:'Elasticsearch',
        9300:'Elasticsearch',11211:'Memcached',27017:'MongoDB',
    }
    return SERVICES.get(port, f'port/{port}')


def cors_check(host, origin_tests=None):
    """Test CORS misconfiguration."""
    origin_tests = origin_tests or [
        f"https://evil.com",
        f"https://{host}.evil.com",
        f"null",
        f"https://evil{host}",
    ]
    results = []
    for origin in origin_tests:
        try:
            req = urllib.request.Request(
                f"https://{host}/",
                headers={
                    'Origin': origin,
                    'User-Agent': 'TeamCyberOps/4.0',
                }
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                acao = r.headers.get('Access-Control-Allow-Origin','')
                acac = r.headers.get('Access-Control-Allow-Credentials','')
                if acao and (acao == origin or acao == '*'):
                    results.append({
                        'origin': origin,
                        'acao': acao,
                        'credentials': acac,
                        'vulnerable': acac.lower() == 'true' or acao == '*',
                        'severity': 'CRITICAL' if acac.lower() == 'true' else 'HIGH',
                    })
        except Exception:
            pass
    return results


# ══════════════════════════════════════════════════════════════
#  DEEP RECON CORE — per subdomain full analysis
# ══════════════════════════════════════════════════════════════

def deep_recon_subdomain(host, domain, log_cb=None):
    """
    Full deep reconnaissance on a single subdomain.
    Based on hunt.sh logic but MUCH more advanced.
    Returns complete intelligence dict.
    """
    log = log_cb or (lambda m, t='': None)
    result = {
        'host':          host,
        'domain':        domain,
        'timestamp':     datetime.now().isoformat(),
        'dns':           {},
        'ip_info':       {},
        'http':          {},
        'security_headers': [],
        'spf_dmarc':     {},
        'ports':         {},
        'cors':          [],
        'zone_transfer': [],
        'takeover':      [],
        'cname_takeover':[],
        'findings':      [],  # vuln findings
    }

    # ── 1. DNS — ALL record types ────────────────────────────
    log(f"  [DNS] Querying all record types for {host}", 'info')
    dns_data = {}
    for rtype in DNS_RECORD_TYPES:
        records = dig_record(host, rtype)
        if records:
            dns_data[rtype] = records

    result['dns'] = dns_data

    # ── 2. IP Geolocation + ASN ──────────────────────────────
    primary_ip = resolve_ip(host)
    if primary_ip:
        log(f"  [IP]  {host} → {primary_ip}", 'ok')
        result['ip_info'] = whois_asn(primary_ip)
        result['ip_info']['ip'] = primary_ip

        # Internal IP leak detection (from hunt.sh)
        if is_internal_ip(primary_ip):
            msg = f"INTERNAL IP LEAK: {host} resolves to {primary_ip}"
            result['findings'].append({
                'severity': 'CRITICAL',
                'type': 'Internal IP Exposure',
                'detail': msg,
            })
            log(f"  [!!!] {msg}", 'err')

    # ── 3. CNAME Analysis + Takeover Check ───────────────────
    cname_records = dns_data.get('CNAME', [])
    for cname in cname_records:
        log(f"  [CNAME] {host} → {cname}", 'info')
        # Cloud CNAME takeover potential
        cname_findings = detect_cname_takeover(host, cname)
        if cname_findings:
            for cf in cname_findings:
                log(f"  [!] Potential takeover: {cf['provider']} via CNAME {cname}", 'warn')
            result['cname_takeover'].extend(cname_findings)

    # ── 4. Zone Transfer Attempt ─────────────────────────────
    log(f"  [ZT]  Attempting zone transfer on {host}", 'info')
    zt = zone_transfer_check(host)
    if zt:
        for z in zt:
            msg = f"ZONE TRANSFER VULNERABLE: {host} via {z['ns']}"
            result['findings'].append({'severity': 'CRITICAL', 'type': 'Zone Transfer', 'detail': msg})
            log(f"  [!!!] {msg}", 'err')
        result['zone_transfer'] = zt

    # ── 5. SPF / DMARC ───────────────────────────────────────
    # Only run on root domain + first-level subdomains
    if host.count('.') <= domain.count('.') + 1:
        log(f"  [SPF] Checking SPF/DMARC on {host}", 'info')
        spf_dmarc = spf_dmarc_check(host)
        result['spf_dmarc'] = spf_dmarc
        for issue in spf_dmarc.get('issues', []):
            result['findings'].append({
                'severity': issue['severity'],
                'type': f"{issue['type']} Issue",
                'detail': issue['issue'],
            })
            if issue['severity'] in ('CRITICAL','HIGH'):
                log(f"  [!] {issue['issue']}", 'warn')

    # ── 6. HTTP Fingerprinting ────────────────────────────────
    log(f"  [HTTP] Fingerprinting {host}", 'info')
    http_data = http_fingerprint(host)
    result['http'] = http_data
    if http_data.get('status'):
        log(f"  [HTTP] {http_data.get('scheme','?')}://{host} → {http_data['status']} | {http_data.get('title','')[:60]}", 'ok')
        if http_data.get('waf'):
            log(f"  [WAF]  {host} → {http_data['waf']}", 'warn')
        if http_data.get('technologies'):
            log(f"  [TECH] {', '.join(http_data['technologies'][:6])}", 'info')

    # ── 7. Security Headers ───────────────────────────────────
    if http_data.get('headers'):
        header_issues = security_headers_check(http_data['headers'])
        result['security_headers'] = header_issues
        critical_headers = [h for h in header_issues if h['severity'] in ('CRITICAL','HIGH')]
        if critical_headers:
            for h in critical_headers:
                result['findings'].append({
                    'severity': h['severity'],
                    'type': 'Missing Security Header',
                    'detail': h['issue'],
                })

    # ── 8. HTTP-based Subdomain Takeover Check ────────────────
    log(f"  [TKO] Checking takeover signatures on {host}", 'info')
    takeover = check_subdomain_takeover_http(host)
    if takeover:
        for t in takeover:
            msg = f"SUBDOMAIN TAKEOVER: {host} → {t['provider']}"
            result['findings'].append({'severity': 'CRITICAL', 'type': 'Subdomain Takeover', 'detail': msg})
            log(f"  [!!!] {msg}", 'err')
        result['takeover'] = takeover

    # ── 9. Quick Port Scan ────────────────────────────────────
    if primary_ip:
        log(f"  [PORT] Quick port scan on {primary_ip}", 'info')
        open_ports = port_scan_quick(primary_ip)
        result['ports'] = open_ports
        if open_ports:
            interesting = {p:s for p,s in open_ports.items()
                          if p in [23,2375,5900,6379,9200,27017,11211,1521,1433]}
            for port, svc in interesting.items():
                result['findings'].append({
                    'severity': 'HIGH',
                    'type': 'Dangerous Open Port',
                    'detail': f"Port {port} ({svc}) open on {primary_ip}",
                })
                log(f"  [!] Port {port} ({svc}) open", 'warn')
            log(f"  [PORT] Open: {list(open_ports.keys())}", 'info')

    # ── 10. CORS Check ────────────────────────────────────────
    if http_data.get('status'):
        log(f"  [CORS] Testing CORS on {host}", 'info')
        cors_results = cors_check(host)
        result['cors'] = cors_results
        for c in cors_results:
            if c.get('vulnerable'):
                result['findings'].append({
                    'severity': c['severity'],
                    'type': 'CORS Misconfiguration',
                    'detail': f"Origin '{c['origin']}' accepted by {host}",
                })
                log(f"  [!] CORS vuln: origin {c['origin']} accepted", 'warn')

    total_findings = len(result['findings'])
    log(f"  [✓] {host} — {total_findings} finding(s)\n", 'ok' if total_findings else 'dim')
    return result


# ══════════════════════════════════════════════════════════════
#  MAIN DEEP RECON RUNNER
# ══════════════════════════════════════════════════════════════

def run_deep_recon(domain, subdomains, log_cb=None, max_workers=10,
                   proj_dir=None, stop_event=None):
    """
    Run deep recursive recon on all subdomains.
    Advanced version of hunt.sh — parallel, comprehensive.
    """
    log     = log_cb or (lambda m, t='': None)
    stop    = stop_event or threading.Event()
    results = {}
    proj    = proj_dir or (LOGS_DIR / domain)
    proj.mkdir(parents=True, exist_ok=True)

    total = len(subdomains)
    log(f"{'='*60}", 'dim')
    log(f"  DEEP RECURSIVE RECON — {domain}", 'info')
    log(f"  Subdomains: {total}  |  Workers: {max_workers}", 'info')
    log(f"  Checks per host: DNS(12) + IP/ASN + HTTP + WAF + CDN", 'info')
    log(f"  + Security Headers + SPF/DMARC + Zone Transfer", 'info')
    log(f"  + Subdomain Takeover + Port Scan + CORS", 'info')
    log(f"{'='*60}\n", 'dim')

    done    = [0]
    lock    = threading.Lock()

    def _process(host):
        if stop.is_set(): return host, None
        try:
            r = deep_recon_subdomain(host, domain, log_cb=log)
            with lock:
                done[0] += 1
                pct = int(done[0] / total * 100)
                log(f"  [{done[0]:3d}/{total}] {pct:3d}%  ──  {host}", 'dim')
            return host, r
        except Exception as e:
            with lock: done[0] += 1
            return host, {'host': host, 'error': str(e), 'findings': []}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_process, h): h for h in subdomains}
        for future in as_completed(futures):
            if stop.is_set(): break
            host, result = future.result()
            if result:
                results[host] = result

    # ── Aggregate all findings ────────────────────────────────
    all_findings = []
    for host, r in results.items():
        for f in r.get('findings', []):
            f['host'] = host
            all_findings.append(f)

    all_findings.sort(key=lambda x: {
        'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4
    }.get(x.get('severity','INFO'), 5))

    # ── Save outputs ──────────────────────────────────────────
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Full JSON report
    full_report = {
        'domain':    domain,
        'timestamp': datetime.now().isoformat(),
        'total_hosts': total,
        'scanned': len(results),
        'total_findings': len(all_findings),
        'findings': all_findings,
        'hosts': results,
    }
    json_path = proj / f"deep_recon_{ts}.json"
    with open(json_path, 'w') as f:
        json.dump(full_report, f, indent=2, default=str)

    # Text report (hunt.sh style but enriched)
    txt_path = proj / f"deep_recon_{ts}.txt"
    with open(txt_path, 'w') as f:
        f.write(f"{'='*65}\n")
        f.write(f"  DEEP RECURSIVE RECON REPORT\n")
        f.write(f"  Domain:    {domain}\n")
        f.write(f"  Date:      {datetime.now().isoformat()}\n")
        f.write(f"  Hosts:     {total} subdomains\n")
        f.write(f"  Findings:  {len(all_findings)}\n")
        f.write(f"{'='*65}\n\n")

        # Findings summary first
        if all_findings:
            f.write(f"{'─'*65}\n  ⚠  FINDINGS SUMMARY\n{'─'*65}\n")
            for fnd in all_findings:
                f.write(f"  [{fnd['severity']:8s}] {fnd['type']:30s} {fnd['host']}\n")
                f.write(f"             {fnd['detail']}\n\n")

        # Per-host details
        for host, r in sorted(results.items()):
            f.write(f"\n{'='*65}\n")
            f.write(f"  TARGET: {host}\n{'='*65}\n")
            # DNS
            for rtype, records in r.get('dns',{}).items():
                for rec in records:
                    f.write(f"  [DNS/{rtype:6s}] {rec}\n")
            # IP + ASN
            ipi = r.get('ip_info',{})
            if ipi.get('ip'):
                f.write(f"  [INFRA] IP: {ipi.get('ip','')} | ASN: {ipi.get('asn','')} | ORG: {ipi.get('org','')} | CC: {ipi.get('country','')}\n")
            # HTTP
            http = r.get('http',{})
            if http.get('status'):
                f.write(f"  [HTTP]  {http.get('scheme','?')}://{host} → {http['status']} | WAF: {http.get('waf','None')} | CDN: {http.get('cdn','None')}\n")
                f.write(f"  [TITLE] {http.get('title','')}\n")
                if http.get('technologies'):
                    f.write(f"  [TECH]  {', '.join(http['technologies'])}\n")
            # Ports
            ports = r.get('ports',{})
            if ports:
                f.write(f"  [PORTS] {', '.join(f'{p}/{s}' for p,s in ports.items())}\n")
            # SPF/DMARC
            sd = r.get('spf_dmarc',{})
            if sd.get('spf'):  f.write(f"  [SPF]   {sd['spf']}\n")
            if sd.get('dmarc'): f.write(f"  [DMARC] {sd['dmarc']}\n")

    # Findings only (quick reference)
    findings_path = proj / f"deep_recon_findings_{ts}.txt"
    with open(findings_path, 'w') as f:
        f.write(f"# DEEP RECON FINDINGS — {domain}\n\n")
        for fnd in all_findings:
            f.write(f"[{fnd['severity']:8s}] [{fnd['type']}] {fnd.get('host','')}\n")
            f.write(f"           {fnd['detail']}\n\n")

    log(f"\n{'='*60}", 'dim')
    log(f"  SCAN COMPLETE", 'info')
    log(f"  Hosts scanned:  {len(results)}/{total}", 'ok')
    log(f"  Total findings: {len(all_findings)}", 'ok' if all_findings else 'dim')
    crit = sum(1 for f in all_findings if f.get('severity')=='CRITICAL')
    high = sum(1 for f in all_findings if f.get('severity')=='HIGH')
    log(f"  CRITICAL: {crit}  HIGH: {high}", 'err' if crit else 'warn')
    log(f"  Saved → {json_path.name}", 'ok')
    log(f"{'='*60}", 'dim')

    return full_report, txt_path, json_path


# ══════════════════════════════════════════════════════════════
#  DeepReconEngine — OOP wrapper (used by GUI tab)
# ══════════════════════════════════════════════════════════════

class DeepReconEngine:
    """
    Object-oriented wrapper around run_deep_recon.
    Provides .run() → dict of results, and .findings list.
    """
    def __init__(self, domain: str, subdomains: list, output_dir=None,
                 log_cb=None, finding_cb=None, max_workers: int = 20,
                 stop_flag=None):
        self.domain      = domain
        self.subdomains  = subdomains
        self.output_dir  = output_dir or (LOGS_DIR / domain)
        self.log_cb      = log_cb or (lambda m, t='info': None)
        self.finding_cb  = finding_cb
        self.max_workers = max_workers
        self.stop_flag   = stop_flag or threading.Event()
        self.findings    = []   # populated after run()
        self._results    = {}   # raw per-host results

    # ------------------------------------------------------------------
    def run(self) -> dict:
        """
        Execute full deep recon.
        Returns dict[hostname → result_dict].
        Also populates self.findings.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        full_report, txt_path, json_path = run_deep_recon(
            domain       = self.domain,
            subdomains   = self.subdomains,
            log_cb       = self.log_cb,
            max_workers  = self.max_workers,
            proj_dir     = self.output_dir,
            stop_event   = self.stop_flag,
        )
        # Flatten results into self._results (hostname → data)
        hosts_data = full_report.get('hosts', {})
        self._results = hosts_data

        # Build findings list compatible with GUI expectations
        self.findings = []
        for host, hdata in hosts_data.items():
            for f in hdata.get('findings', []):
                finding = {
                    'hostname': host,
                    'severity': f.get('severity', 'INFO'),
                    'type':     f.get('type', 'Unknown'),
                    'detail':   f.get('detail', ''),
                    'cvss':     {'CRITICAL':'9.0','HIGH':'7.5','MEDIUM':'5.0',
                                 'LOW':'3.0','INFO':'0.0'}.get(f.get('severity','INFO'),'0.0'),
                }
                self.findings.append(finding)
                if self.finding_cb:
                    try:
                        self.finding_cb(finding)
                    except Exception:
                        pass

        # Build per-host summary dict for the Results Table tab
        results = {}
        for host, hdata in hosts_data.items():
            dns     = hdata.get('dns', {})
            http_d  = hdata.get('http', {})
            ip_info = hdata.get('ip_info', {})
            results[host] = {
                'dns':   dns,
                'http':  {
                    'status': http_d.get('status'),
                    'title':  http_d.get('title', ''),
                    'tech':   http_d.get('technologies', []),
                    'waf':    http_d.get('waf', ''),
                    'headers': http_d.get('headers', {}),
                },
                'infra': {
                    'ip':      ip_info.get('ip', ''),
                    'asn':     ip_info.get('asn', ''),
                    'org':     ip_info.get('org', ''),
                    'country': ip_info.get('country', ''),
                    'cdn':     http_d.get('cdn', ''),
                },
                'tls':      hdata.get('tls', {}),
                'ports':    [{'port': p, 'service': s}
                             for p, s in hdata.get('ports', {}).items()],
                'zone_xfer': {'vulnerable': bool(hdata.get('zone_transfer', []))},
                'findings': hdata.get('findings', []),
            }
        return results
