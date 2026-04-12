"""
TeamCyberOps Suite v4 — Active Recon Module (Production Grade)
Port Scanning · Directory Fuzzing · Tech Detection · Screenshot capture
All tools have Python fallbacks — works on Windows/Linux/macOS
"""
# BUG #31 fix: removed unused 'ssl' import
import json, subprocess, urllib.request, urllib.parse, re, socket
import threading, concurrent.futures, os, time
from pathlib import Path
from datetime import datetime
from functools import lru_cache  # BUG #27 fix: cache tool availability

BASE_DIR = Path(__file__).parent.parent.parent
CFG_PATH = BASE_DIR / "config.json"
LOGS_DIR = BASE_DIR / "logs"

def _cfg():
    try:
        with open(CFG_PATH) as f: return json.load(f)
    except Exception: return {}

@lru_cache(maxsize=64)
def _tool_exists(name):
    """BUG #27: Cache tool availability — avoids repeated shutil.which() calls."""
    import shutil
    return shutil.which(name) is not None

def _run(cmd, timeout=180):
    """BUG #37: Always uses list form (shell=False) — no shell injection risk."""
    try:
        # Ensure cmd is always a list — never a string to avoid shell injection
        if isinstance(cmd, str):
            cmd = cmd.split()
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""
    except (FileNotFoundError, OSError):
        return ""
    except Exception:
        return ""

def _save(project, filename, content):
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    p = d / filename
    with open(p, 'w') as f: f.write(content if isinstance(content,str) else '\n'.join(content))
    return str(p)

# ── httpx (probe live hosts) ─────────────────────────────────────
def probe_hosts(hosts_file_or_list, project, log_cb=None, timeout=10):
    log = log_cb or (lambda m,t='': None)
    if isinstance(hosts_file_or_list, list):
        tmp = LOGS_DIR / project / "_tmp_hosts.txt"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text('\n'.join(hosts_file_or_list))
        hosts_file = str(tmp)
    else:
        hosts_file = hosts_file_or_list
    out_file = str(LOGS_DIR / project / "httpx.txt")

    if _tool_exists("httpx"):
        log("[httpx] Probing live hosts...", "info")
        cmd = ["httpx", "-l", hosts_file, "-o", out_file, "-silent",
               "-title", "-status-code", "-content-length", "-tech-detect",
               "-follow-redirects", "-threads", "50", "-timeout", str(timeout)]
        _run(cmd, 300)
        try:
            lines = [l for l in open(out_file).readlines() if l.strip()]
            log(f"[httpx] {len(lines)} live hosts", "ok")
            return lines
        except Exception: pass

    # Python fallback
    log("[httpx] Tool not found — using Python HTTP prober", "warn")
    hosts = [l.strip() for l in open(hosts_file) if l.strip()] if os.path.isfile(hosts_file) else hosts_file_or_list
    live = []; lock = threading.Lock()

    def _check(host):
        for scheme in ["https","http"]:
            url = f"{scheme}://{host}" if not host.startswith("http") else host
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    status = r.status
                    title_m = re.search(r'<title[^>]*>(.*?)</title>',
                                        r.read(3000).decode("utf-8","replace"), re.I|re.S)
                    title = title_m.group(1).strip()[:50] if title_m else ""
                    with lock:
                        line = f"{url} [{status}] [{title}]"
                        live.append(line)
                        log(f"  [+] {line}", "ok")
                    return
            except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_check, hosts[:500]))
    _save(project, "httpx.txt", live)
    log(f"[HTTP Probe] {len(live)} live hosts", "ok")
    return live

# ── nmap (port scanning) ─────────────────────────────────────────
def port_scan(target, project, scan_type="standard", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    out_file = str(LOGS_DIR / project / f"nmap_{scan_type}.txt")

    scan_configs = {
        "quick":    ["-T4", "-F", "--open", "-sV"],
        "standard": ["-T4", "-p", "1-10000", "--open", "-sV", "-sC"],
        "full":     ["-T4", "-p-", "--open", "-sV", "-sC"],
        "vuln":     ["-T4", "-p", "1-10000", "--script=vuln", "--open"],
        "udp":      ["-T4", "-sU", "--top-ports", "100", "--open"],
    }
    flags = scan_configs.get(scan_type, scan_configs["standard"])

    if _tool_exists("nmap"):
        log(f"[nmap] {scan_type} scan on {target}", "info")
        cmd = ["nmap"] + flags + [target, "-oN", out_file]
        out = _run(cmd, 600)
        ports = parse_nmap_output(out)
        log(f"[nmap] {len(ports)} open ports", "ok" if ports else "dim")
        return ports

    # Python fallback — TCP connect scan
    log(f"[PortScan] nmap not found — Python TCP scanner", "warn")
    COMMON_PORTS = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
        80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
        465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",
        1433:"MSSQL",1521:"Oracle",2222:"SSH-Alt",3000:"Node",
        3306:"MySQL",3389:"RDP",4444:"Metasploit",5432:"PostgreSQL",
        5900:"VNC",5984:"CouchDB",6379:"Redis",7001:"WebLogic",
        8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",9200:"Elasticsearch",
        9300:"Elasticsearch",27017:"MongoDB",50000:"SAP",
    }
    open_ports = []; lock = threading.Lock()

    def _check_port(port, service):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                with lock:
                    open_ports.append({"port":port,"service":service,"state":"open"})
                    log(f"  [+] {port}/tcp  open  {service}", "ok")
        except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(lambda kv: _check_port(*kv), COMMON_PORTS.items()))

    result = sorted(open_ports, key=lambda x: x["port"])
    lines = [f"{p['port']}/tcp  open  {p['service']}" for p in result]
    _save(project, f"nmap_{scan_type}.txt", lines)
    log(f"[PortScan] {len(result)} open ports", "ok" if result else "dim")
    return result

def parse_nmap_output(text):
    ports = []
    for line in text.splitlines():
        m = re.match(r'(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)', line)
        if m:
            ports.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "state":   m.group(3),
                "service": m.group(4),
                "version": m.group(5).strip(),
            })
    return ports

# ── Directory fuzzing ────────────────────────────────────────────
BUILTIN_DIRS = [
    "admin","login","wp-admin","phpmyadmin","administrator",
    ".env",".git","backup","api","swagger","graphql",
    "api/v1","api/v2",".git/HEAD",".git/config","config","debug",
    "console","monitor","health","status","metrics","actuator",
    "actuator/env","actuator/health","server-info","server-status",
    "robots.txt","sitemap.xml","crossdomain.xml",".htaccess",
    "wp-config.php","web.config","app.config","settings.py",
    "database.yml","config.php","phpinfo.php","info.php","test.php",
    "db.sql","backup.zip","backup.tar.gz","database.sql","dump.sql",
    ".DS_Store",".svn","CVS","Thumbs.db","error_log","access_log",
    "upload","uploads","files","media","assets","static",
    "old","new","dev","test","staging","beta","prod",
    "dashboard","panel","manage","internal","private",
]

def dir_fuzz(url, project, wordlist=None, extensions="php,html,txt,js",
             threads=50, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[DirFuzz] Scanning {url}", "info")
    out_file = str(LOGS_DIR / project / "dirsearch.txt")
    base = url.rstrip("/")

    if _tool_exists("ffuf"):
        wl = wordlist or _cfg().get("wordlists",{}).get("directories","")
        if wl and os.path.isfile(wl):
            log(f"[ffuf] Running with {wl}", "info")
            cmd = ["ffuf", "-u", f"{base}/FUZZ", "-w", wl,
                   "-e", "." + extensions.replace(",",",."),
                   "-t", str(threads), "-mc", "200,201,204,301,302,307,401,403,405",
                   "-o", out_file, "-of", "json", "-s"]
            _run(cmd, 300)
            try:
                data = json.load(open(out_file))
                results = data.get("results",[])
                found = [{"url":r["url"],"status":r["status"],"length":r["length"]} for r in results]
                log(f"[ffuf] {len(found)} paths found", "ok" if found else "dim")
                return found
            except Exception: pass

    if _tool_exists("gobuster"):
        wl = wordlist or _cfg().get("wordlists",{}).get("directories","")
        if wl and os.path.isfile(wl):
            log(f"[gobuster] Running", "info")
            cmd = ["gobuster","dir","-u",base,"-w",wl,"-x",extensions,"-t",str(threads),"--no-error","-q"]
            out = _run(cmd, 300)
            found = []
            for line in out.splitlines():
                m = re.match(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
                if m: found.append({"url":base+m.group(1),"status":int(m.group(2))})
            log(f"[gobuster] {len(found)} paths found", "ok" if found else "dim")
            return found

    # Python fallback
    log(f"[DirFuzz] No fuzzing tool — Python brute-forcer ({len(BUILTIN_DIRS)} paths)", "warn")
    found = []; lock = threading.Lock()
    paths = BUILTIN_DIRS[:]
    if wordlist and os.path.isfile(wordlist):
        paths = [l.strip() for l in open(wordlist) if l.strip()][:2000]

    def _check(path):
        for scheme_url in [f"{base}/{path.lstrip('/')}"]:
            try:
                req = urllib.request.Request(scheme_url, headers={"User-Agent":"TeamCyberOps/4"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    if r.status in (200,201,204,403):
                        with lock:
                            found.append({"url":scheme_url,"status":r.status,"length":0})
                            log(f"  [{r.status}] {scheme_url}", "ok")
            except urllib.error.HTTPError as e:
                if e.code in (401,403,405):
                    with lock:
                        found.append({"url":scheme_url,"status":e.code,"length":0})
                        log(f"  [{e.code}] {scheme_url}", "warn")
            except Exception: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(_check, paths))

    _save(project, "dirsearch.txt", [f"[{f['status']}] {f['url']}" for f in found])
    log(f"[DirFuzz] {len(found)} paths found", "ok" if found else "dim")
    return found

# ── Tech detection ───────────────────────────────────────────────
TECH_SIGNATURES = {
    "WordPress":     [r'wp-content',r'wp-includes',r'WordPress'],
    "Drupal":        [r'Drupal',r'/sites/default/'],
    "Joomla":        [r'Joomla',r'/components/com_'],
    "Laravel":       [r'laravel_session',r'X-Powered-By: PHP'],
    "Django":        [r'csrfmiddlewaretoken',r'django'],
    "Ruby on Rails": [r'X-Runtime',r'_rails_session'],
    "ASP.NET":       [r'ASP\.NET',r'__VIEWSTATE',r'X-AspNet-Version'],
    "Angular":       [r'ng-version',r'angular',r'ng-app'],
    "React":         [r'react-dom',r'__react_devtools',r'_reactRootContainer'],
    "Vue.js":        [r'vue\.js',r'__vue__',r'v-app'],
    "jQuery":        [r'jquery',r'jQuery'],
    "Bootstrap":     [r'bootstrap'],
    "Cloudflare":    [r'cf-ray',r'cloudflare',r'__cfduid'],
    "Akamai":        [r'akamai',r'AkamaiGHost'],
    "AWS":           [r'x-amzn',r'amazonaws',r'X-Cache: Hit from cloudfront'],
    "Nginx":         [r'nginx'],
    "Apache":        [r'Apache'],
    "IIS":           [r'Microsoft-IIS',r'X-Powered-By: ASP'],
    "PHP":           [r'X-Powered-By: PHP',r'\.php'],
    "Java":          [r'X-Powered-By: Servlet',r'JSESSIONID',r'\.jsp'],
    "Node.js":       [r'X-Powered-By: Express',r'node\.js'],
    "GraphQL":       [r'graphql',r'"__typename"'],
}

def detect_tech(url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    detected = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(5000).decode("utf-8","replace")
            headers_str = '\n'.join(f"{k}: {v}" for k,v in r.headers.items())
            full = body + '\n' + headers_str
        for tech, patterns in TECH_SIGNATURES.items():
            if any(re.search(p, full, re.I) for p in patterns):
                detected.append(tech)
                log(f"  [+] {tech}", "ok")
        if not detected:
            log(f"  [-] No known tech detected", "dim")
    except Exception as e:
        log(f"  [!] Error: {e}", "err")
    return detected

# ── WAF Detection ────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray","cloudflare","__cfduid","cloudflare-nginx"],
    "Akamai":      ["akamai","akamaiGHost","x-check-cacheable"],
    "Imperva":     ["incap_ses","visid_incap","x-iinfo","x-cdn=Imperva"],
    "Sucuri":      ["x-sucuri-id","sucuri/cloudproxy"],
    "AWS WAF":     ["awswaf","x-amzn-requestid","aws-waf"],
    "F5 BIG-IP":   ["bigipserver","f5-trafficshield","x-waf-status"],
    "Barracuda":   ["barra_counter_session","barracuda_"],
    "Wordfence":   ["wordfence"],
    "ModSecurity": ["mod_security","NOYB","modsecurity"],
    "Nginx WAF":   ["x-ngx-me","x-nf-request-id"],
    "Fortinet":    ["fortigate","fortiweb"],
    "Fastly":      ["x-fastly-request-id","fastly"],
}

def detect_waf(url, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    detected = []
    # Normal request
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/4"})
        with urllib.request.urlopen(req, timeout=10) as r:
            hdrs = '\n'.join(f"{k.lower()}: {v.lower()}" for k,v in r.headers.items())
            body = r.read(1000).decode("utf-8","replace").lower()
            full = hdrs + '\n' + body
    except urllib.error.HTTPError as e:
        full = '\n'.join(f"{k.lower()}: {v.lower()}" for k,v in e.headers.items())
        full += e.read(500).decode("utf-8","replace").lower()
    except Exception: return ["Unknown / No WAF detected"]

    for waf, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in full for s in sigs):
            detected.append(waf)
            log(f"  [WAF] {waf} detected", "warn")

    # Also check with malicious payload (triggers WAF)
    try:
        xss_req = urllib.request.Request(
            url + "?q=<script>alert(1)</script>",
            headers={"User-Agent":"TeamCyberOps/4"})
        with urllib.request.urlopen(xss_req, timeout=8) as r:
            pass
    except urllib.error.HTTPError as e:
        if e.code in (403, 406, 429, 444):
            hdrs2 = '\n'.join(f"{k.lower()}: {v.lower()}" for k,v in e.headers.items())
            for waf, sigs in WAF_SIGNATURES.items():
                if waf not in detected and any(s.lower() in hdrs2 for s in sigs):
                    detected.append(waf); log(f"  [WAF] {waf} (from XSS probe)", "warn")
    except Exception: pass

    if not detected:
        log("  [WAF] No WAF detected", "dim")
    return detected if detected else ["None detected"]

# ── Build commands ───────────────────────────────────────────────
def build_cmd_nmap(target, flags="-sV -sC -T4 --open"):
    return ["nmap"] + flags.split() + [target]

def build_cmd_nmap_full(target):
    return ["nmap", "-p-", "-sV", "-sC", "-T4", "--open", target]

def build_cmd_ffuf(url, wordlist, extensions="php,html,txt,js,json", threads="50"):
    cfg = _cfg(); wl = wordlist or cfg.get("wordlists",{}).get("directories","")
    return ["ffuf","-u",f"{url}/FUZZ","-w",wl,
            "-e","."+extensions.replace(",",",.")  if extensions else "",
            "-t",threads,"-mc","200,201,204,301,302,307,401,403","-c","-v"]

def build_cmd_gobuster(url, wordlist, extensions="php,html,txt"):
    cfg = _cfg(); wl = wordlist or cfg.get("wordlists",{}).get("directories","")
    return ["gobuster","dir","-u",url,"-w",wl,"-x",extensions,"-t","50","--no-error"]

def build_cmd_httpx(input_file, output_file):
    return ["httpx","-l",input_file,"-o",output_file,"-silent",
            "-title","-status-code","-content-length","-tech-detect",
            "-follow-redirects","-threads","50","-timeout","10"]

def save_ports(project, target, ports):
    d = LOGS_DIR / project; d.mkdir(parents=True, exist_ok=True)
    lines = [f"{p['port']}/{p.get('proto','tcp')}  {p.get('state','open')}  {p.get('service','')}  {p.get('version','')}" for p in ports]
    (d / "ports.txt").write_text('\n'.join(lines))
    return lines
