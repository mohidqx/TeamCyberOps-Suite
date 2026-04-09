"""
TeamCyberOps Suite v4 — Dorks Intelligence Module
Google Dorks | Shodan Dorks | Censys Dorks | GitHub Dorks
"""
import json
import urllib.parse
import webbrowser
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════
#  GOOGLE DORKS
# ══════════════════════════════════════════════════════════════════════

GOOGLE_DORK_CATEGORIES = {

    "🔑 Login Pages": [
        'site:{target} inurl:login',
        'site:{target} inurl:admin',
        'site:{target} inurl:signin',
        'site:{target} inurl:dashboard',
        'site:{target} inurl:portal',
        'site:{target} inurl:wp-admin',
        'site:{target} inurl:cpanel',
        'site:{target} inurl:phpmyadmin',
        'site:{target} intitle:"Login" OR intitle:"Sign In"',
        'site:{target} inurl:auth',
    ],

    "📁 Sensitive Files": [
        'site:{target} ext:env',
        'site:{target} ext:conf',
        'site:{target} ext:cfg',
        'site:{target} ext:ini',
        'site:{target} ext:bak',
        'site:{target} ext:old',
        'site:{target} ext:sql',
        'site:{target} ext:log',
        'site:{target} ext:xml inurl:config',
        'site:{target} ext:yaml OR ext:yml',
        'site:{target} ext:json inurl:config',
        'site:{target} ext:pem OR ext:key OR ext:crt',
        'site:{target} ext:htpasswd',
        'site:{target} intitle:"index of" ".env"',
        'site:{target} intitle:"index of" "backup"',
    ],

    "🗄️ Database Exposure": [
        'site:{target} ext:sql',
        'site:{target} inurl:phpMyAdmin',
        'site:{target} intitle:"phpMyAdmin" "Welcome to"',
        'site:{target} inurl:db_admin',
        'site:{target} intitle:"adminer"',
        'site:{target} inurl:adminer.php',
        'site:{target} ext:sql intitle:"MySQL dump"',
        'site:{target} intext:"sql syntax" OR intext:"mysql error"',
        'site:{target} inurl:sqlite OR inurl:mongodb',
    ],

    "🌐 Subdomains & Dirs": [
        'site:*.{target}',
        'site:{target} -www',
        'site:{target} inurl:api',
        'site:{target} inurl:dev OR inurl:staging OR inurl:test',
        'site:{target} inurl:beta',
        'site:{target} inurl:old OR inurl:backup',
        'site:{target} intitle:"index of"',
        'site:{target} intitle:"Apache2 Ubuntu Default Page"',
        'site:{target} inurl:/.git',
    ],

    "🔓 Exposed Credentials": [
        'site:{target} intext:"password" ext:log',
        'site:{target} intext:"api_key" OR intext:"api key"',
        'site:{target} intext:"secret_key" OR intext:"secret key"',
        'site:{target} intext:"access_token" OR intext:"accesstoken"',
        'site:{target} intext:"private_key"',
        'site:{target} filetype:env "DB_PASSWORD"',
        'site:{target} filetype:env "AWS_SECRET"',
        'site:{target} intext:"BEGIN RSA PRIVATE KEY"',
        'site:{target} intitle:"Credential" ext:xml OR ext:json',
    ],

    "📡 API Endpoints": [
        'site:{target} inurl:api/v1',
        'site:{target} inurl:api/v2',
        'site:{target} inurl:rest',
        'site:{target} inurl:graphql',
        'site:{target} inurl:swagger',
        'site:{target} inurl:swagger-ui',
        'site:{target} inurl:openapi',
        'site:{target} ext:json inurl:api',
        'site:{target} inurl:api-docs',
        'site:{target} inurl:wp-json/wp/v2',
    ],

    "🐛 Error Messages": [
        'site:{target} intext:"Fatal error"',
        'site:{target} intext:"Warning:" intext:"PHP"',
        'site:{target} intext:"Stack trace"',
        'site:{target} intext:"ORA-01756" OR intext:"mysql_fetch"',
        'site:{target} intext:"Traceback (most recent call last)"',
        'site:{target} intitle:"500 Internal Server Error"',
        'site:{target} intext:"SQLSTATE" OR intext:"PDOException"',
        'site:{target} intext:"exception" intext:"error" ext:log',
    ],

    "📋 Documents & Leaks": [
        'site:{target} ext:pdf',
        'site:{target} ext:docx OR ext:xlsx OR ext:pptx',
        'site:{target} ext:csv',
        'site:{target} intitle:"confidential" OR intitle:"internal use"',
        'site:{target} intext:"do not distribute"',
        'site:{target} ext:pdf intitle:"invoice" OR intitle:"contract"',
        'site:{target} ext:xlsx intext:"password" OR intext:"username"',
    ],

    "🔧 Tech Stack Detection": [
        'site:{target} intitle:"Welcome to nginx"',
        'site:{target} intext:"Powered by WordPress"',
        'site:{target} intext:"Powered by Joomla"',
        'site:{target} inurl:wp-content',
        'site:{target} intitle:"Laravel" OR inurl:laravel',
        'site:{target} intext:"Django" intext:"WSGI"',
        'site:{target} intitle:"IIS Windows Server"',
        'site:{target} intitle:"Apache Tomcat"',
    ],

    "📷 Cameras & IoT": [
        'site:{target} inurl:"/view/index.shtml"',
        'site:{target} intitle:"Live View / - AXIS"',
        'site:{target} inurl:ViewerFrame?Mode=',
        'site:{target} intitle:"webcamXP" inurl:8080',
        'site:{target} intitle:"netcam"',
    ],

    "📚 Books & eBooks (Open Directories)": [
        '{target} +(MOBI|CBZ|CBR|CBC|CHM|EPUB|FB2|LIT|LRF|ODT|PDF|PRC|PDB|PML|RB|RTF|TCR|DOC|DOCX) -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:index.of -inurl:(listen77|mp3raid|mp3toss|mp3drug|index_of|index-of|wallywashis|downloadmana)',
        '"{target}" +(epub|pdf|mobi|chm|lit|djvu) intitle:"index of" -inurl:(php|html|aspx)',
        'intitle:"index of" "{target}" (pdf|epub|mobi|chm) -inurl:(jsp|pl|php|html|aspx|htm)',
        '"{target}" intitle:"index.of" (ebook|book|manual|guide) (pdf|epub|mobi)',
        'site:{target} intitle:"index of" (pdf|epub|mobi|doc|docx)',
        '"{target}" filetype:pdf -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml)',
        '"{target}" filetype:epub -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml)',
        '"{target}" filetype:mobi -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml)',
    ],

    "🎬 Movies & TV Shows (Open Directories)": [
        '{target} +(mkv|mp4|avi|mov|mpg|wmv|divx|mpeg) -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:index.of -inurl:(listen77|mp3raid|mp3toss|mp3drug|index_of|index-of|wallywashis|downloadmana)',
        '"{target}" intitle:"index of" (mkv|mp4|avi|mov|mpeg|wmv) -inurl:(php|html|aspx)',
        'intitle:"index of" "{target}" (mkv|mp4|avi) -inurl:(jsp|pl|php|html|aspx|htm)',
        '"{target}" intitle:"index.of" (season|episode|s01|s02|720p|1080p|bluray)',
        'site:{target} intitle:"index of" (mkv|mp4|avi|mov)',
        '"{target}" intitle:"index of" "parent directory" (mkv|mp4|avi)',
    ],

    "🎵 Music & Audio (Open Directories)": [
        '{target} +(mp3|wav|ac3|ogg|flac|wma|m4a|aac|mod) -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:index.of -inurl:(listen77|mp3raid|mp3toss|mp3drug|index_of|index-of|wallywashis|downloadmana)',
        '"{target}" intitle:"index of" (mp3|flac|wav|ogg|m4a) -inurl:(php|html|aspx)',
        'intitle:"index of" "{target}" (mp3|flac|wav) -inurl:(jsp|pl|php|html|aspx|htm)',
        '"{target}" intitle:"index.of" (album|discography|music|audio) (mp3|flac)',
        'site:{target} intitle:"index of" (mp3|flac|wav|ogg)',
        '"{target}" filetype:mp3 intitle:"index of" -inurl:(php|html)',
    ],

    "💿 Software, ISO & Games (Open Directories)": [
        '{target} +(exe|iso|dmg|tar|7z|bz2|gz|rar|zip|apk) -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:index.of -inurl:(listen77|mp3raid|mp3toss|mp3drug|index_of|index-of|wallywashis|downloadmana)',
        '"{target}" intitle:"index of" (exe|iso|dmg|zip|rar|7z|apk) -inurl:(php|html|aspx)',
        'intitle:"index of" "{target}" (software|setup|install|crack|keygen) -inurl:(htm|html)',
        '"{target}" intitle:"index.of" (iso|img|bin|nrg|mdf) -inurl:(php|html)',
        'site:{target} intitle:"index of" (exe|msi|dmg|pkg|deb|rpm)',
        '"{target}" filetype:iso intitle:"index of" -inurl:(php|html)',
        '"{target}" intitle:"index of" (game|games|rom|roms) (zip|rar|7z|iso)',
    ],

    "🖼 Images & Photography (Open Directories)": [
        '{target} +(jpg|png|bmp|gif|tif|tiff|psd|webp|jpeg) -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:index.of -inurl:(listen77|mp3raid|mp3toss|mp3drug|index_of|index-of|wallywashis|downloadmana)',
        '"{target}" intitle:"index of" (jpg|png|gif|bmp|tiff|psd|raw) -inurl:(php|html|aspx)',
        'intitle:"index of" "{target}" (photos|pictures|images|gallery) -inurl:(htm|html)',
        '"{target}" intitle:"index.of" (wallpaper|photo|image|picture) (jpg|png|gif)',
        'site:{target} intitle:"index of" (jpg|jpeg|png|gif|tiff)',
        '"{target}" filetype:psd intitle:"index of" -inurl:(php|html)',
    ],

    "🗂 Other Files (Open Directories)": [
        '{target} -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:index.of -inurl:(listen77|mp3raid|mp3toss|mp3drug|index_of|index-of|wallywashis|downloadmana)',
        '"{target}" intitle:"index of" "parent directory" -inurl:(php|html|aspx)',
        'intitle:"index of" "{target}" -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml)',
        '"{target}" intitle:"index.of" -html -htm -php -asp -aspx',
        'site:{target} intitle:"index of" "last modified"',
        '"{target}" intitle:"directory listing" -inurl:(php|html|aspx)',
        '"{target}" intitle:"index of /" "parent directory"',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  SHODAN DORKS
# ══════════════════════════════════════════════════════════════════════

SHODAN_DORK_CATEGORIES = {

    "🌐 Web Servers": [
        'hostname:{target}',
        'hostname:{target} http.title:"Dashboard"',
        'hostname:{target} http.component:"WordPress"',
        'hostname:{target} product:"Apache httpd"',
        'hostname:{target} product:"nginx"',
        'hostname:{target} product:"IIS"',
        'org:"{target}" http.status:200',
        'ssl.cert.subject.cn:{target}',
        'ssl.cert.subject.cn:"*.{target}"',
    ],

    "🗄️ Databases": [
        'hostname:{target} port:3306',
        'hostname:{target} port:5432',
        'hostname:{target} port:27017',
        'hostname:{target} port:6379',
        'hostname:{target} port:9200',
        'hostname:{target} product:"MongoDB"',
        'hostname:{target} product:"Elasticsearch"',
        'hostname:{target} port:1433',
        'org:"{target}" port:3306 "MySQL"',
    ],

    "🔓 Open Services": [
        'hostname:{target} port:21',
        'hostname:{target} port:22',
        'hostname:{target} port:23',
        'hostname:{target} port:25',
        'hostname:{target} port:445',
        'hostname:{target} port:3389',
        'hostname:{target} port:5900',
        'hostname:{target} "authentication disabled"',
        'hostname:{target} port:2375 "Docker"',
        'hostname:{target} port:6443 "Kubernetes"',
    ],

    "☁️ Cloud & DevOps": [
        'org:"{target}" product:"Kubernetes"',
        'org:"{target}" http.title:"Grafana"',
        'org:"{target}" http.title:"Jenkins"',
        'org:"{target}" http.title:"GitLab"',
        'org:"{target}" http.title:"Prometheus"',
        'org:"{target}" product:"Docker"',
        'org:"{target}" http.title:"Kibana"',
        'org:"{target}" port:8080 http.title:"Jenkins"',
    ],

    "📡 IoT & Network": [
        'hostname:{target} product:"Cisco"',
        'hostname:{target} product:"Juniper"',
        'hostname:{target} "VNC authentication disabled"',
        'hostname:{target} port:161 "SNMP"',
        'hostname:{target} product:"Printer"',
        'org:"{target}" port:102',
        'org:"{target}" port:47808 "BACnet"',
    ],

    "🔑 Admin Panels": [
        'hostname:{target} http.title:"Admin"',
        'hostname:{target} http.title:"phpMyAdmin"',
        'hostname:{target} http.title:"cPanel"',
        'hostname:{target} http.title:"Webmin"',
        'hostname:{target} http.title:"pfSense"',
        'hostname:{target} http.title:"Netdata"',
        'hostname:{target} http.title:"Zabbix"',
        'hostname:{target} http.title:"Nagios"',
    ],

    "⚡ Vuln Signatures": [
        'hostname:{target} vuln:CVE-2021-44228',
        'hostname:{target} vuln:CVE-2017-0144',
        'hostname:{target} vuln:CVE-2019-0708',
        'hostname:{target} http.html:"<h1>Not supported</h1>"',
        'hostname:{target} "default password"',
        'hostname:{target} http.title:"Index of /"',
        'org:"{target}" "403 Forbidden" port:8080',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  CENSYS DORKS
# ══════════════════════════════════════════════════════════════════════

CENSYS_DORK_CATEGORIES = {

    "🌐 Domain & Cert": [
        'parsed.names: {target}',
        'parsed.subject_dn: {target}',
        'parsed.subject.common_name: {target}',
        'parsed.names: "*.{target}"',
        'parsed.issuer.common_name: {target}',
        'autonomous_system.name: "{target}"',
    ],

    "🗄️ Services": [
        'ip: {target} AND services.port: 22',
        'ip: {target} AND services.port: 3306',
        'ip: {target} AND services.port: 27017',
        'ip: {target} AND services.port: 6379',
        'ip: {target} AND services.port: 9200',
        'ip: {target} AND services.port: 5432',
        'ip: {target} AND services.port: 2375',
        'ip: {target} AND services.port: 6443',
    ],

    "🔓 HTTP Banner": [
        'services.http.response.html_title: "Admin" AND parsed.names: {target}',
        'services.http.response.html_title: "Dashboard" AND parsed.names: {target}',
        'services.http.response.html_title: "phpMyAdmin" AND parsed.names: {target}',
        'services.http.response.html_title: "Jenkins" AND parsed.names: {target}',
        'services.http.response.body: "DB_PASSWORD" AND parsed.names: {target}',
        'services.http.response.body: "api_key" AND parsed.names: {target}',
    ],

    "☁️ Cloud Infra": [
        'autonomous_system.name: "{target}" AND services.port: 443',
        'parsed.names: {target} AND services.tls.certificates.leaf.subject_dn: *',
        'parsed.names: "*.{target}" AND services.port: 8443',
        'labels: "cloud" AND parsed.names: {target}',
    ],

    "⚡ Vuln Checks": [
        'parsed.names: {target} AND services.truncated: true',
        'parsed.names: {target} AND services.http.response.status_code: 401',
        'parsed.names: {target} AND services.http.response.status_code: 500',
        'services.certificate: * AND parsed.names: {target} AND parsed.subject.organization: *',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  GITHUB DORKS
# ══════════════════════════════════════════════════════════════════════

GITHUB_DORK_CATEGORIES = {

    "🔑 Credentials & Secrets": [
        '"{target}" password',
        '"{target}" secret_key',
        '"{target}" api_key',
        '"{target}" private_key',
        '"{target}" access_token',
        '"{target}" oauth_token',
        '"{target}" auth_token',
        '"{target}" DB_PASSWORD',
        '"{target}" AWS_SECRET_ACCESS_KEY',
        '"{target}" "client_secret"',
        '"{target}" "-----BEGIN RSA PRIVATE KEY-----"',
        '"{target}" "-----BEGIN PGP PRIVATE KEY BLOCK-----"',
    ],

    "⚙️ Config Files": [
        '"{target}" filename:.env',
        '"{target}" filename:config.yml',
        '"{target}" filename:config.json',
        '"{target}" filename:.htpasswd',
        '"{target}" filename:wp-config.php',
        '"{target}" filename:settings.py',
        '"{target}" filename:database.yml',
        '"{target}" filename:credentials',
        '"{target}" filename:.bashrc',
        '"{target}" filename:Dockerfile',
        '"{target}" filename:docker-compose.yml',
    ],

    "🔐 SSH & Certs": [
        '"{target}" filename:id_rsa',
        '"{target}" filename:id_dsa',
        '"{target}" filename:*.pem',
        '"{target}" filename:*.key',
        '"{target}" "ssh-rsa"',
        '"{target}" "authorized_keys"',
    ],

    "🗄️ DB Dumps & Backups": [
        '"{target}" extension:sql',
        '"{target}" extension:dump',
        '"{target}" extension:bak',
        '"{target}" filename:*.sql.gz',
        '"{target}" "CREATE TABLE" extension:sql',
        '"{target}" "INSERT INTO" extension:sql',
        '"{target}" filename:backup',
    ],

    "🌐 Endpoints & URLs": [
        '"{target}" inurl:api',
        '"{target}" "https://{target}" language:javascript',
        '"{target}" path:*.js url',
        '"{target}" "graphql" language:javascript',
        '"{target}" "swagger" filename:*.yaml',
        '"{target}" "baseUrl" OR "base_url"',
    ],

    "📧 Emails & Internal": [
        '"{target}" "@{target}"',
        '"{target}" "internal" OR "confidential"',
        '"{target}" "do not share"',
        '"{target}" "internal only"',
        '"{target}" "proprietary"',
        '"{target}" employee',
    ],

    "⚡ CVEs & Exploits": [
        'org:{target} security',
        'org:{target} vulnerability',
        'org:{target} exploit',
        '"{target}" CVE-',
        'org:{target} filename:*.log',
        'org:{target} "error" filename:*.log',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  URL BUILDERS
# ══════════════════════════════════════════════════════════════════════

def build_google_url(dork: str) -> str:
    return f"https://www.google.com/search?q={urllib.parse.quote(dork)}&num=50"

def build_bing_url(dork: str) -> str:
    return f"https://www.bing.com/search?q={urllib.parse.quote(dork)}"

def build_shodan_url(dork: str) -> str:
    return f"https://www.shodan.io/search?query={urllib.parse.quote(dork)}"

def build_censys_url(dork: str) -> str:
    return f"https://search.censys.io/hosts?q={urllib.parse.quote(dork)}"

def build_github_url(dork: str) -> str:
    return f"https://github.com/search?q={urllib.parse.quote(dork)}&type=code"

def build_fofa_url(dork: str) -> str:
    import base64
    return f"https://fofa.info/result?qbase64={base64.b64encode(dork.encode()).decode()}"

def build_hunter_url(dork: str) -> str:
    import base64
    return f"https://hunter.how/list?searchValue={urllib.parse.quote(dork)}"

# ══════════════════════════════════════════════════════════════════════
#  DORK GENERATION
# ══════════════════════════════════════════════════════════════════════

def generate_google_dorks(target: str, categories: list = None) -> dict:
    """Generate all Google dorks for a target."""
    result = {}
    cats = categories or list(GOOGLE_DORK_CATEGORIES.keys())
    for cat in cats:
        if cat in GOOGLE_DORK_CATEGORIES:
            result[cat] = [d.replace("{target}", target) for d in GOOGLE_DORK_CATEGORIES[cat]]
    return result


def generate_shodan_dorks(target: str, categories: list = None) -> dict:
    result = {}
    cats = categories or list(SHODAN_DORK_CATEGORIES.keys())
    for cat in cats:
        if cat in SHODAN_DORK_CATEGORIES:
            result[cat] = [d.replace("{target}", target) for d in SHODAN_DORK_CATEGORIES[cat]]
    return result


def generate_censys_dorks(target: str, categories: list = None) -> dict:
    result = {}
    cats = categories or list(CENSYS_DORK_CATEGORIES.keys())
    for cat in cats:
        if cat in CENSYS_DORK_CATEGORIES:
            result[cat] = [d.replace("{target}", target) for d in CENSYS_DORK_CATEGORIES[cat]]
    return result


def generate_github_dorks(target: str, categories: list = None) -> dict:
    result = {}
    cats = categories or list(GITHUB_DORK_CATEGORIES.keys())
    for cat in cats:
        if cat in GITHUB_DORK_CATEGORIES:
            result[cat] = [d.replace("{target}", target) for d in GITHUB_DORK_CATEGORIES[cat]]
    return result


def get_all_dorks_flat(engine: str, target: str) -> list:
    """Return all dorks for an engine as flat list."""
    engine_map = {
        "google":  GOOGLE_DORK_CATEGORIES,
        "shodan":  SHODAN_DORK_CATEGORIES,
        "censys":  CENSYS_DORK_CATEGORIES,
        "github":  GITHUB_DORK_CATEGORIES,
    }
    cats = engine_map.get(engine.lower(), {})
    result = []
    for dorks in cats.values():
        result.extend([d.replace("{target}", target) for d in dorks])
    return result


def export_dorks_txt(target: str, output_path: str) -> str:
    """Export all dorks to a text file."""
    lines = []
    for engine, cats in [
        ("GOOGLE", GOOGLE_DORK_CATEGORIES),
        ("SHODAN", SHODAN_DORK_CATEGORIES),
        ("CENSYS", CENSYS_DORK_CATEGORIES),
        ("GITHUB", GITHUB_DORK_CATEGORIES),
    ]:
        lines.append(f"\n{'='*60}")
        lines.append(f"  {engine} DORKS — Target: {target}")
        lines.append(f"{'='*60}\n")
        for cat, dorks in cats.items():
            lines.append(f"\n[ {cat} ]")
            for d in dorks:
                lines.append(f"  {d.replace('{target}', target)}")
    content = "\n".join(lines)
    with open(output_path, 'w') as f:
        f.write(content)
    return output_path


def count_total_dorks() -> dict:
    return {
        "google":  sum(len(v) for v in GOOGLE_DORK_CATEGORIES.values()),
        "shodan":  sum(len(v) for v in SHODAN_DORK_CATEGORIES.values()),
        "censys":  sum(len(v) for v in CENSYS_DORK_CATEGORIES.values()),
        "github":  sum(len(v) for v in GITHUB_DORK_CATEGORIES.values()),
    }


def save_dorks_for_target(target: str, output_dir, log_cb=None) -> dict:
    """
    Save all 4 engine dork files to output_dir.
    Returns dict of {engine: filepath}
    """
    from pathlib import Path
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    saved = {}
    log   = log_cb or (lambda m, t='': None)

    engine_map = [
        ("google", GOOGLE_DORK_CATEGORIES, "dorks_google.txt"),
        ("shodan", SHODAN_DORK_CATEGORIES, "dorks_shodan.txt"),
        ("censys", CENSYS_DORK_CATEGORIES, "dorks_censys.txt"),
        ("github", GITHUB_DORK_CATEGORIES, "dorks_github.txt"),
    ]

    total = 0
    for engine, cats, fname in engine_map:
        lines  = [f"# {engine.upper()} DORKS  —  Target: {target}",
                  f"# Generated: {__import__('datetime').datetime.now().isoformat()}",
                  f"# Total: {sum(len(v) for v in cats.values())} dorks\n"]
        for cat, dorks in cats.items():
            lines.append(f"\n## {cat}")
            for d in dorks:
                lines.append(d.replace("{target}", target))
        fpath = out / fname
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        saved[engine] = str(fpath)
        count = sum(len(v) for v in cats.values())
        total += count
        log(f"[+] Saved {count:3d} {engine.upper()} dorks → {fname}", "ok")

    # Also save combined file
    combined_path = out / "dorks_all.txt"
    with open(combined_path, 'w', encoding='utf-8') as f:
        f.write(f"# ALL DORKS — Target: {target}\n")
        f.write(f"# Total: {total} dorks across 4 engines\n\n")
        for engine, _, fname in engine_map:
            fpath = out / fname
            if fpath.exists():
                f.write(f"\n{'='*60}\n")
                f.write(fpath.read_text(encoding='utf-8'))
    saved['all'] = str(combined_path)
    log(f"[✓] Total {total} dorks saved → dorks_all.txt", "ok")
    return saved


def get_category_dorks_flat(engine: str, target: str, category: str = None) -> dict:
    """Return dorks organized by category."""
    engine_map = {
        "google": GOOGLE_DORK_CATEGORIES,
        "shodan": SHODAN_DORK_CATEGORIES,
        "censys": CENSYS_DORK_CATEGORIES,
        "github": GITHUB_DORK_CATEGORIES,
    }
    cats = engine_map.get(engine.lower(), {})
    result = {}
    for cat, dorks in cats.items():
        if category and category != cat: continue
        result[cat] = [d.replace("{target}", target) for d in dorks]
    return result
