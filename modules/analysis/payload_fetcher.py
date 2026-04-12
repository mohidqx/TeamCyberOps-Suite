"""
TeamCyberOps Suite — Advanced Payload Manager
Fetch payloads from Exploit-DB, SecWordlist, PayloadAllThings
"""
import json, urllib.request, urllib.parse, re, shutil
from pathlib import Path

BASE_DIR  = Path(__file__).parent.parent.parent
CACHE_DIR = BASE_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)

# ══════════════════════════════════════════════════════════════
#  PAYLOADS ALL THE THINGS (GitHub)
# ══════════════════════════════════════════════════════════════

PATT_BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

PATT_SOURCES = {
    "XSS":               f"{PATT_BASE}/XSS%20Injection/README.md",
    "SQL Injection":     f"{PATT_BASE}/SQL%20Injection/README.md",
    "SSRF":              f"{PATT_BASE}/Server%20Side%20Request%20Forgery/README.md",
    "LFI":               f"{PATT_BASE}/File%20Inclusion/README.md",
    "RCE":               f"{PATT_BASE}/Command%20Injection/README.md",
    "SSTI":              f"{PATT_BASE}/Server%20Side%20Template%20Injection/README.md",
    "XXE":               f"{PATT_BASE}/XXE%20Injection/README.md",
    "Open Redirect":     f"{PATT_BASE}/Open%20Redirect/README.md",
    "IDOR":              f"{PATT_BASE}/Insecure%20Direct%20Object%20References/README.md",
    "Path Traversal":    f"{PATT_BASE}/Directory%20Traversal/README.md",
    "JWT":               f"{PATT_BASE}/JSON%20Web%20Token/README.md",
    "CSRF":              f"{PATT_BASE}/Cross-Site%20Request%20Forgery/README.md",
    "OAuth":             f"{PATT_BASE}/OAuth/README.md",
    "GraphQL":           f"{PATT_BASE}/GraphQL%20Injection/README.md",
    "LDAP Injection":    f"{PATT_BASE}/LDAP%20Injection/README.md",
    "NoSQL Injection":   f"{PATT_BASE}/NoSQL%20Injection/README.md",
    "HTTP Request Smuggling": f"{PATT_BASE}/HTTP%20Request%20Smuggling/README.md",
    "Race Condition":    f"{PATT_BASE}/Race%20Condition/README.md",
    "Mass Assignment":   f"{PATT_BASE}/Mass%20Assignment/README.md",
    "Prototype Pollution":f"{PATT_BASE}/Prototype%20Pollution/README.md",
}

def fetch_patt_payloads(category: str) -> dict:
    """Fetch payloads from PayloadsAllTheThings GitHub."""
    url = PATT_SOURCES.get(category)
    if not url:
        return {"error": f"Category '{category}' not found", "payloads": []}

    cache_file = CACHE_DIR / f"patt_{category.replace(' ','_').lower()}.md"
    content    = ""

    # Check cache (24h TTL)
    import time
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
        content = cache_file.read_text(encoding="utf-8", errors="replace")
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                content = r.read().decode("utf-8", errors="replace")
            cache_file.write_text(content, encoding="utf-8")
        except Exception as e:
            if cache_file.exists():
                content = cache_file.read_text(encoding="utf-8", errors="replace")
            else:
                return {"error": str(e), "payloads": []}

    # Extract code blocks as payloads
    payloads = []
    # Code blocks
    code_blocks = re.findall(r'```[^\n]*\n(.*?)```', content, re.DOTALL)
    for block in code_blocks:
        for line in block.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("//"):
                payloads.append(line)

    # Also extract inline code
    inline = re.findall(r'`([^`]{5,})`', content)
    payloads.extend(inline)

    # Deduplicate
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen and len(p) >= 3:
            seen.add(p)
            unique.append(p)

    return {
        "category": category,
        "source":   "PayloadsAllTheThings (GitHub)",
        "count":    len(unique),
        "payloads": unique[:500],  # cap at 500
        "raw_url":  url,
    }


# ══════════════════════════════════════════════════════════════
#  SECWORDLIST / WORDLIST FETCHER
# ══════════════════════════════════════════════════════════════

SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

WORDLIST_SOURCES = {
    "directories_small":     f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
    "directories_medium":    f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "directories_large":     f"{SECLISTS_BASE}/Discovery/Web-Content/raft-large-directories.txt",
    "directories_small_raft":f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-directories.txt",
    "files_common":          f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-files.txt",
    "files_sensitive":       f"{SECLISTS_BASE}/Discovery/Web-Content/sensitive-data-detection.txt",
    "subdomains_5k":         f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt",
    "subdomains_20k":        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-20000.txt",
    "params_burp":           f"{SECLISTS_BASE}/Discovery/Web-Content/burp-parameter-names.txt",
    "api_endpoints":         f"{SECLISTS_BASE}/Discovery/Web-Content/api/api-endpoints.txt",
    "api_objects":           f"{SECLISTS_BASE}/Discovery/Web-Content/api/objects.txt",
    "backup_files":          f"{SECLISTS_BASE}/Discovery/Web-Content/backup-filenames.txt",
    "passwords_10k":         f"{SECLISTS_BASE}/Passwords/Common-Credentials/10k-most-common.txt",
    "passwords_top1000":     f"{SECLISTS_BASE}/Passwords/Common-Credentials/best1050.txt",
    "usernames":             f"{SECLISTS_BASE}/Usernames/top-usernames-shortlist.txt",
    "default_creds":         f"{SECLISTS_BASE}/Passwords/Default-Credentials/default-passwords.txt",
    "xss_polyglots":         f"{SECLISTS_BASE}/Fuzzing/XSS/XSS-Jhaddix.txt",
    "sqli_intruder":         f"{SECLISTS_BASE}/Fuzzing/SQLi/quick-SQLi.txt",
    "lfi_payloads":          f"{SECLISTS_BASE}/Fuzzing/LFI/LFI-Jhaddix.txt",
    "jwt_secrets":           f"{SECLISTS_BASE}/Passwords/Leaked-Databases/rockyou-50.txt",
    "fuzzing_special_chars": f"{SECLISTS_BASE}/Fuzzing/special-chars.txt",
    "dotfiles":              f"{SECLISTS_BASE}/Discovery/Web-Content/quickhits.txt",
}

def fetch_wordlist(name: str, lines_limit: int = 0) -> dict:
    """Fetch a wordlist from SecLists GitHub."""
    url = WORDLIST_SOURCES.get(name)
    if not url:
        return {"error": f"Wordlist '{name}' not found", "words": []}

    # Check local SecLists first
    local_paths = {
        "directories_small":  "/usr/share/wordlists/dirb/common.txt",
        "directories_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "subdomains_5k":      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "params_burp":        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "passwords_10k":      "/usr/share/wordlists/rockyou.txt",
    }
    if name in local_paths and Path(local_paths[name]).exists():
        words = Path(local_paths[name]).read_text(errors="replace").splitlines()
        words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
        if lines_limit:
            words = words[:lines_limit]
        return {"name": name, "source": "local", "count": len(words), "words": words}

    # Download from GitHub
    cache_file = CACHE_DIR / f"wl_{name}.txt"
    import time
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
        content = cache_file.read_text(errors="replace")
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                content = r.read().decode("utf-8", errors="replace")
            cache_file.write_text(content, encoding="utf-8")
        except Exception as e:
            return {"error": str(e), "words": [], "fallback_url": url}

    words = [w.strip() for w in content.splitlines() if w.strip() and not w.startswith("#")]
    if lines_limit:
        words = words[:lines_limit]

    return {
        "name":   name,
        "source": "SecLists (GitHub)",
        "count":  len(words),
        "words":  words,
        "url":    url,
    }


def download_wordlist_to_file(name: str, save_path: str = None) -> str:
    """Download a wordlist and save to disk."""
    result = fetch_wordlist(name)
    if "error" in result:
        return ""
    if not save_path:
        save_path = str(CACHE_DIR / f"{name}.txt")
    Path(save_path).write_text("\n".join(result["words"]))
    return save_path


def get_all_wordlist_names() -> list:
    """Return all available wordlist names."""
    return list(WORDLIST_SOURCES.keys())


# ══════════════════════════════════════════════════════════════
#  EXPLOIT-DB PAYLOAD EXTRACTOR
# ══════════════════════════════════════════════════════════════

def get_exploit_payloads(cve_or_keyword: str, extract_code: bool = True) -> dict:
    """Search Exploit-DB and optionally extract exploit code."""
    from modules.analysis.cve_fetcher import search_exploitdb, get_exploit_by_id

    result = search_exploitdb(cve_or_keyword, limit=10)
    exploits = result.get("exploits", [])

    if extract_code and exploits:
        for exploit in exploits[:3]:  # only extract top 3
            detail = get_exploit_by_id(exploit["id"])
            exploit["code"] = detail.get("code","")

    return result


# ══════════════════════════════════════════════════════════════
#  COMBINED PAYLOAD SEARCH
# ══════════════════════════════════════════════════════════════

PATT_CATEGORIES = list(PATT_SOURCES.keys())
WORDLIST_NAMES  = list(WORDLIST_SOURCES.keys())
