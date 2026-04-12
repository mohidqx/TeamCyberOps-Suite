"""
TeamCyberOps Suite v4 — Wordlist Manager
Scans ALL Kali Linux / SecLists paths + built-in + custom
"""
import os, json, glob
from pathlib import Path

WL_DIR   = Path(__file__).parent.parent / "wordlists"
CFG_PATH = Path(__file__).parent.parent / "config.json"
WL_DIR.mkdir(exist_ok=True)

# ── All Kali / SecLists scan roots ───────────────────────────────────────────
SCAN_ROOTS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/fuzzdb",
    "/usr/share/wfuzz/wordlist",
    "/opt/SecLists",
    "/opt/wordlists",
    os.path.expanduser("~/wordlists"),
    os.path.expanduser("~/SecLists"),
]

# ── Pinned high-value wordlists (always shown, even if missing) ───────────────
PINNED_SYSTEM = {
    "rockyou":               "/usr/share/wordlists/rockyou.txt",
    "rockyou.gz":            "/usr/share/wordlists/rockyou.txt.gz",
    "dirb_common":           "/usr/share/wordlists/dirb/common.txt",
    "dirb_big":              "/usr/share/wordlists/dirb/big.txt",
    "dirbuster_medium":      "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "dirbuster_small":       "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "seclists_dirs_medium":  "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "seclists_dirs_big":     "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "seclists_dirs_words":   "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
    "seclists_subs_110k":    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "seclists_subs_5k":      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "seclists_api":          "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "seclists_api_objects":  "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "seclists_burp_params":  "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "seclists_lfi":          "/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
    "seclists_xss":          "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
    "seclists_sqli":         "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
    "seclists_fuzz":         "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt",
    "seclists_passwords":    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "seclists_usernames":    "/usr/share/seclists/Usernames/Names/names.txt",
    "seclists_default_creds":"/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv",
    "wfuzz_common":          "/usr/share/wfuzz/wordlist/general/common.txt",
    "wfuzz_dirs":            "/usr/share/wfuzz/wordlist/general/big.txt",
}

# ── Built-in project wordlists ────────────────────────────────────────────────
BUILTIN = {
    "directories":     str(WL_DIR / "directories.txt"),
    "subdomains":      str(WL_DIR / "subdomains.txt"),
    "parameters":      str(WL_DIR / "parameters.txt"),
    "api_endpoints":   str(WL_DIR / "api_endpoints.txt"),
    "sensitive_files": str(WL_DIR / "sensitive_files.txt"),
    "common":          str(WL_DIR / "common.txt"),
    "xss_payloads":    str(WL_DIR / "xss_payloads.txt"),
    "sqli_payloads":   str(WL_DIR / "sqli_payloads.txt"),
    "lfi_paths":       str(WL_DIR / "lfi_paths.txt"),
}

# Category hints for auto-classification
CATEGORY_MAP = {
    "rockyou": "🔑 Passwords", "password": "🔑 Passwords", "pass": "🔑 Passwords",
    "credential": "🔑 Passwords", "default": "🔑 Passwords", "10-million": "🔑 Passwords",
    "subdomain": "🌐 Subdomains", "dns": "🌐 Subdomains", "host": "🌐 Subdomains",
    "domain": "🌐 Subdomains",
    "director": "📁 Directories", "dirbuster": "📁 Directories", "dirb": "📁 Directories",
    "raft": "📁 Directories", "big": "📁 Directories", "medium": "📁 Directories",
    "api": "🔌 API/Params", "param": "🔌 API/Params", "burp-param": "🔌 API/Params",
    "endpoint": "🔌 API/Params",
    "xss": "💉 Fuzzing/XSS", "sqli": "💉 Fuzzing/SQLi", "lfi": "💉 Fuzzing/LFI",
    "fuzz": "💉 Fuzzing", "inject": "💉 Fuzzing", "payload": "💉 Fuzzing",
    "username": "👤 Usernames", "user": "👤 Usernames", "name": "👤 Usernames",
    "sensitive": "🔒 Sensitive Files", "backup": "🔒 Sensitive Files",
}


def _guess_category(name: str, path: str) -> str:
    n = (name + path).lower()
    for key, cat in CATEGORY_MAP.items():
        if key in n:
            return cat
    return "📂 General"


def _file_size_str(path: str) -> str:
    try:
        sz = os.path.getsize(path)
        for unit in ["B","KB","MB","GB"]:
            if sz < 1024: return f"{sz:.0f} {unit}"
            sz /= 1024
        return f"{sz:.1f} GB"
    except Exception:
        return "?"


def count_lines(path: str) -> int:
    try:
        count = 0
        with open(path, 'rb') as f:
            for _ in f:
                count += 1
        return count
    except Exception:
        return 0


def list_wordlists(include_system_scan: bool = False) -> dict:
    """
    Return all wordlists.
    include_system_scan=True → deep scan all SCAN_ROOTS for *.txt files.
    """
    result = {}

    # 1. Built-in project wordlists
    for name, path in BUILTIN.items():
        exists = os.path.isfile(path)
        result[f"builtin_{name}"] = {
            "path":     path,
            "exists":   exists,
            "type":     "built-in",
            "category": "📦 Built-in",
            "lines":    count_lines(path) if exists else 0,
            "size":     _file_size_str(path) if exists else "—",
        }

    # 2. Pinned high-value system wordlists (always shown)
    for name, path in PINNED_SYSTEM.items():
        exists = os.path.isfile(path)
        result[name] = {
            "path":     path,
            "exists":   exists,
            "type":     "system",
            "category": _guess_category(name, path),
            "lines":    count_lines(path) if exists else 0,
            "size":     _file_size_str(path) if exists else "—",
        }

    # 3. Quick scan — check if wordlist directories exist and add top-level files
    for root_dir in SCAN_ROOTS:
        if not os.path.isdir(root_dir):
            continue
        # Walk one level deep by default for speed
        depth = 3 if include_system_scan else 2
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Limit depth
            current_depth = dirpath.replace(root_dir, '').count(os.sep)
            if current_depth >= depth:
                dirnames.clear()
                continue
            for fname in filenames:
                if not fname.endswith(('.txt', '.lst', '.wordlist', '.csv')):
                    continue
                fpath = os.path.join(dirpath, fname)
                # Skip if already pinned
                if any(v['path'] == fpath for v in result.values()):
                    continue
                name_key = os.path.splitext(fname)[0].lower().replace(' ', '_').replace('-', '_')
                # Make unique key
                key = f"scan_{name_key}"
                i   = 1
                while key in result:
                    key = f"scan_{name_key}_{i}"; i += 1
                result[key] = {
                    "path":     fpath,
                    "exists":   True,
                    "type":     "system",
                    "category": _guess_category(fname, fpath),
                    "lines":    count_lines(fpath) if include_system_scan else 0,
                    "size":     _file_size_str(fpath),
                }

    # 4. Custom imported wordlists
    custom_path = WL_DIR / "_custom_index.json"
    if custom_path.exists():
        try:
            with open(custom_path) as f:
                custom = json.load(f)
            for name, path in custom.items():
                exists = os.path.isfile(path)
                result[f"custom_{name}"] = {
                    "path":     path,
                    "exists":   exists,
                    "type":     "custom",
                    "category": "✏️ Custom",
                    "lines":    count_lines(path) if exists else 0,
                    "size":     _file_size_str(path) if exists else "—",
                }
        except Exception:
            pass

    return result


def save_custom_wordlist(name: str, content: str) -> str:
    """Save a custom wordlist and register it."""
    safe_name = "".join(c for c in name if c.isalnum() or c in('_','-',' ')).strip()
    fpath = WL_DIR / f"{safe_name}.txt"
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(content)
    # Update custom index
    idx_path = WL_DIR / "_custom_index.json"
    idx = {}
    if idx_path.exists():
        try:
            with open(idx_path) as f: idx = json.load(f)
        except Exception: pass
    idx[safe_name] = str(fpath)
    with open(idx_path, 'w') as f: json.dump(idx, f, indent=2)
    return str(fpath)


def merge_wordlists(paths: list, output_name: str,
                    deduplicate: bool = True) -> str:
    """Merge multiple wordlists into one."""
    lines = []
    for p in paths:
        try:
            with open(p, encoding='utf-8', errors='replace') as f:
                lines.extend(f.readlines())
        except Exception:
            pass
    if deduplicate:
        seen = set(); unique = []
        for line in lines:
            key = line.strip()
            if key and key not in seen:
                seen.add(key); unique.append(line)
        lines = unique
    return save_custom_wordlist(output_name, ''.join(lines))


def get_best_wordlist(purpose: str) -> str:
    """
    Return the best available wordlist path for a given purpose.
    purpose: 'directories' | 'subdomains' | 'passwords' | 'params' | 'api' | 'xss' | 'sqli' | 'lfi'
    """
    preference = {
        "directories": [
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            str(WL_DIR / "directories.txt"),
        ],
        "subdomains": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            str(WL_DIR / "subdomains.txt"),
        ],
        "passwords": [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        ],
        "params": [
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            str(WL_DIR / "parameters.txt"),
        ],
        "api": [
            "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            str(WL_DIR / "api_endpoints.txt"),
        ],
        "xss": [
            "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
            str(WL_DIR / "xss_payloads.txt"),
        ],
        "sqli": [
            "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
            str(WL_DIR / "sqli_payloads.txt"),
        ],
        "lfi": [
            "/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
            str(WL_DIR / "lfi_paths.txt"),
        ],
    }
    for path in preference.get(purpose, []):
        if os.path.isfile(path):
            return path
    # Fallback: return project wordlist regardless
    fallback = str(WL_DIR / f"{purpose}.txt")
    return fallback
