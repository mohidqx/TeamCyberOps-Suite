"""
TeamCyberOps V5 — Web Path Fuzzing Module
Refactored from fuzz_server.py with user-controlled targets and atomic file writes
"""
import requests
from concurrent.futures import ThreadPoolExecutor
import urllib3
from pathlib import Path
from typing import Callable, Optional
import tempfile
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-impact sensitive paths
DEFAULT_PATHS = [
    # Environmental & Credentials
    "/.env", "/.env.bak", "/.env.old", "/.env.php", "/.env.local", "/.env.dev",
    "/.aws/credentials", "/.docker/config.json", "/.ssh/id_rsa", "/.ssh/known_hosts",
    "/config.php", "/config.php.bak", "/wp-config.php", "/web.config",
    
    # Backups & Databases
    "/backup.sql", "/db.sql", "/dump.sql", "/backup.tar.gz", "/backup.zip",
    
    # Version Control
    "/.git/config", "/.git/HEAD", "/.gitignore", "/.svn/entries",
    
    # Admin Panels
    "/phpmyadmin/", "/phpMyAdmin/", "/roundcube/", "/webmail/",
    "/cgi-bin/", "/.well-known/security.txt",
    
    # Development
    "/info.php", "/phpinfo.php", "/test.php", "/status", "/robots.txt",
    "/package.json", "/composer.json", "/Dockerfile",
]


def fuzz_paths(
    target_url: str,
    paths: list[str] = None,
    output_file: str = "fuzz_results.txt",
    max_workers: int = 20,
    timeout: int = 4,
    callback: Optional[Callable] = None,
) -> list[dict]:
    """
    Fuzz web server paths to discover sensitive files/endpoints.
    
    Args:
        target_url: Base URL (e.g., http://target.com)
        paths: List of paths to test (default: DEFAULT_PATHS)
        output_file: File to save results
        max_workers: Thread pool size
        timeout: Request timeout per path
        callback: Optional callback(message) for status
    
    Returns:
        List of found paths with status codes
    """
    if not target_url.startswith(("http://", "https://")):
        if callback:
            callback("[ERR] Invalid URL — must start with http:// or https://")
        return []
    
    paths = paths or DEFAULT_PATHS
    
    # Normalize URL (no trailing slash for path concatenation)
    target_url = target_url.rstrip("/")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    found = []
    
    if callback:
        callback(f"[*] Starting path fuzzing on {target_url}")
        callback(f"[*] Testing {len(paths)} paths with {max_workers} workers...")
    
    def scan_path(path):
        url = f"{target_url}{path}"
        try:
            r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            
            if r.status_code == 200:
                result = f"[+] FOUND (200 OK): {url} | Size: {len(r.content)}"
                if callback:
                    callback(result)
                found.append({"url": url, "status": 200, "size": len(r.content)})
                return result
            
            elif r.status_code == 403:
                result = f"[*] FORBIDDEN (403): {url}"
                if callback:
                    callback(result)
                found.append({"url": url, "status": 403})
                return result
            
            elif r.status_code in (301, 302):
                loc = r.headers.get("Location", "Unknown")
                result = f"[!] REDIRECT ({r.status_code}): {url} -> {loc}"
                if callback:
                    callback(result)
                return result
                
        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass
        return None
    
    # Execute with thread pool
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(scan_path, paths)
    except Exception as e:
        if callback:
            callback(f"[!] Thread pool error: {e}")
    
    # Atomic write to output file (atomic rename)
    if found:
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
                for item in found:
                    tmp.write(f"{item['url']} | Status: {item['status']}\n")
                tmp_path = tmp.name
            
            os.fsync(open(tmp_path).fileno())
            os.replace(tmp_path, output_file)
            
            if callback:
                callback(f"\n[+] Results saved to {output_file}")
        except Exception as e:
            if callback:
                callback(f"[!] Error saving results: {e}")
    
    if callback:
        callback(f"[*] Fuzzing complete. Found {len(found)} results.")
    
    return found
