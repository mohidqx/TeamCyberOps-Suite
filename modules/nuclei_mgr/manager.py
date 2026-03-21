"""
TeamCyberOps Suite v4 — Nuclei Template Manager
Browse, create, import, run custom Nuclei YAML templates
"""
import json, os, re, shutil, subprocess
from pathlib import Path
from datetime import datetime
import urllib.request, urllib.parse

BASE_DIR   = Path(__file__).parent.parent.parent
# Project-local nuclei templates: TeamCyberOps/nuclei-templates/
TMPL_DIR   = BASE_DIR / "nuclei-templates"
CUSTOM_DIR = TMPL_DIR / "custom"
TMPL_DIR.mkdir(exist_ok=True)
CUSTOM_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  TEMPLATE CATEGORIES
# ══════════════════════════════════════════════════════════════

TEMPLATE_CATEGORIES = {
    "🔓 Authentication": ["default-credentials", "oauth", "jwt", "authentication"],
    "🌐 Exposures":      ["configs", "logs", "files", "paths"],
    "💉 Injections":     ["sqli", "xss", "ssti", "xxe", "rce"],
    "🔧 Misconfigs":     ["misconfiguration", "cors", "open-redirect", "ssrf"],
    "🐛 CVEs":           ["cve-2024", "cve-2023", "cve-2022", "cve-2021"],
    "🖥️ Tech-Specific":  ["wordpress", "spring", "jenkins", "grafana", "laravel"],
    "📡 Network":        ["network", "ssl", "dns", "http"],
    "☁️ Cloud":          ["aws", "azure", "gcp", "kubernetes"],
    "🔍 Discovery":      ["technologies", "fingerprints", "panels"],
    "⚡ Custom":         ["custom"],
}

# ══════════════════════════════════════════════════════════════
#  YAML TEMPLATE BUILDER
# ══════════════════════════════════════════════════════════════

def create_template(
    template_id:  str,
    name:         str,
    description:  str,
    severity:     str,
    target_url:   str,
    method:       str = "GET",
    path:         str = "/",
    headers:      dict = None,
    body:         str = "",
    matchers:     list = None,
    extractors:   list = None,
    tags:         list = None,
    author:       str  = "TeamCyberOps",
    reference:    list = None,
) -> str:
    """Generate a Nuclei YAML template."""

    headers_yaml = ""
    if headers:
        headers_yaml = "\n".join(f"          {k}: \"{v}\"" for k, v in headers.items())
        headers_yaml = "        headers:\n" + headers_yaml + "\n"

    body_yaml = ""
    if body:
        body_yaml = f"        body: |\n          {body}\n"

    # Default matchers
    if not matchers:
        matchers = [{"type": "status", "status": [200]}]

    matchers_yaml_lines = []
    for i, m in enumerate(matchers):
        mtype = m.get("type", "status")
        matchers_yaml_lines.append(f"      - type: {mtype}")
        if mtype == "status":
            statuses = m.get("status", [200])
            matchers_yaml_lines.append(f"        status:")
            for s in statuses:
                matchers_yaml_lines.append(f"          - {s}")
        elif mtype in ("word", "words"):
            words = m.get("words", [])
            matchers_yaml_lines.append(f"        words:")
            for w in words:
                matchers_yaml_lines.append(f"          - \"{w}\"")
            part = m.get("part", "body")
            matchers_yaml_lines.append(f"        part: {part}")
        elif mtype == "regex":
            regexes = m.get("regex", [])
            matchers_yaml_lines.append(f"        regex:")
            for r in regexes:
                matchers_yaml_lines.append(f"          - \"{r}\"")
            part = m.get("part", "body")
            matchers_yaml_lines.append(f"        part: {part}")
        elif mtype == "dsl":
            dsl_list = m.get("dsl", [])
            matchers_yaml_lines.append(f"        dsl:")
            for d in dsl_list:
                matchers_yaml_lines.append(f"          - \"{d}\"")

        condition = m.get("condition", "")
        if condition:
            matchers_yaml_lines.append(f"        condition: {condition}")

        negative = m.get("negative", False)
        if negative:
            matchers_yaml_lines.append(f"        negative: true")

    matchers_yaml = "\n".join(matchers_yaml_lines)

    # Extractors
    extractors_yaml = ""
    if extractors:
        ex_lines = ["      extractors:"]
        for e in extractors:
            ex_lines.append(f"        - type: {e.get('type','regex')}")
            if e.get('regex'):
                ex_lines.append(f"          regex:")
                for r in e['regex']:
                    ex_lines.append(f"            - \"{r}\"")
            if e.get('group'):
                ex_lines.append(f"          group: {e['group']}")
            if e.get('name'):
                ex_lines.append(f"          name: {e['name']}")
            if e.get('part'):
                ex_lines.append(f"          part: {e['part']}")
        extractors_yaml = "\n".join(ex_lines) + "\n"

    tags_str = ", ".join(tags or ["custom"])
    refs = "".join(f"\n    - {r}" for r in (reference or []))

    template = f"""id: {template_id}

info:
  name: {name}
  author: {author}
  severity: {severity.lower()}
  description: |
    {description}
  tags: {tags_str}{refs and chr(10)+'  reference:'+refs or ''}

requests:
  - method: {method.upper()}
    path:
      - "{{{{BaseURL}}}}{path}"
{headers_yaml}{body_yaml}
    matchers-condition: and
    matchers:
{matchers_yaml}
{extractors_yaml}"""

    return template


# ══════════════════════════════════════════════════════════════
#  TEMPLATE FILE MANAGEMENT
# ══════════════════════════════════════════════════════════════

def save_template(template_yaml: str, filename: str) -> str:
    """Save a template to the custom templates directory."""
    if not filename.endswith('.yaml'):
        filename += '.yaml'
    path = CUSTOM_DIR / filename
    with open(path, 'w') as f:
        f.write(template_yaml)
    return str(path)


def list_templates(search: str = "", category: str = "all") -> list:
    """List all available Nuclei templates."""
    results = []

    # Custom templates first
    for f in sorted(CUSTOM_DIR.glob("*.yaml")):
        meta = _parse_template_meta(f)
        if search and search.lower() not in f.name.lower() \
                  and search.lower() not in meta.get('name','').lower():
            continue
        meta['path']     = str(f)
        meta['source']   = 'custom'
        meta['filename'] = f.name
        results.append(meta)

    # System nuclei templates — search order (first found wins)
    nuclei_dirs = [
        BASE_DIR / "nuclei-templates",                             # project folder (priority)
        Path.home() / "nuclei-templates",                          # ~/.local
        Path("/root/nuclei-templates"),                            # root user default
        Path("/home") / os.environ.get('USER','user') / "nuclei-templates",
    ]
    for ndir in nuclei_dirs:
        if ndir.exists():
            for f in sorted(ndir.rglob("*.yaml"))[:500]:  # limit for performance
                meta = _parse_template_meta(f)
                if search and search.lower() not in f.name.lower() \
                          and search.lower() not in meta.get('name','').lower():
                    continue
                if category != "all":
                    tags = meta.get('tags','').lower()
                    if category.lower() not in tags and category.lower() not in str(f).lower():
                        continue
                meta['path']     = str(f)
                meta['source']   = 'system'
                meta['filename'] = f.name
                results.append(meta)
            break  # use first found directory

    return results[:1000]  # cap at 1000


def _parse_template_meta(path: Path) -> dict:
    """Extract metadata from a Nuclei template YAML file."""
    try:
        content = path.read_text(errors='replace')
        meta = {
            'id':          re.search(r'^id:\s*(.+)', content, re.M) and
                           re.search(r'^id:\s*(.+)', content, re.M).group(1).strip() or path.stem,
            'name':        re.search(r'name:\s*(.+)', content) and
                           re.search(r'name:\s*(.+)', content).group(1).strip() or '',
            'severity':    re.search(r'severity:\s*(\w+)', content) and
                           re.search(r'severity:\s*(\w+)', content).group(1).strip() or 'unknown',
            'tags':        re.search(r'tags:\s*(.+)', content) and
                           re.search(r'tags:\s*(.+)', content).group(1).strip() or '',
            'description': re.search(r'description:\s*\|?\s*\n\s*(.+)', content) and
                           re.search(r'description:\s*\|?\s*\n\s*(.+)', content).group(1).strip() or '',
            'author':      re.search(r'author:\s*(.+)', content) and
                           re.search(r'author:\s*(.+)', content).group(1).strip() or '',
            'size':        path.stat().st_size,
        }
        return meta
    except Exception:
        return {'id': path.stem, 'name': path.stem, 'severity': 'unknown',
                'tags': '', 'description': '', 'author': '', 'size': 0}


def import_template_from_url(url: str) -> dict:
    """Import a Nuclei template from a URL (GitHub raw, etc.)."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'TeamCyberOps/1.0'})
        with urllib.request.urlopen(req, timeout=15) as r:
            content = r.read().decode('utf-8', errors='replace')

        # Validate it looks like a Nuclei template
        if 'id:' not in content or 'requests:' not in content and 'network:' not in content:
            return {"error": "Does not look like a valid Nuclei template"}

        meta     = _parse_template_meta_from_str(content)
        filename = meta.get('id', 'imported') + '.yaml'
        path     = save_template(content, filename)
        return {"success": True, "path": path, "meta": meta}
    except Exception as e:
        return {"error": str(e)}


def _parse_template_meta_from_str(content: str) -> dict:
    return {
        'id': re.search(r'^id:\s*(.+)', content, re.M) and
              re.search(r'^id:\s*(.+)', content, re.M).group(1).strip() or 'unknown',
        'name': re.search(r'name:\s*(.+)', content) and
                re.search(r'name:\s*(.+)', content).group(1).strip() or '',
        'severity': re.search(r'severity:\s*(\w+)', content) and
                    re.search(r'severity:\s*(\w+)', content).group(1).strip() or 'unknown',
        'tags': re.search(r'tags:\s*(.+)', content) and
                re.search(r'tags:\s*(.+)', content).group(1).strip() or '',
    }


def build_nuclei_run_cmd(target: str, templates: list = None,
                          custom_dir: bool = False,
                          severity: str = "medium,high,critical",
                          output: str = None, rate: int = 100) -> list:
    """Build nuclei command for running templates."""
    cmd = ["nuclei", "-u", target, "-severity", severity,
           "-rate-limit", str(rate), "-silent", "-no-color"]
    if custom_dir and CUSTOM_DIR.exists():
        cmd += ["-t", str(CUSTOM_DIR)]
    elif templates:
        for t in templates:
            cmd += ["-t", t]
    if output:
        cmd += ["-o", output]
    return cmd


# ══════════════════════════════════════════════════════════════
#  TEMPLATE PRESETS (Quick-Start)
# ══════════════════════════════════════════════════════════════

PRESET_TEMPLATES = {
    "🔓 Admin Panel Finder": {
        "id": "admin-panel-finder",
        "name": "Admin Panel Finder",
        "severity": "medium",
        "description": "Find common admin panel paths",
        "method": "GET",
        "paths": ["/admin", "/admin/login", "/administrator", "/admin.php",
                  "/wp-admin", "/cpanel", "/phpmyadmin", "/dashboard",
                  "/control-panel", "/manage", "/panel"],
        "matchers": [{"type": "status", "status": [200, 301, 302]},
                     {"type": "word", "words": ["admin","login","dashboard","control"],
                      "part": "body", "condition": "or"}],
        "tags": ["admin","panel","detection"],
    },
    "📋 Exposed Files": {
        "id": "exposed-sensitive-files",
        "name": "Exposed Sensitive Files",
        "severity": "high",
        "description": "Check for exposed config and sensitive files",
        "method": "GET",
        "paths": ["/.env", "/config.php", "/wp-config.php", "/.git/HEAD",
                  "/backup.sql", "/database.sql", "/.htpasswd",
                  "/web.config", "/appsettings.json"],
        "matchers": [{"type": "status", "status": [200]}],
        "tags": ["exposure","files","config"],
    },
    "🔑 Default Credentials": {
        "id": "default-creds-check",
        "name": "Default Credentials Test",
        "severity": "critical",
        "description": "Test common default admin credentials",
        "method": "POST",
        "path": "/admin/login",
        "body": "username=admin&password=admin",
        "matchers": [{"type": "word", "words": ["dashboard","logout","welcome"],
                      "part": "body"}],
        "tags": ["default-creds","auth","login"],
    },
    "💾 SQL Error Detection": {
        "id": "sql-error-detection",
        "name": "SQL Error Detection",
        "severity": "high",
        "description": "Detect SQL errors in responses",
        "method": "GET",
        "path": "/?id=1'",
        "matchers": [{"type": "word", "words": ["sql syntax","mysql_fetch","ORA-",
                                                 "SQLSTATE","pg_query","sqlite3"],
                      "part": "body", "condition": "or"}],
        "tags": ["sqli","error","detection"],
    },
    "🌐 CORS Misconfiguration": {
        "id": "cors-wildcard",
        "name": "CORS Wildcard Detection",
        "severity": "medium",
        "description": "Detect CORS misconfiguration allowing any origin",
        "method": "GET",
        "path": "/",
        "headers": {"Origin": "https://evil.com"},
        "matchers": [{"type": "dsl",
                      "dsl": ["contains(all_headers, 'access-control-allow-origin: *') || "
                               "contains(all_headers, 'access-control-allow-origin: https://evil.com')"]}],
        "tags": ["cors","misconfiguration"],
    },
    "📡 Open Redirect": {
        "id": "open-redirect-detection",
        "name": "Open Redirect Detection",
        "severity": "medium",
        "description": "Find open redirect vulnerabilities",
        "method": "GET",
        "path": "/?next=https://evil.com&url=https://evil.com&redirect=https://evil.com",
        "matchers": [{"type": "regex", "regex": ["Location:.*evil\\.com"],
                      "part": "header"}],
        "tags": ["redirect","open-redirect"],
    },
}

def get_preset_yaml(preset_name: str) -> str:
    """Get YAML for a preset template."""
    preset = PRESET_TEMPLATES.get(preset_name, {})
    if not preset:
        return ""
    return create_template(
        template_id  = preset.get("id","custom"),
        name         = preset.get("name","Custom"),
        description  = preset.get("description",""),
        severity     = preset.get("severity","medium"),
        target_url   = "{{BaseURL}}",
        method       = preset.get("method","GET"),
        path         = preset.get("path","/"),
        headers      = preset.get("headers",{}),
        body         = preset.get("body",""),
        matchers     = preset.get("matchers",[]),
        tags         = preset.get("tags",["custom"]),
    )
