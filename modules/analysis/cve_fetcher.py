"""
TeamCyberOps Suite v4 — CVE Intelligence (Production Grade)
NVD API v2 · CISA KEV · ExploitDB · GitHub Advisory · Vulners
"""
import json, urllib.request, urllib.parse, re, time
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).parent.parent.parent

def _cfg():
    try:
        with open(BASE_DIR/"config.json") as f: return json.load(f)
    except Exception: return {}

def _req(url, headers=None, timeout=15):
    h = {"User-Agent":"TeamCyberOps/4",**(headers or {})}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8","replace")
    except Exception as e:
        return f"ERROR:{e}"

# ── NVD API v2 ───────────────────────────────────────────────────
def nvd_search(query, limit=20, severity=None, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[NVD] Searching: {query}", "info")
    cfg = _cfg()
    nvd_key = cfg.get("api_keys",{}).get("nvd_api_key","")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": min(limit,2000)}
    if severity: params["cvssV3Severity"] = severity.upper()
    if nvd_key: params["apiKey"] = nvd_key
    url = base_url + "?" + urllib.parse.urlencode(params)
    try:
        out = _req(url, timeout=20)
        if out.startswith("ERROR"): return []
        data = json.loads(out)
        results = []
        for vuln in data.get("vulnerabilities",[]):
            cve = vuln.get("cve",{})
            cve_id = cve.get("id","")
            desc = ""
            for d in cve.get("descriptions",[]):
                if d.get("lang") == "en": desc = d.get("value",""); break
            # CVSS score
            cvss = "N/A"; severity_val = "UNKNOWN"
            metrics = cve.get("metrics",{})
            for version in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                m_list = metrics.get(version,[])
                if m_list:
                    cvss = str(m_list[0].get("cvssData",{}).get("baseScore","N/A"))
                    severity_val = m_list[0].get("cvssData",{}).get("baseSeverity","") or m_list[0].get("baseSeverity","")
                    break
            # References
            refs = [r.get("url","") for r in cve.get("references",[])[:3]]
            results.append({
                "cve_id":      cve_id,
                "description": desc[:300],
                "cvss":        cvss,
                "severity":    severity_val,
                "published":   cve.get("published","")[:10],
                "modified":    cve.get("lastModified","")[:10],
                "references":  refs,
            })
            log(f"  [{severity_val}] {cve_id} (CVSS {cvss}): {desc[:60]}", "ok" if severity_val in ("CRITICAL","HIGH") else "dim")
        log(f"[NVD] {len(results)} CVEs found", "ok" if results else "dim")
        return results
    except Exception as e:
        log(f"[NVD] Error: {e}", "err"); return []

def nvd_lookup_cve(cve_id, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[NVD] Looking up {cve_id}", "info")
    out = _req(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=15)
    if out.startswith("ERROR"): return {}
    try:
        data = json.loads(out)
        vulns = data.get("vulnerabilities",[])
        if not vulns: return {}
        cve = vulns[0].get("cve",{})
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
        # CVSS
        metrics = cve.get("metrics",{}); cvss = "N/A"; sev = "UNKNOWN"; vector = ""
        for ver in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            ml = metrics.get(ver,[])
            if ml:
                cvss = str(ml[0].get("cvssData",{}).get("baseScore","N/A"))
                sev  = ml[0].get("cvssData",{}).get("baseSeverity","") or ml[0].get("baseSeverity","")
                vector = ml[0].get("cvssData",{}).get("vectorString","")
                break
        # CWE
        cwes = [w.get("description",[{}])[0].get("value","") for w in cve.get("weaknesses",[])]
        # CPE (affected products)
        cpes = []
        for config in cve.get("configurations",[]):
            for node in config.get("nodes",[]):
                for match in node.get("cpeMatch",[]):
                    if match.get("vulnerable"): cpes.append(match.get("criteria",""))
        return {
            "cve_id":      cve_id,
            "description": desc,
            "cvss":        cvss,
            "severity":    sev,
            "vector":      vector,
            "cwes":        cwes,
            "cpes":        cpes[:10],
            "published":   cve.get("published","")[:10],
            "references":  [r.get("url","") for r in cve.get("references",[])],
            "nvd_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    except Exception as e:
        log(f"[NVD] Parse error: {e}", "err"); return {}

# ── CISA KEV (Known Exploited Vulnerabilities) ───────────────────
_kev_cache = None
_kev_loaded = None

def get_cisa_kev(log_cb=None):
    global _kev_cache, _kev_loaded
    log = log_cb or (lambda m,t='': None)
    # Cache for 1 hour
    if _kev_cache and _kev_loaded and (datetime.now()-_kev_loaded).seconds < 3600:
        return _kev_cache
    log("[CISA KEV] Fetching Known Exploited Vulnerabilities catalog", "info")
    out = _req("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20)
    if out.startswith("ERROR"):
        log(f"[CISA KEV] Error: {out}", "err"); return []
    try:
        data = json.loads(out)
        vulns = data.get("vulnerabilities",[])
        _kev_cache = vulns; _kev_loaded = datetime.now()
        log(f"[CISA KEV] {len(vulns)} actively exploited CVEs", "ok")
        return vulns
    except Exception as e:
        log(f"[CISA KEV] Parse error: {e}", "err"); return []

def search_kev(query, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    vulns = get_cisa_kev(log)
    q = query.lower()
    results = [v for v in vulns if q in v.get("vendorProject","").lower()
               or q in v.get("product","").lower()
               or q in v.get("vulnerabilityName","").lower()
               or q in v.get("cveID","").lower()]
    log(f"[CISA KEV] {len(results)} matches for '{query}'", "ok" if results else "dim")
    return results

def is_exploited(cve_id, log_cb=None):
    vulns = get_cisa_kev(log_cb)
    return any(v.get("cveID","") == cve_id for v in vulns)

# ── TECH-TO-CVE MAPPER ───────────────────────────────────────────
TECH_CVE_MAP = {
    "WordPress":    ["wordpress","wp-includes","wp-content"],
    "Apache":       ["apache httpd","apache2"],
    "Nginx":        ["nginx"],
    "PHP":          ["php"],
    "Laravel":      ["laravel","php laravel"],
    "Django":       ["django"],
    "Spring":       ["spring","springframework"],
    "Struts":       ["apache struts"],
    "Log4j":        ["log4j","log4shell"],
    "OpenSSL":      ["openssl"],
    "IIS":          ["microsoft iis","internet information services"],
    "Tomcat":       ["apache tomcat"],
    "Jenkins":      ["jenkins"],
    "GitLab":       ["gitlab"],
    "Drupal":       ["drupal"],
    "Joomla":       ["joomla"],
    "Elasticsearch":["elasticsearch"],
    "Redis":        ["redis"],
    "MongoDB":      ["mongodb"],
    "MySQL":        ["mysql"],
    "PostgreSQL":   ["postgresql","postgres"],
    "React":        ["react","reactjs"],
    "Node.js":      ["node.js","nodejs","npm"],
    "jQuery":       ["jquery"],
    "Kubernetes":   ["kubernetes","k8s"],
    "Docker":       ["docker"],
    "VMware":       ["vmware"],
    "Cisco":        ["cisco"],
    "F5":           ["f5 bigip","f5 networks"],
    "Fortinet":     ["fortinet","fortigate","fortios"],
    "Palo Alto":    ["palo alto","pan-os"],
    "Exchange":     ["microsoft exchange"],
    "SharePoint":   ["microsoft sharepoint"],
}

def tech_to_cves(tech_list, severity_filter="HIGH", log_cb=None):
    log = log_cb or (lambda m,t='': None)
    all_cves = {}
    for tech in tech_list:
        query = None
        for tech_name, keywords in TECH_CVE_MAP.items():
            if any(k in tech.lower() for k in keywords):
                query = tech_name; break
        if not query: query = tech
        log(f"[CVE] Searching for {query} CVEs", "info")
        cves = nvd_search(query, limit=10, severity=severity_filter, log_cb=log)
        if cves:
            # Check against CISA KEV
            for cve in cves:
                cve["actively_exploited"] = is_exploited(cve["cve_id"])
                if cve["actively_exploited"]:
                    log(f"  [!] {cve['cve_id']} is ACTIVELY EXPLOITED (CISA KEV)", "ok")
            all_cves[query] = cves
        time.sleep(0.5)  # NVD rate limit
    return all_cves

# ── GitHub Security Advisories ───────────────────────────────────
def github_advisories(ecosystem, package, log_cb=None):
    log = log_cb or (lambda m,t='': None)
    log(f"[GitHub] Advisories for {package} ({ecosystem})", "info")
    query = """
    {
      securityVulnerabilities(first: 10, ecosystem: %s, package: "%s") {
        nodes {
          severity
          vulnerableVersionRange
          advisory { summary publishedAt ghsaId permalink }
          firstPatchedVersion { identifier }
        }
      }
    }
    """ % (ecosystem.upper(), package)
    gh_token = _cfg().get("api_keys",{}).get("github_token","")
    headers = {"Content-Type":"application/json"}
    if gh_token: headers["Authorization"] = f"bearer {gh_token}"
    try:
        req = urllib.request.Request(
            "https://api.github.com/graphql",
            data=json.dumps({"query":query}).encode(),
            headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        vulns = data.get("data",{}).get("securityVulnerabilities",{}).get("nodes",[])
        log(f"[GitHub] {len(vulns)} advisories", "ok" if vulns else "dim")
        return vulns
    except Exception as e:
        log(f"[GitHub] Error: {e}", "err"); return []
