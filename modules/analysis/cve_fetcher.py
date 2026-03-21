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


# ══════════════════════════════════════════════════════════════════════════════
#  COMPATIBILITY ALIASES — matches main.py import names
# ══════════════════════════════════════════════════════════════════════════════

def search_nvd(keyword="", cve_id="", severity=None, limit=20, log_cb=None):
    """Alias: search_nvd → nvd_search or nvd_lookup_cve."""
    if cve_id:
        r = nvd_lookup_cve(cve_id, log_cb=log_cb)
        return [r] if r else []
    return nvd_search(keyword, limit=limit, severity=severity, log_cb=log_cb)

def fetch_cisa_kev(force_refresh=False, log_cb=None):
    """Alias: fetch_cisa_kev → get_cisa_kev."""
    return get_cisa_kev(log_cb=log_cb)

def is_in_kev(cve_id, log_cb=None):
    """Alias: is_in_kev → is_exploited."""
    return is_exploited(cve_id, log_cb=log_cb)

def get_cves_for_tech(tech_list, severity="HIGH", log_cb=None):
    """Alias: get_cves_for_tech → tech_to_cves."""
    return tech_to_cves(tech_list, severity_filter=severity, log_cb=log_cb)

def get_recent_cves(days=7, severity="CRITICAL", per_page=20, log_cb=None):
    """Get recent CVEs published in the last N days."""
    log = log_cb or (lambda m, t='': None)
    from datetime import datetime, timedelta
    end   = datetime.utcnow()
    start = end - timedelta(days=days)
    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    cfg = _cfg()
    nvd_key = cfg.get("api_keys", {}).get("nvd_api_key", "")
    params = {
        "pubStartDate":    pub_start,
        "pubEndDate":      pub_end,
        "resultsPerPage":  min(per_page, 2000),
    }
    if severity:
        params["cvssV3Severity"] = severity.upper()
    if nvd_key:
        params["apiKey"] = nvd_key
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    log(f"[NVD] Fetching recent CVEs (last {days} days, {severity})…", "info")
    try:
        out = _req(url, timeout=25)
        if out.startswith("ERROR"):
            log(f"[NVD] Request failed: {out}", "err"); return []
        data  = json.loads(out)
        vulns = data.get("vulnerabilities", [])
        results = []
        for v in vulns:
            cve  = v.get("cve", {})
            cid  = cve.get("id", "")
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            score = "N/A"; sev = severity
            for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                ml = cve.get("metrics", {}).get(ver, [])
                if ml:
                    score = str(ml[0].get("cvssData", {}).get("baseScore", "N/A"))
                    sev   = ml[0].get("cvssData", {}).get("baseSeverity", severity)
                    break
            results.append({"cve_id": cid, "description": desc[:300],
                             "cvss": score, "severity": sev,
                             "published": cve.get("published", "")[:10]})
        log(f"[NVD] {len(results)} recent CVEs found", "ok")
        return results
    except Exception as e:
        log(f"[NVD] Error: {e}", "err"); return []

def search_exploitdb(query="", cve_id="", limit=20, log_cb=None):
    """Search ExploitDB via search.sploitus.com (public API)."""
    log = log_cb or (lambda m, t='': None)
    q = cve_id if cve_id else query
    if not q:
        return []
    log(f"[ExploitDB] Searching sploitus for: {q}", "info")
    try:
        payload = json.dumps({"query": q, "type": "exploits",
                               "offset": 0, "limit": min(limit, 25)}).encode()
        req = urllib.request.Request(
            "https://sploitus.com/search",
            data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "TeamCyberOps/4"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        items = data.get("exploits", [])
        results = []
        for it in items:
            results.append({
                "id":          it.get("id", ""),
                "title":       it.get("title", ""),
                "type":        it.get("type", "exploit"),
                "published":   it.get("published", "")[:10],
                "url":         it.get("href", ""),
                "source":      it.get("source", ""),
                "description": it.get("description", "")[:200],
            })
        log(f"[ExploitDB] {len(results)} results", "ok" if results else "dim")
        return results
    except Exception as e:
        log(f"[ExploitDB] sploitus error: {e} — trying nvd fallback", "warn")
        return search_nvd(keyword=q, limit=limit, log_cb=log_cb)

def full_vuln_intel(query, log_cb=None):
    """Combined intelligence: NVD + CISA KEV + ExploitDB."""
    log = log_cb or (lambda m, t='': None)
    log(f"[Intel] Full vuln intelligence for: {query}", "info")
    nvd_results  = search_nvd(keyword=query, limit=10, log_cb=log_cb)
    kev_data     = fetch_cisa_kev(log_cb=log_cb)
    edb_results  = search_exploitdb(query=query, limit=10, log_cb=log_cb)
    # Mark KEV entries
    kev_ids = {v.get("cveID", "") for v in kev_data} if isinstance(kev_data, list) else set()
    for r in nvd_results:
        r["in_kev"] = r.get("cve_id", "") in kev_ids
    return {
        "nvd":          nvd_results,
        "kev_total":    len(kev_ids),
        "exploitdb":    edb_results,
        "query":        query,
    }

def get_exploit_by_id(edb_id, log_cb=None):
    """Fetch a single exploit by its ID from sploitus."""
    log = log_cb or (lambda m, t='': None)
    log(f"[ExploitDB] Fetching exploit: {edb_id}", "info")
    try:
        url = f"https://sploitus.com/exploit?id={urllib.parse.quote(str(edb_id))}"
        out = _req(url, timeout=15)
        if out.startswith("ERROR"):
            return {"error": out}
        # Try to parse JSON response
        try:
            data = json.loads(out)
            return data
        except Exception:
            return {"id": edb_id, "raw": out[:500]}
    except Exception as e:
        log(f"[ExploitDB] Error: {e}", "err")
        return {"error": str(e)}
