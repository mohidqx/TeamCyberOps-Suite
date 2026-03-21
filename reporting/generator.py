"""
TeamCyberOps Suite v3 — Report Generator
Generates HTML, Markdown, HackerOne, and Bugcrowd format reports
"""
import json
import os
from pathlib import Path
from datetime import datetime

DB_PATH      = Path(__file__).parent.parent / "db"
REPORTS_PATH = Path(__file__).parent.parent / "reports"
REPORTS_PATH.mkdir(exist_ok=True)


def _cfg():
    cfg_path = Path(__file__).parent.parent / "config.json"
    with open(cfg_path) as f:
        return json.load(f)


def get_findings(project: str) -> list:
    with open(DB_PATH / "findings.json") as f:
        data = json.load(f)
    return [f for f in data["findings"] if f.get("project") == project]


def severity_badge_html(severity: str) -> str:
    colors = {
        "CRITICAL": "#f85149", "HIGH": "#d29922",
        "MEDIUM": "#58a6ff",   "LOW": "#3fb950", "INFO": "#8b949e"
    }
    color = colors.get(severity.upper(), "#8b949e")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{severity.upper()}</span>'


def generate_html_report(project: str, findings: list = None, author: str = "") -> str:
    if findings is None:
        findings = get_findings(project)
    cfg = _cfg()["report"]
    if not author:
        author = cfg["author"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings_sorted = sorted(findings, key=lambda x: severity_order.get(x.get("severity","INFO").upper(), 99))

    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        stats[sev] = stats.get(sev, 0) + 1

    findings_html = ""
    for idx, f in enumerate(findings_sorted, 1):
        sev = f.get("severity", "INFO").upper()
        screenshot_html = ""
        if f.get("screenshot"):
            screenshot_html = f'<div style="margin:10px 0"><img src="{f["screenshot"]}" style="max-width:100%;border:1px solid #30363d;border-radius:6px" alt="PoC Screenshot"></div>'

        refs_html = ""
        if f.get("references"):
            refs = f["references"] if isinstance(f["references"], list) else [f["references"]]
            refs_html = "<br><strong>References:</strong><br>" + "<br>".join(
                f'<a href="{r}" style="color:#58a6ff">{r}</a>' for r in refs)

        poc_steps = f.get("poc", "N/A").replace("\n", "<br>")
        findings_html += f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin:15px 0">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
            <span style="color:#8b949e;font-size:14px">#{idx:03d}</span>
            {severity_badge_html(sev)}
            <span style="font-size:18px;font-weight:bold;color:#c9d1d9">{f.get("title","Untitled")}</span>
          </div>
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr><td style="color:#8b949e;padding:4px 0;width:160px">Affected URL:</td>
                <td style="color:#58a6ff">{f.get("url","")}</td></tr>
            <tr><td style="color:#8b949e;padding:4px 0">Vulnerability Type:</td>
                <td style="color:#c9d1d9">{f.get("type","")}</td></tr>
            <tr><td style="color:#8b949e;padding:4px 0">CVSS Score:</td>
                <td style="color:#d29922">{f.get("cvss_score","N/A")} — {f.get("cvss_vector","")}</td></tr>
            <tr><td style="color:#8b949e;padding:4px 0">Status:</td>
                <td style="color:#3fb950">{f.get("status","Open")}</td></tr>
            <tr><td style="color:#8b949e;padding:4px 0">Tool:</td>
                <td style="color:#c9d1d9">{f.get("tool","Manual")}</td></tr>
            <tr><td style="color:#8b949e;padding:4px 0">Discovered:</td>
                <td style="color:#c9d1d9">{f.get("timestamp","")[:16] if f.get("timestamp") else ""}</td></tr>
          </table>
          <div style="margin-top:14px">
            <strong style="color:#c9d1d9">Description:</strong>
            <p style="color:#8b949e;margin:6px 0">{f.get("description","")}</p>
          </div>
          <div style="margin-top:10px">
            <strong style="color:#c9d1d9">Steps to Reproduce (PoC):</strong>
            <div style="background:#0d1117;border-radius:6px;padding:12px;margin-top:6px;color:#3fb950;font-family:monospace;font-size:13px">{poc_steps}</div>
          </div>
          {screenshot_html}
          <div style="margin-top:10px;color:#8b949e;font-size:13px">{refs_html}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bug Bounty Report — {project}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',sans-serif;padding:40px 20px}}
  .container{{max-width:900px;margin:0 auto}}
  h1{{font-size:28px;color:#58a6ff;margin-bottom:4px}}
  h2{{font-size:18px;color:#c9d1d9;border-bottom:1px solid #30363d;padding-bottom:8px;margin:24px 0 12px}}
  .meta{{color:#8b949e;font-size:14px;margin-bottom:24px}}
  .stat-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
  .stat-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
  .stat-num{{font-size:32px;font-weight:bold;margin-bottom:4px}}
  .stat-label{{font-size:12px;color:#8b949e}}
  .exec-summary{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:24px;line-height:1.7;color:#8b949e}}
  @media print{{body{{background:#fff;color:#000}}}}
</style>
</head>
<body>
<div class="container">
  <h1>&#x1F6E1; TeamCyberOps Security Report</h1>
  <div class="meta">
    Target: <strong style="color:#58a6ff">{project}</strong> &nbsp;|&nbsp;
    Date: {now} &nbsp;|&nbsp;
    Author: {author} &nbsp;|&nbsp;
    Total Findings: {len(findings)}
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-num" style="color:#f85149">{stats['CRITICAL']}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#d29922">{stats['HIGH']}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#58a6ff">{stats['MEDIUM']}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#3fb950">{stats['LOW']}</div><div class="stat-label">Low</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#8b949e">{stats['INFO']}</div><div class="stat-label">Info</div></div>
  </div>

  <h2>&#x1F4CB; Executive Summary</h2>
  <div class="exec-summary">
    A comprehensive security assessment was conducted against <strong style="color:#c9d1d9">{project}</strong>.
    The assessment identified a total of <strong style="color:#c9d1d9">{len(findings)}</strong> security findings,
    including <strong style="color:#f85149">{stats['CRITICAL']} Critical</strong>,
    <strong style="color:#d29922">{stats['HIGH']} High</strong>,
    <strong style="color:#58a6ff">{stats['MEDIUM']} Medium</strong>, and
    <strong style="color:#3fb950">{stats['LOW']} Low</strong> severity vulnerabilities.
    Immediate remediation is recommended for all Critical and High severity findings.
    All testing was performed in accordance with responsible disclosure and ethical hacking guidelines.
  </div>

  <h2>&#x26A1; Vulnerability Findings</h2>
  {findings_html if findings_html else '<p style="color:#8b949e">No findings recorded yet.</p>'}

  <div style="margin-top:40px;text-align:center;color:#8b949e;font-size:13px;border-top:1px solid #30363d;padding-top:20px">
    Generated by TeamCyberOps Suite v3 &mdash; {now}
  </div>
</div>
</body>
</html>"""

    out_path = REPORTS_PATH / f"{project}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(out_path, "w") as f:
        f.write(html)
    return str(out_path)


def generate_hackerone_report(finding: dict) -> str:
    """Generate a HackerOne-format report for a single finding."""
    return f"""# {finding.get('title', 'Vulnerability Report')}

## Weakness
{finding.get('type', 'N/A')}

## Severity
{finding.get('severity', 'N/A')} — CVSS: {finding.get('cvss_score', 'N/A')} ({finding.get('cvss_vector', '')})

## Summary
{finding.get('description', '')}

## Steps To Reproduce
{finding.get('poc', 'N/A')}

## Impact
Successful exploitation of this vulnerability allows an attacker to:
- {finding.get('impact', 'See description above')}

## Affected URL
`{finding.get('url', 'N/A')}`

## Supporting Material / References
{chr(10).join(finding.get('references', [])) if isinstance(finding.get('references'), list) else finding.get('references', '')}

---
*Report generated by TeamCyberOps Suite v3*
"""


def generate_bugcrowd_report(finding: dict) -> str:
    severity_map = {
        "CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P5"
    }
    priority = severity_map.get(finding.get("severity", "INFO").upper(), "P3")
    return f"""**Title:** {finding.get('title', 'N/A')}
**Priority:** {priority} — {finding.get('severity', 'N/A')}
**Target:** {finding.get('url', 'N/A')}
**CWE:** {finding.get('cwe', 'N/A')}

**Description:**
{finding.get('description', '')}

**Steps to Reproduce:**
{finding.get('poc', 'N/A')}

**Impact:**
{finding.get('impact', 'See description')}

**CVSS Vector:** {finding.get('cvss_vector', 'N/A')}
**CVSS Score:** {finding.get('cvss_score', 'N/A')}

*Generated by TeamCyberOps Suite v3*
"""


def generate_markdown_report(project: str, findings: list = None) -> str:
    if findings is None:
        findings = get_findings(project)
    now = datetime.now().strftime("%Y-%m-%d")
    lines = [f"# Security Report — {project}", f"**Date:** {now}  ", f"**Total Findings:** {len(findings)}  ", "---\n"]
    for idx, f in enumerate(findings, 1):
        lines += [
            f"## {idx}. {f.get('title','Untitled')}",
            f"**Severity:** {f.get('severity','N/A')} | **CVSS:** {f.get('cvss_score','N/A')}",
            f"**URL:** `{f.get('url','')}`",
            f"\n{f.get('description','')}\n",
            "### Steps to Reproduce",
            f"```\n{f.get('poc','N/A')}\n```",
            "---\n"
        ]
    md = "\n".join(lines)
    out_path = REPORTS_PATH / f"{project}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(out_path, "w") as f:
        f.write(md)
    return str(out_path)
