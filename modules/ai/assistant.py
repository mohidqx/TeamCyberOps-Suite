"""
TeamCyberOps Suite v4 — AI Assistant Module
Powered by Claude (Anthropic API) — 100 Working Features
"""
import json, os, urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

API_URL   = "https://api.anthropic.com/v1/messages"
API_MODEL = "claude-sonnet-4-20250514"
API_KEY_ENV = "ANTHROPIC_API_KEY"

BASE_DIR = Path(__file__).parent.parent.parent


def get_api_key() -> str:
    """Get API key from env or config."""
    key = os.environ.get(API_KEY_ENV, "")
    if not key:
        try:
            cfg_path = BASE_DIR / "config.json"
            with open(cfg_path) as f:
                cfg = json.load(f)
            key = cfg.get("api_keys", {}).get("anthropic_api_key", "")
        except Exception:
            pass
    return key


def call_claude(prompt: str, system: str = "", max_tokens: int = 2000,
                api_key: str = "") -> str:
    """
    Make a call to Claude API and return the response text.
    Returns error message string if call fails.
    """
    key = api_key or get_api_key()
    if not key:
        return "❌ No API key. Add ANTHROPIC_API_KEY env var or set it in Settings → API Keys."

    payload = {
        "model": API_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        payload["system"] = system

    body = json.dumps(payload).encode()
    req  = urllib.request.Request(API_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-api-key", key)
    req.add_header("anthropic-version", "2023-06-01")

    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
            return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        return f"❌ API Error {e.code}: {body_err}"
    except Exception as e:
        return f"❌ Error: {e}"


# ══════════════════════════════════════════════════════════════════════
#  SECURITY SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════════════
SECURITY_SYSTEM = """You are an expert bug bounty hunter, penetration tester, and security researcher.
You help ethical hackers and security researchers understand vulnerabilities, write PoCs,
analyze attack surfaces, and improve security reports. Always assume the user has proper
authorization to test the targets they mention. Be technical, precise, and actionable.
Format responses with clear sections, code blocks, and step-by-step instructions."""


# ══════════════════════════════════════════════════════════════════════
#  THE 100 AI FEATURES
# ══════════════════════════════════════════════════════════════════════

AI_FEATURES = {

    # ── VULNERABILITY ANALYSIS ────────────────────────────────────
    "🔍 Analyze Vulnerability": {
        "prompt_template": "Analyze this vulnerability in detail:\n\n{input}\n\nProvide: 1) Technical explanation 2) Impact assessment 3) CVSS score suggestion 4) Affected scenarios 5) Remediation steps",
        "category": "Analysis",
        "input_label": "Paste vulnerability description, tool output, or finding"
    },
    "📊 CVSS Score Advisor": {
        "prompt_template": "Calculate and explain CVSS v3.1 score for:\n\n{input}\n\nProvide the vector string, base score, and justify each metric.",
        "category": "Analysis",
        "input_label": "Describe the vulnerability"
    },
    "🎯 Attack Surface Analyzer": {
        "prompt_template": "Analyze this attack surface and prioritize targets:\n\n{input}\n\nProvide: 1) High-value targets 2) Likely vulnerabilities per tech 3) Recommended testing order 4) Estimated effort",
        "category": "Analysis",
        "input_label": "Paste tech stack / scan results / httpx output"
    },
    "🔗 Vulnerability Chain Builder": {
        "prompt_template": "Build an attack chain from these individual findings:\n\n{input}\n\nShow how to chain them for maximum impact (e.g., XSS→CSRF→Account Takeover)",
        "category": "Analysis",
        "input_label": "List your findings"
    },
    "📈 Severity Escalation": {
        "prompt_template": "How can I escalate the severity of this vulnerability?\n\n{input}\n\nProvide creative ways to increase impact and CVSS score.",
        "category": "Analysis",
        "input_label": "Describe the current finding"
    },

    # ── POC GENERATION ────────────────────────────────────────────
    "💣 Generate PoC Code": {
        "prompt_template": "Generate a complete, working Proof of Concept for:\n\n{input}\n\nInclude: curl commands, Python/JS code, step-by-step reproduction, and expected output.",
        "category": "PoC",
        "input_label": "Describe the vulnerability"
    },
    "🐍 Python PoC Writer": {
        "prompt_template": "Write a complete Python exploit/PoC script for:\n\n{input}\n\nMake it professional with args parsing, colored output, and clear documentation.",
        "category": "PoC",
        "input_label": "Describe the vulnerability"
    },
    "📜 Bash Oneliner Generator": {
        "prompt_template": "Generate powerful bash oneliners for:\n\n{input}\n\nProvide 5-10 different approaches, from basic to advanced.",
        "category": "PoC",
        "input_label": "Attack technique or vulnerability type"
    },
    "🌐 HTTP Request Builder": {
        "prompt_template": "Build the exact HTTP request(s) to exploit:\n\n{input}\n\nProvide raw HTTP, curl, and Python requests library versions.",
        "category": "PoC",
        "input_label": "Vulnerability description"
    },
    "💉 Payload Customizer": {
        "prompt_template": "Customize and enhance these payloads for the target:\n\nTarget tech: {target_tech}\nBase payload: {input}\n\nGenerate 10 variations with WAF bypass techniques.",
        "category": "PoC",
        "input_label": "Base payload to customize",
        "extra_fields": {"target_tech": "Target technology (e.g., PHP, Node.js, Java)"}
    },

    # ── REPORT WRITING ────────────────────────────────────────────
    "📝 Write Full Bug Report": {
        "prompt_template": "Write a professional, detailed bug bounty report for:\n\n{input}\n\nFormat for HackerOne submission with: Title, Summary, Steps to Reproduce, Impact, Remediation, CVSS.",
        "category": "Reports",
        "input_label": "Describe your finding"
    },
    "✨ Improve Report Quality": {
        "prompt_template": "Improve this bug bounty report to maximize acceptance chances:\n\n{input}\n\nEnhance: technical detail, impact description, clarity, and professionalism.",
        "category": "Reports",
        "input_label": "Paste your current report"
    },
    "🎯 Executive Summary Writer": {
        "prompt_template": "Write a concise executive summary for this security assessment:\n\n{input}\n\nMake it suitable for non-technical management (max 300 words).",
        "category": "Reports",
        "input_label": "Paste findings/scan results"
    },
    "📧 Responsible Disclosure Email": {
        "prompt_template": "Write a professional responsible disclosure email for:\n\n{input}\n\nInclude: vulnerability summary, impact, proposed fix, disclosure timeline.",
        "category": "Reports",
        "input_label": "Describe the vulnerability"
    },
    "🔴 HackerOne Report Optimizer": {
        "prompt_template": "Optimize this for HackerOne submission to maximize payout:\n\n{input}\n\nFocus on impact, uniqueness, and technical quality. Suggest severity rating.",
        "category": "Reports",
        "input_label": "Paste your report"
    },
    "🟡 Bugcrowd Report Formatter": {
        "prompt_template": "Format and optimize this for Bugcrowd P1-P5 system:\n\n{input}\n\nSuggest priority level (P1-P5) and justify with impact analysis.",
        "category": "Reports",
        "input_label": "Paste your finding"
    },

    # ── SMART RECON ───────────────────────────────────────────────
    "🎯 Smart Attack Suggestions": {
        "prompt_template": "Based on this recon data, suggest the most likely vulnerabilities and attack vectors:\n\n{input}\n\nPrioritize by likelihood and impact. Include specific tools and techniques for each.",
        "category": "Smart Recon",
        "input_label": "Paste httpx output / tech stack / scan results"
    },
    "🔧 Tech Stack Attack Planner": {
        "prompt_template": "Create a comprehensive attack plan for this tech stack:\n\n{input}\n\nFor each technology: known CVEs, misconfigs, attack techniques, and specific nuclei templates.",
        "category": "Smart Recon",
        "input_label": "List the detected technologies"
    },
    "🌐 Subdomain Analysis": {
        "prompt_template": "Analyze these subdomains and identify high-value targets:\n\n{input}\n\nIdentify: dev/staging environments, APIs, admin panels, potential takeovers.",
        "category": "Smart Recon",
        "input_label": "Paste subdomain list"
    },
    "🔍 URL Pattern Analysis": {
        "prompt_template": "Analyze these URLs and identify vulnerable patterns:\n\n{input}\n\nIdentify: IDOR patterns, injectable parameters, dangerous endpoints, file inclusion candidates.",
        "category": "Smart Recon",
        "input_label": "Paste URL list (from GAU/Waybackurls)"
    },
    "🕵️ OSINT Strategy": {
        "prompt_template": "Create an OSINT strategy for:\n\n{input}\n\nProvide: dork queries, data sources, LinkedIn/GitHub recon, certificate transparency tips.",
        "category": "Smart Recon",
        "input_label": "Target company/domain"
    },

    # ── VULNERABILITY-SPECIFIC HELPERS ────────────────────────────
    "🔑 JWT Attack Guide": {
        "prompt_template": "Provide a complete JWT attack guide for:\n\n{input}\n\nCover: algorithm confusion, none alg, kid injection, weak secrets, jku/x5u manipulation.",
        "category": "Vuln Specific",
        "input_label": "Paste JWT token or describe the JWT implementation"
    },
    "🗃️ Cache Poisoning Strategy": {
        "prompt_template": "Design a cache poisoning attack strategy for:\n\n{input}\n\nCover: unkeyed headers, fat GET, parameter cloaking, DoS variations.",
        "category": "Vuln Specific",
        "input_label": "Target URL and headers"
    },
    "📦 Request Smuggling Hunter": {
        "prompt_template": "Guide me through finding HTTP request smuggling in:\n\n{input}\n\nProvide: detection techniques, CL.TE/TE.CL/TE.TE probes, exploitation steps.",
        "category": "Vuln Specific",
        "input_label": "Target domain and proxy setup"
    },
    "🎭 SSRF Exploitation Guide": {
        "prompt_template": "Create a complete SSRF exploitation guide for:\n\n{input}\n\nCover: cloud metadata, internal network scan, protocol smuggling, bypass techniques.",
        "category": "Vuln Specific",
        "input_label": "SSRF parameter / URL"
    },
    "🧬 Prototype Pollution Finder": {
        "prompt_template": "Guide prototype pollution testing for:\n\n{input}\n\nCover: detection, client-side, server-side Node.js, gadget chains, RCE path.",
        "category": "Vuln Specific",
        "input_label": "Target application description"
    },
    "📊 GraphQL Attack Guide": {
        "prompt_template": "Complete GraphQL security testing guide for:\n\n{input}\n\nCover: introspection, batching, IDOR, injection, depth attacks.",
        "category": "Vuln Specific",
        "input_label": "GraphQL endpoint URL"
    },
    "🔐 OAuth Attack Planner": {
        "prompt_template": "Test OAuth implementation for vulnerabilities:\n\n{input}\n\nCover: redirect_uri manipulation, CSRF, token leakage, open redirect chains.",
        "category": "Vuln Specific",
        "input_label": "OAuth implementation details / URLs"
    },
    "💉 SQLi Exploitation Guide": {
        "prompt_template": "Complete SQL injection guide for:\n\n{input}\n\nCover: detection, type, extraction, WAF bypass, OOB, SQLMap commands.",
        "category": "Vuln Specific",
        "input_label": "Vulnerable parameter / URL"
    },
    "🔀 IDOR Hunter Guide": {
        "prompt_template": "Find and exploit IDOR in:\n\n{input}\n\nCover: parameter types, enumeration strategy, horizontal/vertical, mass assignment.",
        "category": "Vuln Specific",
        "input_label": "Application description / endpoints"
    },
    "🎯 Host Header Injection": {
        "prompt_template": "Complete host header injection testing for:\n\n{input}\n\nCover: detection, password reset poisoning, cache poisoning, routing attacks.",
        "category": "Vuln Specific",
        "input_label": "Target domain"
    },

    # ── CODE ANALYSIS ─────────────────────────────────────────────
    "🐛 Code Vulnerability Review": {
        "prompt_template": "Review this code for security vulnerabilities:\n\n```\n{input}\n```\n\nIdentify all vulnerabilities with line references, severity, and fix recommendations.",
        "category": "Code Analysis",
        "input_label": "Paste code to review"
    },
    "🔍 JavaScript Secret Finder": {
        "prompt_template": "Analyze this JavaScript code for exposed secrets and sensitive data:\n\n```javascript\n{input}\n```\n\nFind: API keys, tokens, hardcoded credentials, dangerous functions, SSTI.",
        "category": "Code Analysis",
        "input_label": "Paste JavaScript code"
    },
    "📡 API Security Review": {
        "prompt_template": "Review this API documentation/endpoint for security issues:\n\n{input}\n\nCheck: auth bypass, IDOR, injection, rate limiting, mass assignment, over-privilege.",
        "category": "Code Analysis",
        "input_label": "Paste API docs, Swagger, or endpoint list"
    },
    "🔓 Authentication Bypass Guide": {
        "prompt_template": "Find authentication bypass techniques for:\n\n{input}\n\nCover: SQL injection in login, JWT weaknesses, session fixation, race conditions.",
        "category": "Code Analysis",
        "input_label": "Login mechanism description or code"
    },
    "🗄️ Database Query Analyzer": {
        "prompt_template": "Analyze these database queries for injection vulnerabilities:\n\n```\n{input}\n```\n\nIdentify injectable parameters, suggest payloads, and exploitability.",
        "category": "Code Analysis",
        "input_label": "Paste SQL queries or ORM code"
    },

    # ── TOOL HELP ─────────────────────────────────────────────────
    "🛠 Nuclei Template Writer": {
        "prompt_template": "Write a Nuclei YAML template for:\n\n{input}\n\nMake it production-ready with proper matchers, extractors, and metadata.",
        "category": "Tool Help",
        "input_label": "Describe the vulnerability to template"
    },
    "⚡ SQLMap Command Builder": {
        "prompt_template": "Build the perfect SQLMap command for:\n\n{input}\n\nInclude all flags for efficient exploitation, WAF bypass, and data extraction.",
        "category": "Tool Help",
        "input_label": "Target URL and injection parameters"
    },
    "💥 FFUF Wordlist Advisor": {
        "prompt_template": "Recommend the best FFUF configuration and wordlists for:\n\n{input}\n\nProvide: wordlist choices, flags, filters, and advanced techniques.",
        "category": "Tool Help",
        "input_label": "Target type and scope"
    },
    "🔫 Burp Suite Extension Advisor": {
        "prompt_template": "Recommend Burp Suite extensions and configuration for testing:\n\n{input}\n\nList best extensions, configuration tips, and testing workflow.",
        "category": "Tool Help",
        "input_label": "Target application type"
    },
    "📡 Nuclei Filter Helper": {
        "prompt_template": "Help me build the right Nuclei command for:\n\n{input}\n\nSuggest: templates, severity filters, tags, rate limiting, output format.",
        "category": "Tool Help",
        "input_label": "Target and testing objective"
    },

    # ── BYPASS TECHNIQUES ─────────────────────────────────────────
    "🛡️ WAF Bypass Generator": {
        "prompt_template": "Generate WAF bypass techniques for:\n\nPayload type: {input}\nWAF vendor: {waf_vendor}\n\nProvide 10+ bypass variants for SQL, XSS, command injection.",
        "category": "Bypass",
        "input_label": "Payload type (XSS/SQLi/CMD)",
        "extra_fields": {"waf_vendor": "WAF vendor (Cloudflare/AWS WAF/ModSecurity/unknown)"}
    },
    "🔒 Rate Limit Bypass": {
        "prompt_template": "Bypass rate limiting on:\n\n{input}\n\nTechniques: header manipulation, IP rotation, race conditions, parameter variation.",
        "category": "Bypass",
        "input_label": "Rate limited endpoint description"
    },
    "🚪 Admin Panel Bypass": {
        "prompt_template": "Find ways to bypass admin authentication for:\n\n{input}\n\nTechniques: IP spoofing, path confusion, parameter manipulation, default creds.",
        "category": "Bypass",
        "input_label": "Admin panel URL and description"
    },
    "🎭 Filter Evasion": {
        "prompt_template": "Evade input filters for:\n\nFilter type: {input}\nContext: {filter_context}\n\nGenerate encoding, case variation, alternate syntax approaches.",
        "category": "Bypass",
        "input_label": "Payload being blocked",
        "extra_fields": {"filter_context": "Where is the filter (server-side/client-side/WAF)"}
    },
    "🌐 IP Restriction Bypass": [
        "Techniques: X-Forwarded-For spoofing, X-Real-IP, SSRF to bypass, IPv6 vs IPv4",
        "curl -H 'X-Forwarded-For: 127.0.0.1' target/admin",
    ],

    # ── LEARNING & TRAINING ───────────────────────────────────────
    "📚 Explain Vulnerability": {
        "prompt_template": "Explain this vulnerability in simple terms:\n\n{input}\n\nProvide: what it is, how it works, real-world examples, why it matters.",
        "category": "Learning",
        "input_label": "Vulnerability name or description"
    },
    "🎓 Bug Bounty Methodology": {
        "prompt_template": "Create a complete bug bounty methodology for:\n\n{input}\n\nStep-by-step from recon to report, with time allocation and tool recommendations.",
        "category": "Learning",
        "input_label": "Target type (web app / mobile / API / cloud)"
    },
    "📋 Security Checklist Generator": {
        "prompt_template": "Generate a comprehensive security testing checklist for:\n\n{input}\n\nOrganize by: authentication, authorization, injection, business logic, infrastructure.",
        "category": "Learning",
        "input_label": "Application type and tech stack"
    },
    "🗺️ Attack Tree Builder": {
        "prompt_template": "Build an attack tree for compromising:\n\n{input}\n\nShow all paths from initial access to data exfil with probability estimates.",
        "category": "Learning",
        "input_label": "Target system description"
    },
    "🏆 CTF Challenge Helper": {
        "prompt_template": "Help me solve this CTF challenge:\n\n{input}\n\nProvide hints first, then full solution with explanation.",
        "category": "Learning",
        "input_label": "CTF challenge description"
    },

    # ── PRACTICAL TOOLS ───────────────────────────────────────────
    "🔐 Hash Identifier": {
        "prompt_template": "Identify this hash and suggest cracking approaches:\n\n{input}\n\nProvide: hash type, hashcat mode, best wordlists, rules to use.",
        "category": "Tools",
        "input_label": "Paste hash"
    },
    "🔑 API Key Validator": {
        "prompt_template": "Identify this API key/token and explain how to test it:\n\n{input}\n\nWhat service does it belong to? How to verify if it's valid? What can it access?",
        "category": "Tools",
        "input_label": "Paste API key or token"
    },
    "🌐 Regex Vulnerability Finder": {
        "prompt_template": "Analyze this regex for security vulnerabilities (ReDoS, bypass):\n\n```\n{input}\n```\n\nTest for ReDoS, bypass patterns, and input validation escapes.",
        "category": "Tools",
        "input_label": "Paste regex pattern"
    },
    "📡 HTTP Header Analyzer": {
        "prompt_template": "Analyze these HTTP headers for security issues:\n\n{input}\n\nCheck: missing security headers, misconfigured CSP, CORS, HSTS, cookie flags.",
        "category": "Tools",
        "input_label": "Paste HTTP response headers"
    },
    "🔍 Certificate Analyzer": {
        "prompt_template": "Analyze this SSL/TLS certificate information:\n\n{input}\n\nCheck for: weak algorithms, expiry, SAN enumeration, certificate transparency.",
        "category": "Tools",
        "input_label": "Paste certificate details"
    },
    "📋 Error Message Analyzer": {
        "prompt_template": "Analyze this error message for information disclosure:\n\n{input}\n\nExtract: tech stack, paths, versions, internal IPs, potential vulns.",
        "category": "Tools",
        "input_label": "Paste error message"
    },
    "🗂️ File Path Analyzer": {
        "prompt_template": "Analyze these file paths and suggest attack vectors:\n\n{input}\n\nIdentify: backup files, config exposure, traversal targets, interesting directories.",
        "category": "Tools",
        "input_label": "Paste file paths/directory listing"
    },
    "🔐 Password Policy Analyzer": {
        "prompt_template": "Analyze this password policy and find bypass techniques:\n\n{input}\n\nFind: weak implementations, bypass methods, spraying candidates, default passwords.",
        "category": "Tools",
        "input_label": "Describe password policy"
    },

    # ── CLOUD SECURITY ────────────────────────────────────────────
    "☁️ AWS Security Review": {
        "prompt_template": "Review this AWS configuration for security issues:\n\n{input}\n\nCheck: IAM misconfigs, S3 exposure, metadata SSRF, key exposure, service misconfigs.",
        "category": "Cloud",
        "input_label": "Paste AWS config/output"
    },
    "🔵 Azure Security Review": {
        "prompt_template": "Review this Azure configuration for vulnerabilities:\n\n{input}\n\nCheck: storage exposure, AD misconfigs, function app vulns, key vault access.",
        "category": "Cloud",
        "input_label": "Paste Azure config/output"
    },
    "🟢 GCP Security Review": {
        "prompt_template": "Review this GCP configuration for security issues:\n\n{input}\n\nCheck: bucket exposure, metadata SSRF, service account keys, IAM policies.",
        "category": "Cloud",
        "input_label": "Paste GCP config/output"
    },
    "🪣 S3 Bucket Attack Guide": {
        "prompt_template": "Complete S3 bucket attack guide for:\n\n{input}\n\nCover: enumeration, read/write/delete, website hosting exploitation, CORS.",
        "category": "Cloud",
        "input_label": "S3 bucket name or domain"
    },

    # ── MOBILE & API ──────────────────────────────────────────────
    "📱 Android APK Analysis": {
        "prompt_template": "Security analysis approach for Android APK:\n\n{input}\n\nCover: decompilation, certificate pinning bypass, hardcoded secrets, webview vulns.",
        "category": "Mobile",
        "input_label": "App description or decompiled code snippet"
    },
    "🍎 iOS App Security": {
        "prompt_template": "iOS security testing guide for:\n\n{input}\n\nCover: SSL pinning bypass, keychain analysis, IPA decryption, objection commands.",
        "category": "Mobile",
        "input_label": "App description"
    },
    "🔌 REST API Security Tester": {
        "prompt_template": "Complete REST API security test plan for:\n\n{input}\n\nCover: auth, rate limiting, injection, mass assignment, IDOR, version-specific vulns.",
        "category": "API",
        "input_label": "Paste API documentation or endpoint list"
    },
    "📡 gRPC Security Guide": {
        "prompt_template": "Security testing guide for gRPC service:\n\n{input}\n\nCover: reflection attack, injection, auth bypass, protobuf manipulation.",
        "category": "API",
        "input_label": "Service description"
    },

    # ── INFRASTRUCTURE ────────────────────────────────────────────
    "🖥️ Network Service Analyzer": {
        "prompt_template": "Analyze this nmap/port scan output for attack opportunities:\n\n{input}\n\nPrioritize services, suggest exploits, NSE scripts, and exploitation path.",
        "category": "Infra",
        "input_label": "Paste nmap scan output"
    },
    "🔒 SSL/TLS Attack Guide": {
        "prompt_template": "SSL/TLS vulnerability testing for:\n\n{input}\n\nCover: weak ciphers, BEAST, POODLE, DROWN, Heartbleed, cert pinning.",
        "category": "Infra",
        "input_label": "Domain or SSL test output"
    },
    "🌐 DNS Attack Techniques": {
        "prompt_template": "DNS security testing for:\n\n{input}\n\nCover: zone transfer, subdomain takeover, cache poisoning, DNS rebinding.",
        "category": "Infra",
        "input_label": "Target domain"
    },
    "🔧 Misconfiguration Hunter": {
        "prompt_template": "Find security misconfigurations in:\n\n{input}\n\nCheck all common misconfigs for this tech stack with specific tests.",
        "category": "Infra",
        "input_label": "Tech stack or service description"
    },

    # ── AUTOMATION & SCRIPTING ────────────────────────────────────
    "🤖 Auto Recon Script Writer": {
        "prompt_template": "Write a complete bash recon automation script for:\n\n{input}\n\nInclude: tool calls, output saving, deduplication, color output, error handling.",
        "category": "Automation",
        "input_label": "Scope/target description"
    },
    "🐍 Python Exploit Framework": {
        "prompt_template": "Write a Python exploit framework for:\n\n{input}\n\nMake it modular with: CLI args, proxy support, multi-threading, output formatting.",
        "category": "Automation",
        "input_label": "Vulnerability description"
    },
    "⚡ Nuclei Template Generator": {
        "prompt_template": "Generate 3 Nuclei templates for:\n\n{input}\n\nMake production-ready with proper matchers, extractors, severity, and metadata.",
        "category": "Automation",
        "input_label": "Vulnerability or endpoint to template"
    },
    "🔄 Burp Extension Generator": {
        "prompt_template": "Write a Burp Suite Python extension for:\n\n{input}\n\nMake it functional with UI, scanner integration, and clear documentation.",
        "category": "Automation",
        "input_label": "Functionality needed"
    },

    # ── SOCIAL ENGINEERING & PHISHING ────────────────────────────
    "📧 Phishing Awareness": {
        "prompt_template": "Create phishing awareness training material about:\n\n{input}\n\nFor educational purposes: identify tactics, red flags, and how to protect against them.",
        "category": "Social Eng",
        "input_label": "Phishing scenario to explain"
    },

    # ── INTELLIGENCE & RESEARCH ───────────────────────────────────
    "🔍 CVE Deep Dive": {
        "prompt_template": "Deep technical analysis of:\n\n{input}\n\nProvide: root cause, affected versions, PoC approach, patch analysis, detection.",
        "category": "Research",
        "input_label": "CVE ID or vulnerability name"
    },
    "🏆 Bug Bounty Program Analyzer": {
        "prompt_template": "Analyze this bug bounty program scope for best opportunities:\n\n{input}\n\nIdentify: high-value targets, likely vulns, quick wins, time investment.",
        "category": "Research",
        "input_label": "Paste program scope/description"
    },
    "📊 Threat Model Builder": {
        "prompt_template": "Build a threat model for:\n\n{input}\n\nUsing STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation.",
        "category": "Research",
        "input_label": "System/application description"
    },
    "🕵️ Digital Forensics Helper": {
        "prompt_template": "Guide forensics analysis of:\n\n{input}\n\nProvide: artifact locations, analysis commands, evidence preservation, timeline.",
        "category": "Research",
        "input_label": "Incident description"
    },
    "🔬 Malware Analysis Guide": {
        "prompt_template": "Analyze this suspicious code/behavior:\n\n{input}\n\nIdentify: techniques, IOCs, MITRE ATT&CK mapping, detection rules.",
        "category": "Research",
        "input_label": "Paste suspicious code or behavior description"
    },

    # ── QUICK FIRE FEATURES ───────────────────────────────────────
    "💬 Ask Anything Security": {
        "prompt_template": "{input}",
        "category": "General",
        "input_label": "Ask any security question"
    },
    "🔄 Translate Technical Finding": {
        "prompt_template": "Translate this technical security finding into business risk language:\n\n{input}",
        "category": "General",
        "input_label": "Paste technical finding"
    },
    "📋 Generate Test Cases": {
        "prompt_template": "Generate security test cases for:\n\n{input}\n\nFormat as a checklist with expected results and severity.",
        "category": "General",
        "input_label": "Feature or functionality to test"
    },
    "🎯 Next Step Advisor": {
        "prompt_template": "I'm currently at this point in my pentest:\n\n{input}\n\nWhat should I do next? Provide a prioritized action list.",
        "category": "General",
        "input_label": "Describe your current findings and situation"
    },
    "🏅 Bug Bounty Tip Generator": {
        "prompt_template": "Give me 10 advanced bug bounty hunting tips for:\n\n{input}\n\nFocus on finding bugs others miss.",
        "category": "General",
        "input_label": "Target type or specific area"
    },
    "🔐 Encryption Weakness Finder": {
        "prompt_template": "Find cryptographic weaknesses in:\n\n{input}\n\nCheck: algorithm, key size, implementation issues, padding oracle, timing attacks.",
        "category": "General",
        "input_label": "Describe encryption implementation"
    },
    "📱 WebSocket Security Tester": {
        "prompt_template": "Complete WebSocket security testing guide for:\n\n{input}\n\nCover: authentication, CSRF via WS, injection, hijacking, DoS.",
        "category": "General",
        "input_label": "WebSocket endpoint description"
    },
    "🎭 Race Condition Hunter": {
        "prompt_template": "Find race condition vulnerabilities in:\n\n{input}\n\nCover: Turbo Intruder attacks, detection, exploitation, common scenarios.",
        "category": "General",
        "input_label": "Endpoint or functionality description"
    },
    "🗝️ Insecure Deserialization": {
        "prompt_template": "Complete deserialization attack guide for:\n\n{input}\n\nCover: Java, PHP, Python, Node.js gadget chains and ysoserial commands.",
        "category": "General",
        "input_label": "Technology and serialized data"
    },
    "🌍 Business Logic Bug Finder": {
        "prompt_template": "Find business logic vulnerabilities in:\n\n{input}\n\nFocus on: price manipulation, workflow bypass, privilege escalation, state confusion.",
        "category": "General",
        "input_label": "Application workflow description"
    },
}


def get_feature_categories() -> dict:
    """Return features organized by category."""
    cats = {}
    for name, feat in AI_FEATURES.items():
        if isinstance(feat, dict):
            cat = feat.get("category", "General")
            cats.setdefault(cat, []).append(name)
    return cats


def run_feature(feature_name: str, user_input: str,
                extra_inputs: dict = None, api_key: str = "") -> str:
    """Execute an AI feature and return the response."""
    feat = AI_FEATURES.get(feature_name)
    if not feat or not isinstance(feat, dict):
        return f"Feature '{feature_name}' not found."

    template = feat.get("prompt_template", "{input}")
    prompt   = template.replace("{input}", user_input)

    if extra_inputs:
        for key, val in extra_inputs.items():
            prompt = prompt.replace(f"{{{key}}}", val)

    return call_claude(prompt, system=SECURITY_SYSTEM,
                       max_tokens=3000, api_key=api_key)


# ══════════════════════════════════════════════════════════════════════
#  GEMINI API INTEGRATION
# ══════════════════════════════════════════════════════════════════════

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
GEMINI_PRO_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"


def get_gemini_key() -> str:
    key = os.environ.get("GEMINI_API_KEY", "")
    if not key:
        try:
            with open(BASE_DIR / "config.json") as f:
                cfg = json.load(f)
            key = cfg.get("api_keys", {}).get("gemini_api_key", "")
        except Exception:
            pass
    return key


def call_gemini(prompt: str, system: str = "", max_tokens: int = 2000,
                api_key: str = "", model: str = "flash") -> str:
    """Call Google Gemini API."""
    key = api_key or get_gemini_key()
    if not key:
        return "❌ No Gemini API key. Add GEMINI_API_KEY or set in Settings → API Keys."

    url   = (GEMINI_PRO_URL if model == "pro" else GEMINI_API_URL) + f"?key={key}"
    parts = []
    if system:
        parts.append({"text": f"[SYSTEM]: {system}\n\n[USER]: {prompt}"})
    else:
        parts.append({"text": prompt})

    payload = {
        "contents": [{"parts": parts}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.7,
        },
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ]
    }

    body = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
            candidates = data.get("candidates", [])
            if not candidates:
                return f"❌ Gemini returned no candidates. Full response: {json.dumps(data)[:500]}"
            return candidates[0]["content"]["parts"][0]["text"]
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        return f"❌ Gemini API Error {e.code}: {body_err}"
    except Exception as e:
        return f"❌ Gemini Error: {e}"


def call_ai(prompt: str, system: str = "", max_tokens: int = 2000,
            api_key: str = "", provider: str = "claude", model: str = "") -> str:
    """
    Unified AI call — routes to Claude or Gemini based on provider.
    provider: 'claude' | 'gemini' | 'gemini-pro'
    """
    if provider.startswith("gemini"):
        gem_model = "pro" if "pro" in provider else "flash"
        return call_gemini(prompt, system, max_tokens, api_key, gem_model)
    else:
        return call_claude(prompt, system, max_tokens, api_key)


def run_feature_with_provider(feature_name: str, user_input: str,
                               extra_inputs: dict = None,
                               api_key: str = "",
                               provider: str = "claude") -> str:
    """Execute an AI feature using specified provider."""
    feat = AI_FEATURES.get(feature_name)
    if not feat or not isinstance(feat, dict):
        return f"Feature '{feature_name}' not found."
    template = feat.get("prompt_template", "{input}")
    prompt   = template.replace("{input}", user_input)
    if extra_inputs:
        for k, v in extra_inputs.items():
            prompt = prompt.replace(f"{{{k}}}", v)
    return call_ai(prompt, system=SECURITY_SYSTEM,
                   max_tokens=3000, api_key=api_key, provider=provider)
