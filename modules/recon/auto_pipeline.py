"""
TeamCyberOps Suite — Auto-Recon Pipeline Engine
Enter target → everything runs automatically
Phase 1: Subdomain Enum → Phase 2: DNS Resolve → Phase 3: HTTP Probe
Phase 4: Port Scan → Phase 5: Tech Fingerprint → Phase 6: Vuln Scan
Phase 7: Payload Testing → Phase 8: Report Generation
"""
import subprocess, threading, os, json, re, shutil, urllib.request, urllib.parse, socket
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
# Project-local nuclei templates folder: TeamCyberOps/nuclei-templates/
NUCLEI_TEMPLATES_DIR = BASE_DIR / "nuclei-templates"
LOGS_DIR.mkdir(exist_ok=True)

# ══════════════════════════════════════════════════════════════
#  TOOL AVAILABILITY CHECKER
# ══════════════════════════════════════════════════════════════

REQUIRED_TOOLS = {
    "subfinder":   {"install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "category": "recon"},
    "amass":       {"install": "go install -v github.com/owasp-amass/amass/v4/...@master", "category": "recon"},
    "dnsx":        {"install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "category": "recon"},
    "httpx":       {"install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "category": "probe"},
    "nmap":        {"install": "apt-get install -y nmap", "category": "portscan"},
    "nuclei":      {"install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "category": "vuln"},
    "katana":      {"install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest", "category": "crawl"},
    "gau":         {"install": "go install -v github.com/lc/gau/v2/cmd/gau@latest", "category": "crawl"},
    "waybackurls": {"install": "go install -v github.com/tomnomnom/waybackurls@latest", "category": "crawl"},
    "subzy":       {"install": "go install -v github.com/PentestPaapa/subzy@latest", "category": "takeover"},
    "dalfox":      {"install": "go install -v github.com/hahwul/dalfox/v2@latest", "category": "xss"},
    "sqlmap":      {"install": "apt-get install -y sqlmap", "category": "sqli"},
    "ffuf":        {"install": "go install -v github.com/ffuf/ffuf/v2@latest", "category": "fuzz"},
    "gobuster":    {"install": "apt-get install -y gobuster", "category": "fuzz"},
    "arjun":       {"install": "pip3 install arjun", "category": "params"},
    "gf":          {"install": "go install -v github.com/tomnomnom/gf@latest", "category": "filter"},
    "kxss":        {"install": "go install -v github.com/Emoe/kxss@latest", "category": "xss"},
    "hakrawler":   {"install": "go install -v github.com/hakluke/hakrawler@latest", "category": "crawl"},
    "gospider":    {"install": "go install -v github.com/jaeles-project/gospider@latest", "category": "crawl"},
    "wafw00f":     {"install": "pip3 install wafw00f", "category": "waf"},
    "nikto":       {"install": "apt-get install -y nikto", "category": "vuln"},
    "whatweb":     {"install": "apt-get install -y whatweb", "category": "fingerprint"},
    "gowitness":   {"install": "go install -v github.com/sensepost/gowitness@latest", "category": "screenshot"},
    "masscan":     {"install": "apt-get install -y masscan", "category": "portscan"},
}

def check_tools() -> dict:
    """Return dict of tool_name: is_installed."""
    return {tool: shutil.which(tool) is not None for tool in REQUIRED_TOOLS}

def get_missing_tools() -> list:
    return [t for t, installed in check_tools().items() if not installed]

def get_install_cmd(tool: str) -> str:
    return REQUIRED_TOOLS.get(tool, {}).get("install", f"apt-get install {tool}")

# ══════════════════════════════════════════════════════════════
#  AUTO-RECON PIPELINE
# ══════════════════════════════════════════════════════════════

PIPELINE_PHASES = [
    {"id": 1, "name": "Subdomain Enumeration",    "icon": "🌐", "tools": ["subfinder","amass","crtsh"]},
    {"id": 2, "name": "DNS Resolution",            "icon": "🔍", "tools": ["dnsx","massdns"]},
    {"id": 3, "name": "HTTP Probing",              "icon": "📡", "tools": ["httpx"]},
    {"id": 4, "name": "Port Scanning",             "icon": "🔌", "tools": ["nmap","masscan"]},
    {"id": 5, "name": "Tech Fingerprinting",       "icon": "🔬", "tools": ["whatweb","wappalyzer"]},
    {"id": 6, "name": "WAF Detection",             "icon": "🛡",  "tools": ["wafw00f"]},
    {"id": 7, "name": "URL Discovery",             "icon": "🕸",  "tools": ["katana","gau","waybackurls","hakrawler"]},
    {"id": 8, "name": "Parameter Discovery",       "icon": "🎯", "tools": ["arjun","x8"]},
    {"id": 9, "name": "Subdomain Takeover",        "icon": "⚠️", "tools": ["subzy","subjack"]},
    {"id": 10,"name": "Vulnerability Scanning",   "icon": "💥", "tools": ["nuclei","nikto"]},
    {"id": 11,"name": "XSS Testing",              "icon": "📝", "tools": ["dalfox","kxss"]},
    {"id": 12,"name": "SQLi Testing",             "icon": "💉", "tools": ["sqlmap","gf"]},
    {"id": 13,"name": "Directory Fuzzing",        "icon": "📂", "tools": ["ffuf","gobuster","feroxbuster"]},
    {"id": 14,"name": "Screenshot Capture",       "icon": "📸", "tools": ["gowitness","aquatone"]},
    {"id": 15,"name": "Secret Detection",         "icon": "🔑", "tools": ["gitleaks","trufflehog"]},
]

class AutoReconPipeline:
    """Fully automated bug hunting pipeline."""

    def __init__(self, target: str, output_dir: Path = None,
                 phases_enabled: list = None, log_callback=None,
                 finding_callback=None):
        self.target       = target.strip().rstrip('/')
        self.domain       = self._extract_domain(target)
        self.output_dir   = output_dir or (LOGS_DIR / self.domain)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.phases       = phases_enabled or list(range(1, 16))
        self.log          = log_callback or print
        self.on_finding   = finding_callback or (lambda f: None)
        self.stop_flag    = threading.Event()
        self.results      = {
            "subdomains": [], "alive_hosts": [], "urls": [],
            "params": [], "vulns": [], "screenshots": []
        }
        self.start_time   = None
        self.phase_status = {}

    def _extract_domain(self, target: str) -> str:
        target = target.replace("https://","").replace("http://","")
        return target.split("/")[0].split("?")[0]

    def stop(self):
        self.stop_flag.set()
        self.log("[!] Stop requested — finishing current task...", "warn")

    def run(self):
        """Run full pipeline in background thread."""
        self.start_time = datetime.now()
        self.log(f"[*] Starting AutoRecon for: {self.domain}", "info")
        self.log(f"[*] Output: {self.output_dir}", "info")
        self.log("=" * 60, "dim")

        phase_map = {
            1:  self._phase_subdomain_enum,
            2:  self._phase_dns_resolve,
            3:  self._phase_http_probe,
            4:  self._phase_port_scan,
            5:  self._phase_tech_fingerprint,
            6:  self._phase_waf_detect,
            7:  self._phase_url_discovery,
            8:  self._phase_param_discovery,
            9:  self._phase_takeover_check,
            10: self._phase_vuln_scan,
            11: self._phase_xss_test,
            12: self._phase_sqli_test,
            13: self._phase_dir_fuzz,
            14: self._phase_screenshot,
            15: self._phase_secret_scan,
        }

        for phase_id in self.phases:
            if self.stop_flag.is_set():
                self.log("[!] Pipeline stopped by user", "warn")
                break
            if phase_id in phase_map:
                info = PIPELINE_PHASES[phase_id - 1]
                self.log(f"\n{info['icon']} Phase {phase_id}: {info['name']}", "header")
                self.phase_status[phase_id] = "running"
                try:
                    phase_map[phase_id]()
                    self.phase_status[phase_id] = "done"
                except Exception as e:
                    self.log(f"[!] Phase {phase_id} error: {e}", "warn")
                    self.phase_status[phase_id] = "error"

        elapsed = (datetime.now() - self.start_time).seconds
        self.log(f"\n[✓] Pipeline complete in {elapsed}s", "ok")
        self.log(f"[+] Subdomains: {len(self.results['subdomains'])}", "ok")
        self.log(f"[+] Alive hosts: {len(self.results['alive_hosts'])}", "ok")
        self.log(f"[+] URLs: {len(self.results['urls'])}", "ok")
        self.log(f"[+] Vulnerabilities: {len(self.results['vulns'])}", "ok" if not self.results['vulns'] else "found")
        self._save_summary()

    def _run_cmd(self, cmd: list, label: str = "", timeout: int = 300) -> str:
        """Run command and return output."""
        if self.stop_flag.is_set():
            return ""
        tool = cmd[0]
        if not shutil.which(tool):
            self.log(f"[!] {tool} not installed — skipping", "warn")
            return ""
        self.log(f"  $ {' '.join(cmd)}", "cmd")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, cwd=str(self.output_dir))
            output = (r.stdout or "").strip()
            if output:
                self.log(f"  [+] {len(output.splitlines())} lines output", "info")
            return output
        except subprocess.TimeoutExpired:
            self.log(f"  [!] {tool} timed out after {timeout}s", "warn")
            return ""
        except Exception as e:
            self.log(f"  [!] {tool} error: {e}", "warn")
            return ""

    def _save_output(self, filename: str, content: str):
        """Save output to file."""
        path = self.output_dir / filename
        with open(path, 'w') as f:
            f.write(content)
        return str(path)

    def _read_output(self, filename: str) -> list:
        """Read lines from output file."""
        path = self.output_dir / filename
        if path.exists():
            return [l.strip() for l in path.read_text().splitlines() if l.strip()]
        return []

    # ── Phase 1: Subdomain Enumeration ────────────────────────
    def _phase_subdomain_enum(self):
        subs = set()

        # subfinder
        out = self._run_cmd(["subfinder", "-d", self.domain, "-silent", "-all"], timeout=120)
        if out:
            subs.update(out.splitlines())
            self._save_output("subfinder.txt", out)

        # amass (passive only)
        out = self._run_cmd(["amass", "enum", "-passive", "-d", self.domain, "-silent"], timeout=180)
        if out:
            subs.update(out.splitlines())

        # crt.sh (always works, no tool needed)
        try:
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(self.domain)}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            for entry in data:
                for name in entry.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.")
                    if self.domain in name:
                        subs.add(name)
            self.log(f"  [+] crt.sh: {len(data)} certificates", "ok")
        except Exception as e:
            self.log(f"  [!] crt.sh error: {e}", "warn")

        # HackerTarget
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode()
            for line in text.strip().split("\n"):
                if "," in line:
                    subs.add(line.split(",")[0].strip())
            self.log(f"  [+] HackerTarget: lines processed", "ok")
        except Exception:
            pass

        # AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            req = urllib.request.Request(url, headers={"User-Agent":"TeamCyberOps/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            for p in data.get("passive_dns", []):
                h = p.get("hostname","")
                if self.domain in h:
                    subs.add(h)
        except Exception:
            pass

        subs = {s for s in subs if s and self.domain in s and not s.startswith("*")}
        self.results["subdomains"] = sorted(list(subs))
        self._save_output("subdomains_all.txt", "\n".join(self.results["subdomains"]))
        self.log(f"  [✓] Total unique subdomains: {len(subs)}", "ok")

    # ── Phase 2: DNS Resolution ────────────────────────────────
    def _phase_dns_resolve(self):
        if not self.results["subdomains"]:
            self.log("  [!] No subdomains to resolve — skipping", "warn")
            return

        subs_file = self._save_output("subdomains_all.txt",
                                       "\n".join(self.results["subdomains"]))

        # Try dnsx first
        out = self._run_cmd(["dnsx", "-l", subs_file, "-silent", "-a", "-resp-only"], timeout=180)
        if out:
            self._save_output("resolved_ips.txt", out)
            self.log(f"  [✓] dnsx resolved {len(out.splitlines())} IPs", "ok")
            return

        # Python fallback — socket resolution
        self.log("  [*] dnsx not found — using Python socket fallback", "warn")
        resolved = []
        for sub in self.results["subdomains"][:200]:  # cap at 200
            try:
                ip = socket.gethostbyname(sub)
                resolved.append(f"{sub},{ip}")
            except Exception:
                pass
        if resolved:
            self._save_output("resolved_ips.txt", "\n".join(r.split(",")[1] for r in resolved))
            self._save_output("resolved_hosts.txt", "\n".join(r.split(",")[0] for r in resolved))
            self.log(f"  [✓] Python socket: {len(resolved)} resolved", "ok")

    # ── Phase 3: HTTP Probing ──────────────────────────────────
    def _phase_http_probe(self):
        subs = self.results["subdomains"] or [self.domain]
        subs_file = str(self.output_dir / "subdomains_all.txt")

        # Try httpx first
        out = self._run_cmd([
            "httpx", "-l", subs_file, "-silent",
            "-status-code", "-tech-detect", "-title",
            "-follow-redirects", "-threads", "50", "-timeout", "10",
        ], timeout=300) if (self.output_dir / "subdomains_all.txt").exists() else ""

        if out:
            self._save_output("httpx_results.txt", out)
            alive = [line.split()[0] for line in out.splitlines()
                     if line.split() and line.split()[0].startswith("http")]
            self.results["alive_hosts"] = alive
            self.log(f"  [✓] httpx: {len(alive)} alive", "ok")
        else:
            # Python urllib fallback
            self.log("  [*] httpx not found — using Python urllib fallback", "warn")
            alive = []
            for sub in subs[:100]:
                for scheme in ["https://", "http://"]:
                    url = scheme + sub if not sub.startswith("http") else sub
                    try:
                        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req, timeout=5) as r:
                            alive.append(url)
                            self.log(f"  [+] {url} [{r.status}]", "ok")
                        break
                    except Exception:
                        pass
            self.results["alive_hosts"] = alive
            self._save_output("alive_hosts.txt", "\n".join(alive))
            self.log(f"  [✓] Python probe: {len(alive)} alive", "ok")
            # Always include main target
            if self.target not in alive:
                self.results["alive_hosts"].insert(0, self.target)

        # Whatweb fingerprint on first 10
        if self.results["alive_hosts"] and shutil.which("whatweb"):
            for host in self.results["alive_hosts"][:10]:
                self._run_cmd(["whatweb", "--color=never", "-q", host], timeout=30)

        if not self.results["alive_hosts"]:
            self.results["alive_hosts"] = [self.target]

    # ── Phase 4: Port Scanning ─────────────────────────────────
    def _phase_port_scan(self):
        target_hosts = self.results["alive_hosts"][:20]  # limit for speed
        if not target_hosts:
            target_hosts = [self.domain]

        # Use nmap on resolved IPs
        for host in target_hosts[:5]:
            h = host.replace("https://","").replace("http://","").split("/")[0]
            out = self._run_cmd([
                "nmap", "-sV", "-sC", "-T4", "--open", "-p",
                "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017",
                h, "-oN", str(self.output_dir / f"nmap_{h}.txt")
            ], timeout=120)

    # ── Phase 5: Tech Fingerprint ─────────────────────────────
    def _phase_tech_fingerprint(self):
        """Already done in phase 3 with httpx -tech-detect."""
        # Parse httpx output for tech info
        httpx_file = self.output_dir / "httpx_results.txt"
        if httpx_file.exists():
            tech_data = {}
            for line in httpx_file.read_text().splitlines():
                parts = line.split()
                if parts:
                    url = parts[0]
                    techs = re.findall(r'\[([^\]]+)\]', line)
                    if techs:
                        tech_data[url] = techs
            if tech_data:
                with open(self.output_dir / "tech_fingerprint.json", 'w') as f:
                    json.dump(tech_data, f, indent=2)
                self.log(f"  [✓] Tech fingerprinted {len(tech_data)} hosts", "ok")

    # ── Phase 6: WAF Detection ────────────────────────────────
    def _phase_waf_detect(self):
        if shutil.which("wafw00f"):
            for host in self.results["alive_hosts"][:10]:
                out = self._run_cmd(["wafw00f", host, "-a"], timeout=30)
                if out and "is behind" in out.lower():
                    waf_name = re.search(r'is behind ([\w\s]+)', out, re.I)
                    if waf_name:
                        self.log(f"  [!] WAF detected on {host}: {waf_name.group(1)}", "warn")

    # ── Phase 7: URL Discovery ────────────────────────────────
    def _phase_url_discovery(self):
        all_urls = set()

        for host in self.results["alive_hosts"][:15]:
            # katana
            out = self._run_cmd(["katana", "-u", host, "-silent", "-d", "3",
                                  "-jc", "-kf", "all"], timeout=120)
            if out:
                all_urls.update(out.splitlines())

            # gau
            domain = host.replace("https://","").replace("http://","").split("/")[0]
            out = self._run_cmd(["gau", "--threads", "5", domain], timeout=60)
            if out:
                all_urls.update(out.splitlines())

            # waybackurls
            out = self._run_cmd(["waybackurls", domain], timeout=60)
            if out:
                all_urls.update(out.splitlines())

        # hakrawler on main target
        if shutil.which("hakrawler"):
            out = self._run_cmd(["hakrawler", "-url", self.target, "-depth", "3",
                                  "-plain"], timeout=120)
            if out:
                all_urls.update(out.splitlines())

        all_urls = {u for u in all_urls if u.startswith("http")}
        self.results["urls"] = sorted(list(all_urls))
        self._save_output("urls_all.txt", "\n".join(self.results["urls"]))
        self.log(f"  [✓] URLs discovered: {len(all_urls)}", "ok")

        # Extract parameters
        params = set()
        for url in all_urls:
            parsed = urllib.parse.urlparse(url)
            for p in urllib.parse.parse_qs(parsed.query).keys():
                params.add(p)
        self.results["params"] = sorted(list(params))
        if params:
            self._save_output("params.txt", "\n".join(params))
            self.log(f"  [+] Unique parameters: {len(params)}", "info")

    # ── Phase 8: Parameter Discovery ─────────────────────────
    def _phase_param_discovery(self):
        hosts = self.results["alive_hosts"][:5] or [self.target]
        if not shutil.which("arjun"):
            self.log("  [!] arjun not installed, skipping", "warn")
            return
        for host in hosts:
            if self.stop_flag.is_set():
                break
            out = self._run_cmd([
                "arjun", "-u", host, "--stable", "-q",
                "-oJ", str(self.output_dir / f"arjun_{host.split('/')[-1]}.json")
            ], timeout=120)
            if out:
                self.log(f"  [+] Parameters found in {host}", "info")

    # ── Phase 9: Subdomain Takeover ───────────────────────────
    def _phase_takeover_check(self):
        subs_file = str(self.output_dir / "subdomains_all.txt")
        if not Path(subs_file).exists():
            return
        if shutil.which("subzy"):
            out = self._run_cmd(["subzy", "run", "--targets", subs_file,
                                  "--hide-fails"], timeout=180)
            if out and "VULNERABLE" in out.upper():
                self.log(f"  [!!!] TAKEOVER FOUND: {out[:200]}", "vuln")
                self.results["vulns"].append({
                    "type": "Subdomain Takeover",
                    "severity": "HIGH",
                    "detail": out[:500]
                })

    # ── Phase 10: Vulnerability Scanning ─────────────────────
    def _phase_vuln_scan(self):
        if not shutil.which("nuclei"):
            self.log("  [!] nuclei not installed", "warn")
            return

        hosts_to_scan = self.results["alive_hosts"][:30]
        if not hosts_to_scan:
            hosts_to_scan = [self.target]

        hosts_file = self._save_output("alive_hosts.txt", "\n".join(hosts_to_scan))

        # Build nuclei command with local templates if available
        cmd = [
            "nuclei", "-l", hosts_file,
            "-severity", "medium,high,critical",
            "-silent", "-no-color",
            "-c", "20",
        ]
        
        # Check local nuclei templates first
        if NUCLEI_TEMPLATES_DIR.exists():
            custom_templates = list(NUCLEI_TEMPLATES_DIR.glob("**/*.yaml"))
            if custom_templates:
                self.log(f"  [+] Found {len(custom_templates)} custom templates locally", "info")
                cmd += ["-t", str(NUCLEI_TEMPLATES_DIR)]
            # Also add tags for system-wide templates
            cmd += ["-tags", "cve,misconfig,exposure,vulnerability,default-login"]
        else:
            # Fallback to tags only
            cmd += ["-tags", "cve,misconfig,exposure,vulnerability,default-login"]
        
        cmd += ["-o", str(self.output_dir / "nuclei_results.txt")]
        
        out = self._run_cmd(cmd, timeout=600)

        # Parse nuclei output for findings
        if out:
            for line in out.splitlines():
                sev_match = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
                sev = sev_match.group(1).upper() if sev_match else "MEDIUM"
                self.results["vulns"].append({"type": "Nuclei", "severity": sev, "detail": line})
                self.on_finding({"title": line[:100], "severity": sev, "type": "Nuclei"})

        self.log(f"  [✓] Nuclei scan done. Findings: {len(self.results['vulns'])}", "ok")

        # Also run nikto on main target
        if shutil.which("nikto"):
            self._run_cmd([
                "nikto", "-h", self.target, "-Format", "txt",
                "-output", str(self.output_dir / "nikto_results.txt"),
                "-nointeractive", "-timeout", "3"
            ], timeout=180)

    # ── Phase 11: XSS Testing ────────────────────────────────
    def _phase_xss_test(self):
        urls_file = str(self.output_dir / "urls_all.txt")
        
        # If no urls file, use alive_hosts as fallback
        if not Path(urls_file).exists() or os.path.getsize(urls_file) == 0:
            if self.results["alive_hosts"]:
                urls_file = self._save_output("urls_for_xss.txt", "\n".join(self.results["alive_hosts"]))
            else:
                self.log("  [!] No URLs or hosts available for XSS testing", "warn")
                return

        # Use gf to filter XSS-prone URLs, then dalfox
        if shutil.which("gf"):
            out = self._run_cmd(["bash", "-c", f"cat {urls_file} | gf xss 2>/dev/null"],
                                 timeout=60)
            if out:
                xss_file = self._save_output("gf_xss.txt", out)
                self.log(f"  [+] gf XSS candidates: {len(out.splitlines())}", "info")

                if shutil.which("dalfox"):
                    dalfox_out = self._run_cmd([
                        "dalfox", "file", xss_file,
                        "--silence", "--no-color", "--format", "plain"
                    ], timeout=300)
                    if dalfox_out:
                        for line in dalfox_out.splitlines():
                            if "VULN" in line.upper() or "POC" in line.upper():
                                self.results["vulns"].append({"type": "XSS", "severity": "HIGH", "detail": line})
                                self.on_finding({"title": f"XSS: {line[:80]}", "severity": "HIGH", "type": "XSS"})
                                self.log(f"  [!!!] XSS: {line[:100]}", "vuln")

    # ── Phase 12: SQLi Testing ────────────────────────────────
    def _phase_sqli_test(self):
        urls_file = str(self.output_dir / "urls_all.txt")
        
        # If no urls file, use alive_hosts as fallback
        if not Path(urls_file).exists() or os.path.getsize(urls_file) == 0:
            if self.results["alive_hosts"]:
                urls_file = self._save_output("urls_for_sqli.txt", "\n".join(self.results["alive_hosts"]))
            else:
                self.log("  [!] No URLs or hosts available for SQLi testing", "warn")
                return
        
        if not shutil.which("gf"):
            self.log("  [!] gf not installed, skipping", "warn")
            return

        out = self._run_cmd(["bash", "-c", f"cat {urls_file} | gf sqli 2>/dev/null"],
                             timeout=60)
        if out:
            sqli_urls = out.splitlines()[:20]  # test max 20
            self.log(f"  [+] SQLi candidates: {len(sqli_urls)}", "info")
            if shutil.which("sqlmap"):
                for url in sqli_urls[:5]:
                    if self.stop_flag.is_set():
                        break
                    sqli_out = self._run_cmd([
                        "sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
                        "--timeout=10", "--retries=1", "--output-dir",
                        str(self.output_dir / "sqlmap")
                    ], timeout=120)
                    if sqli_out and ("sqlmap identified" in sqli_out.lower() or
                                     "is vulnerable" in sqli_out.lower()):
                        self.results["vulns"].append({"type": "SQLi", "severity": "CRITICAL", "detail": sqli_out[:300]})
                        self.on_finding({"title": f"SQLi: {url[:80]}", "severity": "CRITICAL", "type": "SQLi"})
                        self.log(f"  [!!!] SQLi FOUND: {url}", "vuln")

    # ── Phase 13: Directory Fuzzing ───────────────────────────
    def _phase_dir_fuzz(self):
        wordlist = self._get_wordlist("directories")
        if not wordlist:
            self.log("  [!] No wordlist available for fuzzing", "warn")
            return

        hosts = self.results["alive_hosts"][:5] or [self.target]
        if not shutil.which("ffuf"):
            self.log("  [!] ffuf not installed, skipping", "warn")
            return
            
        for host in hosts:
            if self.stop_flag.is_set():
                break
            out = self._run_cmd([
                "ffuf", "-u", f"{host}/FUZZ", "-w", wordlist,
                "-mc", "200,201,204,301,302,307,401,403",
                "-t", "50", "-timeout", "10", "-silent",
                "-o", str(self.output_dir / f"ffuf_{host.split('/')[-1]}.json"),
                "-of", "json"
            ], timeout=180)
            if out:
                self.log(f"  [+] Directory fuzzing complete for {host}", "info")

    def _get_wordlist(self, wtype: str) -> str:
        """Find best available wordlist."""
        paths = {
            "directories": [
                "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                "/usr/share/wordlists/dirb/big.txt",
                "/usr/share/wordlists/dirb/common.txt",
                str(BASE_DIR / "wordlists/directories.txt"),
            ],
            "subdomains": [
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                str(BASE_DIR / "wordlists/subdomains.txt"),
            ]
        }
        for p in paths.get(wtype, []):
            if os.path.isfile(p):
                return p
        return ""

    # ── Phase 14: Screenshots ─────────────────────────────────
    def _phase_screenshot(self):
        hosts_file = str(self.output_dir / "alive_hosts.txt")
        ss_dir = str(self.output_dir / "screenshots")
        Path(ss_dir).mkdir(exist_ok=True)

        if shutil.which("gowitness") and Path(hosts_file).exists():
            self._run_cmd([
                "gowitness", "file", "-f", hosts_file,
                "--screenshot-path", ss_dir,
                "--log-scan-errors"
            ], timeout=300)
            screenshots = list(Path(ss_dir).glob("*.png"))
            self.results["screenshots"] = [str(p) for p in screenshots]
            self.log(f"  [✓] Screenshots: {len(screenshots)}", "ok")

    # ── Phase 15: Secret Detection ────────────────────────────
    def _phase_secret_scan(self):
        """Scan JS files for leaked secrets."""
        urls_file = str(self.output_dir / "urls_all.txt")
        
        # If no urls_all.txt, try to create one from alive hosts
        if not Path(urls_file).exists() or os.path.getsize(urls_file) == 0:
            if self.results["urls"]:
                urls_file = self._save_output("urls_for_secrets.txt", "\n".join(self.results["urls"]))
            elif self.results["alive_hosts"]:
                urls_file = self._save_output("urls_for_secrets.txt", "\n".join(self.results["alive_hosts"]))
            else:
                self.log("  [!] No URLs or hosts available for secret scanning", "warn")
                return

        # Filter JS files
        js_urls = [u for u in (self.results["urls"] or []) if u.endswith(".js")][:20]
        if not js_urls:
            self.log("  [!] No JS files found to scan for secrets", "warn")
            return

        self.log(f"  [*] Scanning {len(js_urls)} JS files for secrets...", "info")

        secret_patterns = {
            "AWS Key":       r'AKIA[0-9A-Z]{16}',
            "GitHub Token":  r'gh[pousr]_[A-Za-z0-9_]{36}',
            "Slack Token":   r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            "Google API":    r'AIza[0-9A-Za-z\-_]{35}',
            "Stripe Key":    r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}',
            "Private Key":   r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            "Generic Secret":r'(?i)(?:secret|api_key|apikey|access_key)[\'"\s]*[:=][\'"\s]*[A-Za-z0-9_\-]{20,}',
            "JWT":           r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        }

        for js_url in js_urls:
            if self.stop_flag.is_set():
                break
            try:
                req = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    code = r.read().decode("utf-8", errors="replace")

                for name, pattern in secret_patterns.items():
                    matches = re.findall(pattern, code)
                    if matches:
                        detail = f"[{name}] in {js_url}: {str(matches[0])[:80]}"
                        self.results["vulns"].append({
                            "type": "Secret Exposure",
                            "severity": "CRITICAL" if name in ("AWS Key","Private Key","Stripe Key") else "HIGH",
                            "detail": detail
                        })
                        self.on_finding({"title": detail[:100], "severity": "CRITICAL",
                                         "type": "Secret Exposure", "url": js_url})
                        self.log(f"  [!!!] SECRET: {detail}", "vuln")
            except Exception:
                pass

    # ── Summary ───────────────────────────────────────────────
    def _save_summary(self):
        summary = {
            "target":      self.domain,
            "scan_time":   datetime.now().isoformat(),
            "elapsed_sec": (datetime.now() - self.start_time).seconds if self.start_time else 0,
            "results":     {
                "subdomains":   len(self.results["subdomains"]),
                "alive_hosts":  len(self.results["alive_hosts"]),
                "urls":         len(self.results["urls"]),
                "params":       len(self.results["params"]),
                "vulns":        len(self.results["vulns"]),
                "screenshots":  len(self.results["screenshots"]),
            },
            "vulnerabilities": self.results["vulns"],
        }
        with open(self.output_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        self.log(f"  [+] Summary saved: {self.output_dir / 'summary.json'}", "info")
        return summary


def get_pipeline_for_target(target: str, phases: list = None,
                             log_cb=None, finding_cb=None) -> AutoReconPipeline:
    """Factory function to create configured pipeline."""
    return AutoReconPipeline(
        target=target,
        output_dir=LOGS_DIR / target.replace("https://","").replace("http://","").split("/")[0],
        phases_enabled=phases,
        log_callback=log_cb,
        finding_callback=finding_cb,
    )
