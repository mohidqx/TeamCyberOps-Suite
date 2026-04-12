"""TeamCyberOps V5 — Scanner Tabs"""
import customtkinter as ctk
import threading
import subprocess
from pathlib import Path
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, Terminal
from app.core.database import save_finding
from app.core.config import cfg


class ScannerMixin:

    # ── VULN SCANNER ──────────────────────────────────────────────
    def _tab_vuln_scanner(self, frame):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent", border_width=0,
                                     scrollbar_button_color=C["bg_hover"],
                                     scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=12, pady=8)
        Section(pad, "VULNERABILITY SCANNER", "⚡", C["yellow"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["yellow"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Python checks: 40+ exposed files · 6 security headers · 7 injection tests · SSL\n"
            "Nuclei: auto-runs if installed · XSS: dalfox or Python · SQLi: sqlmap or Python\n"
            "All confirmed findings auto-saved to Findings tab"
        ), text_color=C["text_muted"], font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        r1 = ctk.CTkFrame(pad, fg_color="transparent"); r1.pack(fill="x", pady=4)
        ctk.CTkLabel(r1, text="Target URL:", text_color=C["text_muted"],
                     font=F(10, mono=True), width=130, anchor="e").pack(side="left", padx=(0,10))
        self._vs_target = ctk.StringVar(
            value=f"https://{self.project.get()}" if self.project.get() else "")
        GlowEntry(r1, textvariable=self._vs_target, width=420, height=34).pack(side="left")
        NeonButton(r1, text="← Project", small=True, color=C["text_dim"],
                   command=lambda v=None: self._vs_target.set(
                       f"https://{self.project.get()}" if self.project.get() else "")
                   ).pack(side="left", padx=6)

        chk_row = ctk.CTkFrame(pad, fg_color="transparent"); chk_row.pack(fill="x", pady=6)
        self._vs_checks = {}
        for lbl, key, color, default in [
            ("Python Checks", "python", C["accent"],   True),
            ("Nuclei Scan",   "nuclei", C["yellow"],  True),
            ("XSS Scan",      "xss",    C["red"],     False),
            ("SQLi Scan",     "sqli",   C["orange"],  False),
            ("Nikto Scan",    "nikto",  C["purple"],  False),
        ]:
            v = ctk.BooleanVar(value=default)
            ctk.CTkCheckBox(chk_row, text=lbl, variable=v,
                            text_color=C["text"], fg_color=color,
                            hover_color=C["bg_hover"], border_color=C["border"],
                            font=F(11)).pack(side="left", padx=10)
            self._vs_checks[key] = v

        self._vs_term = Terminal(pad, height=22)
        self._vs_term.pack(fill="both", expand=True, pady=(10,0))

        self._vs_stop = [False]
        btn_row = ctk.CTkFrame(pad, fg_color="transparent"); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="⚡ Start Scan", command=self._run_vuln_scan,
                     color=C["yellow"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", color=C["red"], small=True,
                   command=lambda v=None: self._vs_stop.__setitem__(0, True)).pack(side="left", padx=8)
        NeonButton(btn_row, text="🗑 Clear", small=True, color=C["text_dim"],
                   command=self._vs_term.clear).pack(side="left", padx=4)

    def _run_vuln_scan(self):
        target = self._vs_target.get().strip()
        if not target: self.set_status("Enter target URL", C["red"]); return
        proj = self.project.get() or target.replace("https://","").split("/")[0]
        self._vs_stop[0] = False
        self._vs_term.clear()

        def _go():
            try:
                log = self._vs_term.log
                log(f"[*] VULN SCAN: {target}", "hdr")
                if self._vs_checks.get("python", ctk.BooleanVar()).get():
                    from modules.vuln.scanner import python_vuln_checks
                    findings = python_vuln_checks(target, proj, log_cb=log)
                    for f in findings:
                        if f.get("severity") in ("CRITICAL","HIGH","MEDIUM"):
                            save_finding({
                                "title": f.get("name", f.get("type","Vuln")),
                                "url": f.get("url", target),
                                "type": f.get("type","Misconfiguration"),
                                "severity": f.get("severity","MEDIUM"),
                                "project": proj, "tool": "Python Checks", "status": "Open"
                            })
                    if findings:
                        self.root.after(0, self._refresh_findings)
                if self._vs_stop[0]: return
                if self._vs_checks.get("nuclei", ctk.BooleanVar()).get():
                    from modules.vuln.scanner import nuclei_scan
                    nuclei_scan(target, proj, log_cb=log)
                if self._vs_stop[0]: return
                if self._vs_checks.get("xss", ctk.BooleanVar()).get():
                    from modules.vuln.scanner import scan_xss
                    scan_xss([target], proj, log_cb=log)
                if self._vs_checks.get("sqli", ctk.BooleanVar()).get():
                    from modules.vuln.scanner import scan_sqli
                    scan_sqli([target], proj, log_cb=log)
                if self._vs_checks.get("nikto", ctk.BooleanVar()).get():
                    from modules.vuln.scanner import nikto_scan
                    nikto_scan(target, proj, log_cb=log)
                log("\n[✓] Scan complete", "ok")
                self.root.after(0, lambda v=None: self.set_status("Vuln scan done", C["green"]))
            except Exception as e:
                self._vs_term.log(f"[-] Error: {e}", "err")

        threading.Thread(target=_go, daemon=True).start()

    # ── NUCLEI MGR ────────────────────────────────────────────────
    def _tab_nuclei_mgr(self, frame):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent", border_width=0,
                                     scrollbar_button_color=C["bg_hover"],
                                     scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=12, pady=8)
        Section(pad, "NUCLEI TEMPLATE MANAGER", "📝", C["accent"]).pack(fill="x", pady=(0,10))

        templates_dir = Path(cfg.get("nuclei_templates_dir","nuclei-templates"))
        templates = list(templates_dir.rglob("*.yaml")) if templates_dir.exists() else []

        info = Card(pad, accent=C["accent"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            f"Templates directory: {templates_dir}\n"
            f"Templates found: {len(templates)}\n"
            "Clone from GitHub · Browse by severity · Run directly on target"
        ), text_color=C["text_muted"], font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        if not templates_dir.exists():
            warn = Card(pad, accent=C["yellow"]); warn.pack(fill="x", pady=(0,10))
            ctk.CTkLabel(warn, text="⚠  nuclei-templates not found",
                         text_color=C["yellow"], font=F(12, bold=True, mono=True)).pack(padx=14, pady=6)
            FilledButton(warn, text="📥 Clone from GitHub",
                         color=C["yellow"], command=self._clone_nuclei_templates).pack(padx=14, pady=(0,8))

        # Search
        sf_row = ctk.CTkFrame(pad, fg_color="transparent"); sf_row.pack(fill="x", pady=4)
        self._nm_search = ctk.StringVar()
        GlowEntry(sf_row, textvariable=self._nm_search,
                  placeholder_text="Search templates...", width=280, height=32).pack(side="left")
        self._nm_search.trace_add("write", lambda *_: self._filter_nuclei_templates())
        self._nm_sev = ctk.StringVar(value="All")
        ctk.CTkComboBox(sf_row, variable=self._nm_sev,
                        values=["All","critical","high","medium","low","info"],
                        width=120, height=32,
                        fg_color=C["bg_input"], border_color=C["border"],
                        text_color=C["text"], font=F(11, mono=True),
                        command=lambda v=None: self._filter_nuclei_templates()
                        ).pack(side="left", padx=8)
        ctk.CTkLabel(sf_row, text=f"{len(templates)} templates",
                     text_color=C["text_muted"], font=F(10)).pack(side="left", padx=8)
        NeonButton(sf_row, text="📥 Clone Templates", small=True, color=C["accent"],
                   command=self._clone_nuclei_templates).pack(side="right")

        self._nm_scroll = ctk.CTkScrollableFrame(pad, fg_color="transparent", border_width=0,
                                                  scrollbar_button_color=C["bg_hover"],
                                                  scrollbar_button_hover_color=C["accent"],
                                                  height=280)
        self._nm_scroll.pack(fill="x", pady=(8,0))
        self._nm_templates = templates
        self._filter_nuclei_templates()

        run_row = ctk.CTkFrame(pad, fg_color="transparent"); run_row.pack(fill="x", pady=8)
        ctk.CTkLabel(run_row, text="Target:", text_color=C["text_muted"],
                     font=F(10, mono=True), width=70, anchor="e").pack(side="left")
        self._nm_run_target = ctk.StringVar(
            value=f"https://{self.project.get()}" if self.project.get() else "")
        GlowEntry(run_row, textvariable=self._nm_run_target, width=360, height=32).pack(side="left", padx=8)

        self._nm_term = Terminal(pad, height=10)
        self._nm_term.pack(fill="both", expand=True, pady=(4,0))

    def _filter_nuclei_templates(self):
        if not hasattr(self, "_nm_scroll"): return
        for w in self._nm_scroll.winfo_children(): w.destroy()
        import re
        q   = getattr(self, "_nm_search",  ctk.StringVar()).get().lower()
        sev = getattr(self, "_nm_sev", ctk.StringVar(value="All")).get()
        shown = 0
        for tmpl in getattr(self, "_nm_templates", [])[:500]:
            try:
                content = tmpl.read_text(errors="replace")[:300]
                tmpl_sev = "info"
                m = re.search(r'severity:\s*(\w+)', content)
                if m: tmpl_sev = m.group(1).lower()
                if sev != "All" and tmpl_sev != sev: continue
                if q and q not in tmpl.name.lower() and q not in content.lower(): continue
                row = ctk.CTkFrame(self._nm_scroll, fg_color="transparent",
                                   cursor="hand2", corner_radius=4)
                row.pack(fill="x", pady=1)
                sev_c = {"critical":C["sev_critical"],"high":C["sev_high"],
                         "medium":C["sev_medium"],"low":C["sev_low"]}.get(tmpl_sev, C["text_dim"])
                ctk.CTkLabel(row, text=f" {tmpl_sev[:4].upper()} ",
                             text_color=sev_c, fg_color=C["bg_hover"],
                             font=F(8, bold=True, mono=True),
                             corner_radius=4, width=48).pack(side="left", padx=(8,6), pady=5)
                ctk.CTkLabel(row, text=tmpl.name[:70], text_color=C["text"],
                             font=F(10, mono=True), anchor="w").pack(side="left", fill="x", expand=True)
                NeonButton(row, text="▶", small=True, color=C["green"], width=30,
                           command=lambda t=str(tmpl): self._run_nuclei_template(t)).pack(side="right", padx=4)
                shown += 1
            except Exception: pass
            if shown >= 200: break

    def _run_nuclei_template(self, tmpl_path):
        target = self._nm_run_target.get().strip()
        if not target: self.set_status("Enter target URL","red"); return
        self._nm_term.clear()

        def _go():
            try:
                self._nm_term.log(f"[*] Running {Path(tmpl_path).name} on {target}", "hdr")
                out = subprocess.run(
                    ["nuclei", "-u", target, "-t", tmpl_path, "-silent", "-no-color"],
                    capture_output=True, text=True, timeout=120).stdout
                for line in out.splitlines():
                    self._nm_term.log(line, "ok" if "[" in line else "dim")
                if not out.strip():
                    self._nm_term.log("[-] No findings", "dim")
            except FileNotFoundError:
                self._nm_term.log("[-] nuclei not installed — use Tool Installer", "err")
            except Exception as e:
                self._nm_term.log(f"[-] Error: {e}", "err")

        threading.Thread(target=_go, daemon=True).start()

    def _clone_nuclei_templates(self):
        def _go():
            try:
                self.set_status("Cloning nuclei-templates...","yellow")
                subprocess.run(
                    ["git", "clone", "--depth", "1",
                     "https://github.com/projectdiscovery/nuclei-templates",
                     str(Path(cfg.get("nuclei_templates_dir","nuclei-templates")))],
                    capture_output=True, timeout=300)
                self.root.after(0, lambda v=None: self.set_status("nuclei-templates cloned!", C["green"]))
            except Exception as e:
                self.root.after(0, lambda v=None: self.set_status(f"Clone error: {e}", C["red"]))

        threading.Thread(target=_go, daemon=True).start()

    # ── ANALYSIS ──────────────────────────────────────────────────
    def _tab_analysis(self, frame):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent", border_width=0,
                                     scrollbar_button_color=C["bg_hover"],
                                     scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=12, pady=8)
        Section(pad, "SECURITY ANALYSIS", "📊", C["purple"]).pack(fill="x", pady=(0,10))

        nb = ctk.CTkTabview(pad, fg_color=C["bg_panel"],
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_unselected_color=C["bg_input"],
                             text_color=C["text"], border_color=C["border"], border_width=1)
        nb.pack(fill="both", expand=True)
        for t in ["JS Analyzer","Endpoint Extractor","CSP Analyzer","CORS Check","Headers"]:
            nb.add(t)

        for tab_name, run_fn, label, color in [
            ("JS Analyzer",        self._run_js_analyze,  "JS File URL",  C["yellow"]),
            ("Endpoint Extractor", self._run_ep_extract,  "Target URL",   C["accent"]),
            ("CSP Analyzer",       self._run_csp,         "Target URL",   C["orange"]),
            ("CORS Check",         self._run_cors,        "Target URL",   C["red"]),
            ("Headers",            self._run_headers,     "Target URL",   C["green"]),
        ]:
            tf = nb.tab(tab_name)
            row = ctk.CTkFrame(tf, fg_color="transparent"); row.pack(fill="x", padx=10, pady=8)
            ctk.CTkLabel(row, text=label+":", text_color=C["text_muted"],
                         font=F(10, mono=True), width=130, anchor="e").pack(side="left", padx=(0,8))
            v = ctk.StringVar()
            GlowEntry(row, textvariable=v, width=400, height=32).pack(side="left")
            NeonButton(row, text="← Target", small=True, color=C["text_dim"],
                       command=lambda vv=v: vv.set(
                           f"https://{self.project.get()}" if self.project.get() else "")
                       ).pack(side="left", padx=6)
            term = Terminal(tf, height=18)
            term.pack(fill="both", expand=True, padx=10, pady=(0,8))

            def _make_runner(fn, vv, t):
                def _run():
                    t.clear()
                    url = vv.get().strip()
                    if not url: return
                    def _go():
                        try: fn(url, t.log, self)
                        except Exception as e: t.log(f"[-] Error: {e}", "err")
                    threading.Thread(target=_go, daemon=True).start()
                return _run

            FilledButton(tf, text=f"▶ {tab_name}", color=color,
                         command=_make_runner(run_fn, v, term)
                         ).pack(side="left", padx=10, pady=(0,8), ipady=4)

    def _run_js_analyze(self, url, log, app):
        from modules.analysis.security_tools import fetch_and_analyze_js
        r = fetch_and_analyze_js(url, log_cb=log)
        if r and r.get("secrets"):
            proj = app.project.get() or "default"
            for s in r["secrets"][:5]:
                save_finding({"title":f"Secret in JS: {s['type']}","url":url,
                              "type":"Secret Exposure","severity":s.get("severity","HIGH"),
                              "description":f"{s['type']}: {s['value'][:60]}",
                              "project":proj,"tool":"JS Analyzer","status":"Open"})
            app.root.after(0, app._refresh_findings)

    def _run_ep_extract(self, url, log, app):
        from modules.analysis.security_tools import extract_endpoints
        r = extract_endpoints(url, log_cb=log)
        log(f"\n[✓] {len(r.get('endpoints',[]))} endpoints, {len(r.get('forms',[]))} forms","ok")

    def _run_csp(self, url, log, app):
        from modules.analysis.security_tools import analyze_csp
        r = analyze_csp(url, log_cb=log)
        for issue in r.get("issues",[]): log(f"  [{issue['severity']}] {issue['type']}","warn")
        if r.get("bypasses"):
            log("XSS Bypasses:","hdr")
            for b in r["bypasses"]: log(f"  {b}","ok")

    def _run_cors(self, url, log, app):
        from modules.analysis.security_tools import analyze_cors
        r = analyze_cors(url, log_cb=log)
        proj = app.project.get() or "default"
        for f in r.get("findings",[]):
            save_finding({"title":f"CORS: {f.get('issue','')}","url":url,
                          "type":"CORS Misconfiguration","severity":f.get("severity","HIGH"),
                          "project":proj,"tool":"CORS Analyzer","status":"Open"})
        if r.get("findings"): app.root.after(0, app._refresh_findings)

    def _run_headers(self, url, log, app):
        from modules.analysis.security_tools import analyze_headers
        r = analyze_headers(url, log_cb=log)
        for issue in r.get("issues",[]): log(f"  [{issue['severity']}] {issue['type']}","warn")

    # ── CVE INTEL ─────────────────────────────────────────────────
    def _tab_cve_intel(self, frame):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent", border_width=0,
                                     scrollbar_button_color=C["bg_hover"],
                                     scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "CVE INTELLIGENCE — NVD + CISA KEV", "🛡", C["red"]).pack(fill="x", pady=(0,10))

        nb = ctk.CTkTabview(pad, fg_color=C["bg_panel"],
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_unselected_color=C["bg_input"],
                             text_color=C["text"], border_color=C["border"], border_width=1)
        nb.pack(fill="both", expand=True)
        nb.add("🔍 NVD Search"); nb.add("☁ CISA KEV"); nb.add("🔧 Tech CVEs")

        # NVD Search
        nvd_tab = nb.tab("🔍 NVD Search")
        nvd_row = ctk.CTkFrame(nvd_tab, fg_color="transparent"); nvd_row.pack(fill="x", padx=10, pady=8)
        self._nvd_q = ctk.StringVar()
        GlowEntry(nvd_row, textvariable=self._nvd_q,
                  placeholder_text="Search CVEs... (e.g. Apache Log4j)",
                  width=360, height=32).pack(side="left")
        self._nvd_sev = ctk.StringVar(value="HIGH")
        ctk.CTkComboBox(nvd_row, variable=self._nvd_sev,
                        values=["CRITICAL","HIGH","MEDIUM","LOW"],
                        width=110, height=32,
                        fg_color=C["bg_input"], border_color=C["border"],
                        text_color=C["text"], font=F(11, mono=True)
                        ).pack(side="left", padx=8)
        self._nvd_term = Terminal(nvd_tab, height=20)
        self._nvd_term.pack(fill="both", expand=True, padx=10, pady=(0,8))

        def _nvd_search():
            q = self._nvd_q.get().strip()
            if not q: return
            self._nvd_term.clear()
            def _go():
                try:
                    from modules.analysis.cve_fetcher import nvd_search
                    results = nvd_search(q, limit=15, severity=self._nvd_sev.get(),
                                         log_cb=self._nvd_term.log)
                    self._nvd_term.log(f"\n[✓] {len(results)} CVEs found","ok")
                except Exception as e:
                    self._nvd_term.log(f"[-] Error: {e}","err")
            threading.Thread(target=_go, daemon=True).start()

        FilledButton(nvd_tab, text="🔍 Search NVD", command=_nvd_search,
                     color=C["red"]).pack(side="left", padx=10, pady=(0,8), ipady=4)

        # CISA KEV
        kev_tab = nb.tab("☁ CISA KEV")
        kev_row = ctk.CTkFrame(kev_tab, fg_color="transparent"); kev_row.pack(fill="x", padx=10, pady=8)
        self._kev_q = ctk.StringVar()
        GlowEntry(kev_row, textvariable=self._kev_q,
                  placeholder_text="Filter KEV... (e.g. Apache)",
                  width=360, height=32).pack(side="left")
        self._kev_term = Terminal(kev_tab, height=20)
        self._kev_term.pack(fill="both", expand=True, padx=10, pady=(0,8))

        def _kev_search():
            q = self._kev_q.get().strip()
            self._kev_term.clear()
            def _go():
                try:
                    from modules.analysis.cve_fetcher import get_cisa_kev, search_kev
                    results = search_kev(q, self._kev_term.log) if q else get_cisa_kev(self._kev_term.log)
                    for r in results[:20]:
                        self._kev_term.log(f"  [{r.get('cveID')}] {r.get('vendorProject')} — {r.get('vulnerabilityName','')}","warn")
                    self._kev_term.log(f"\n[✓] {len(results)} actively exploited CVEs","ok")
                except Exception as e:
                    self._kev_term.log(f"[-] Error: {e}","err")
            threading.Thread(target=_go, daemon=True).start()

        FilledButton(kev_tab, text="☁ Load CISA KEV", command=_kev_search,
                     color=C["red"]).pack(side="left", padx=10, pady=(0,8), ipady=4)

        # Tech CVEs
        tech_tab = nb.tab("🔧 Tech CVEs")
        tech_row = ctk.CTkFrame(tech_tab, fg_color="transparent"); tech_row.pack(fill="x", padx=10, pady=8)
        ctk.CTkLabel(tech_row, text="Tech Stack:", text_color=C["text_muted"],
                     font=F(10, mono=True)).pack(side="left")
        self._tech_q = ctk.StringVar(value="Apache, PHP, WordPress")
        GlowEntry(tech_row, textvariable=self._tech_q, width=360, height=32).pack(side="left", padx=8)
        self._tech_term = Terminal(tech_tab, height=20)
        self._tech_term.pack(fill="both", expand=True, padx=10, pady=(0,8))

        def _tech_cves():
            techs = [t.strip() for t in self._tech_q.get().split(",") if t.strip()]
            if not techs: return
            self._tech_term.clear()
            def _go():
                try:
                    from modules.analysis.cve_fetcher import tech_to_cves
                    results = tech_to_cves(techs, log_cb=self._tech_term.log)
                    total = sum(len(v) for v in results.values())
                    self._tech_term.log(f"\n[✓] {total} CVEs for {len(results)} techs","ok")
                except Exception as e:
                    self._tech_term.log(f"[-] Error: {e}","err")
            threading.Thread(target=_go, daemon=True).start()

        FilledButton(tech_tab, text="🔧 Find CVEs", command=_tech_cves,
                     color=C["orange"]).pack(side="left", padx=10, pady=(0,8), ipady=4)

    # ── SHODAN EXPLOIT ────────────────────────────────────────────
    def _tab_shodan_exploit(self, frame):
        shodan_key = cfg.get_api_key("shodan")

        def _run(vals, log, stop, app):
            try:
                from modules.advanced.intel_tools import shodan_auto_exploit
                t = vals.get("target","").strip()
                if not t: log("[-] Enter target IP/host","err"); return
                r = shodan_auto_exploit(t, vals.get("api_key",""), log_cb=log)
                for f in r.get("findings",[]):
                    save_finding({
                        "title": f.get("description","Service Exposed"),
                        "url": f.get("url",""), "type":"Service Exposure",
                        "severity": f.get("severity","HIGH"),
                        "project": app.project.get() or t,
                        "tool": "Shodan Exploit", "status": "Open"
                    })
                app.root.after(0, app._refresh_findings)
            except Exception as e:
                log(f"[-] Error: {e}","err")

        self._mk_recon_tab(frame,
            "SHODAN AUTO-EXPLOIT", "🔭",
            "Checks: Elasticsearch · MongoDB · Redis · Jenkins · Docker API · K8s\n"
            "Direct probes — no Shodan API key needed for basic checks",
            _run,
            fields=[("Target IP/Host","target","",280),
                    ("Shodan API Key","api_key",shodan_key,280)],
            btn_label="▶ Run", btn_color=C["red"])

    # ── MASS SCANNER ─────────────────────────────────────────────
    def _tab_mass_scanner(self, frame):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent", border_width=0,
                                     scrollbar_button_color=C["bg_hover"],
                                     scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "MASS VULNERABILITY SCANNER", "🎯", C["orange"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["orange"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info,
                     text="16 checks per target: .env · .git · admin · debug · Docker API · backup\nOne target per line",
                     text_color=C["text_muted"], font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        ctk.CTkLabel(pad, text="Targets (one per line):", text_color=C["text_muted"],
                     font=F(10, mono=True), anchor="w").pack(anchor="w")
        self._mass_targets = ctk.CTkTextbox(pad, height=100,
                                             fg_color=C["bg_input"], border_color=C["border"],
                                             text_color=C["text"], font=F(11, mono=True), border_width=1)
        self._mass_targets.pack(fill="x", pady=4)
        if self.project.get():
            self._mass_targets.insert("0.0", f"https://{self.project.get()}\n")

        self._mass_term = Terminal(pad, height=18)
        self._mass_term.pack(fill="both", expand=True, pady=(8,0))

        def _run():
            targets = [l.strip() for l in self._mass_targets.get("0.0","end").splitlines() if l.strip()]
            if not targets: return
            self._mass_term.clear()
            def _go():
                try:
                    from modules.advanced.intel_tools import mass_scan
                    r = mass_scan(targets, log_cb=self._mass_term.log)
                    for tgt, findings in r.get("results",{}).items():
                        for f in findings:
                            save_finding({"title":f["check"],"url":f["url"],
                                          "type":"Misconfiguration","severity":f["severity"],
                                          "project":self.project.get() or tgt,
                                          "tool":"Mass Scanner","status":"Open"})
                    self.root.after(0, self._refresh_findings)
                    self.root.after(0, lambda v=None: self.set_status(
                        f"Mass scan: {r.get('total',0)} findings", C["orange"]))
                except Exception as e:
                    self._mass_term.log(f"[-] Error: {e}","err")

            threading.Thread(target=_go, daemon=True).start()

        FilledButton(pad, text="🎯 Start Mass Scan", command=_run,
                     color=C["orange"]).pack(anchor="w", pady=(8,0), ipady=4)

    # ── shared _mk_recon_tab (same as ReconMixin) ─────────────────
    def _mk_recon_tab(self, frame, title, icon, desc, run_fn,
                      fields=None, btn_label="▶ Run", btn_color=None):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent", border_width=0,
                                     scrollbar_button_color=C["bg_hover"],
                                     scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, title, icon, btn_color or C["accent"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=btn_color or C["accent"]); info.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(info, text=desc, text_color=C["text_muted"],
                     font=F(10), justify="left", wraplength=800, anchor="w"
                     ).pack(anchor="w", padx=14, pady=10)
        vars_map = {}
        for label, key, default, width in (fields or []):
            row = ctk.CTkFrame(pad, fg_color="transparent"); row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, text_color=C["text_muted"],
                         font=F(10, mono=True), width=160, anchor="e").pack(side="left", padx=(0,10))
            v = ctk.StringVar(value=default)
            GlowEntry(row, textvariable=v, width=width or 380, height=32).pack(side="left")
            vars_map[key] = v
        term = Terminal(pad, height=18); term.pack(fill="both", expand=True, pady=(10,0))
        btn_row = ctk.CTkFrame(pad, fg_color="transparent"); btn_row.pack(fill="x", pady=(8,0))
        stop_flag = [False]

        def _run():
            stop_flag[0] = False; term.clear()
            vals = {k: v.get().strip() for k, v in vars_map.items()}
            def _go():
                try: run_fn(vals, term.log, stop_flag, self)
                except Exception as e: term.log(f"[-] Error: {e}","err")
            threading.Thread(target=_go, daemon=True).start()

        FilledButton(btn_row, text=btn_label, command=_run,
                     color=btn_color or C["accent"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", color=C["red"], small=True,
                   command=lambda v=None: stop_flag.__setitem__(0, True)).pack(side="left", padx=8)
        NeonButton(btn_row, text="📋 Copy", small=True, color=C["text_muted"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                           self.root.clipboard_append(term.get_content()),
                                           self.root.update())).pack(side="left", padx=4)
        return vars_map, term
