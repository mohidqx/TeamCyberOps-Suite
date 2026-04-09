import os
import threading
"""TeamCyberOps V5 — Recon Tabs (Passive, Active, URL Discovery, Origin Hunter, Auto-Recon)"""
import customtkinter as ctk, threading, os
from pathlib import Path
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, Terminal
from app.core.database import save_scan_result, add_scan_history, finish_scan_history
from app.core.config import cfg
from pathlib import Path as _Path
LOGS_DIR = _Path(cfg.get("logs_dir","logs"))


def _proj_dir(project, app_self):
    p = Path(cfg.get("logs_dir","logs")) / (project or "default")
    p.mkdir(parents=True, exist_ok=True)
    return p


class ReconMixin:

    # ── Generic terminal tab builder ─────────────────────────────
    def _mk_recon_tab(self, frame, title, icon, desc, run_fn,
                      fields=None, btn_label="▶ Run", btn_color=None):
        """Build a standard recon tab: description + input fields + terminal."""
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)

        Section(pad, title, icon, btn_color or C["accent"]).pack(fill="x", pady=(0,10))

        # Info card
        info = Card(pad, accent=btn_color or C["accent"])
        info.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(info, text=desc,
                     font=F(10), justify="left", wraplength=800,
                     anchor="w").pack(anchor="w", padx=14, pady=10)

        # Input fields
        vars_map = {}
        for label, key, default, width in (fields or []):
            row = ctk.CTkFrame(pad)
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label,
                         font=F(10, mono=True), width=140, anchor="e").pack(side="left", padx=(0,10))
            v = ctk.StringVar(value=default)
            GlowEntry(row, textvariable=v, width=width or 400, height=32).pack(side="left")
            # Auto-fill button
            if key == "target":
                NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                           command=lambda vv=v: vv.set(self.project.get() or "")).pack(
                    side="left", padx=6)
            vars_map[key] = v

        # Terminal
        term = Terminal(pad, height=18)
        term.pack(fill="both", expand=True, pady=(10,0))

        # Button row
        btn_row = ctk.CTkFrame(pad)
        btn_row.pack(fill="x", pady=(8,0))
        stop_flag = [False]

        def _run():
            stop_flag[0] = False
            term.clear()
            vals = {k: v.get().strip() for k, v in vars_map.items()}
            term.log(f"[*] Starting: {title}", "hdr")
            threading.Thread(
                target=lambda: run_fn(vals, term.log, stop_flag, self), daemon=True).start()

        def _stop():
            stop_flag[0] = True
            term.log("[*] Stop requested...", "warn")

        FilledButton(btn_row, text=btn_label, command=_run,
                     color=btn_color or C["accent"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", command=_stop,
                   color=C["red"], small=True).pack(side="left", padx=8)
        NeonButton(btn_row, text="📋 Copy", small=True, color=C["text_muted"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(term.get_content()),
                                    self.root.update())).pack(side="left", padx=4)
        NeonButton(btn_row, text="🗑 Clear", small=True, color=C["text_dim"],
                   command=term.clear).pack(side="left", padx=4)

        return vars_map, term

    # ── PASSIVE RECON ─────────────────────────────────────────────
    def _tab_passive_recon(self, frame):
        def _run(vals, log, stop, app):
            import sys; sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
            from modules.recon.passive import full_passive_recon
            target  = vals.get("target","").strip()
            project = app.project.get() or target.replace("https://","").split("/")[0]
            if not target:
                log("[-] Enter a target domain", "err"); return
            result = full_passive_recon(target, project, log_cb=log)
            save_scan_result(project, "passive_recon", "Subdomain Enum",
                             file_path=str(_proj_dir(project,app)/"subdomains_all.txt"),
                             line_count=result.get("total",0))
            app.set_status(f"Passive recon done: {result.get('total',0)} subdomains", C["green"])

        self._mk_recon_tab(frame,
            "PASSIVE RECON — 6 Sources Parallel", "🔍",
            "Queries: crt.sh · HackerTarget · AlienVault OTX · URLScan.io · ThreatCrowd · Subfinder · Amass\n"
            "All sources run in parallel. Results merged + deduplicated → logs/<project>/subdomains_all.txt",
            _run,
            fields=[("Target Domain", "target", "", 360)],
            btn_label="▶ Run Passive Recon", btn_color=C["accent"])

    # ── ACTIVE RECON ──────────────────────────────────────────────
    def _tab_active_recon(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)

        Section(pad, "ACTIVE RECON", "⚡", C["yellow"]).pack(fill="x", pady=(0,10))

        nb = ctk.CTkTabview(pad,
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_selected_hover_color=C["bg_hover"],
                             segmented_button_unselected_color=C["bg_input"])
        nb.pack(fill="both", expand=True)
        for t in ["Port Scan","HTTP Probe","Dir Fuzz","Tech Detect","WAF Detect"]:
            nb.add(t)

        for tab_name, run_fn, fields, color in [
            ("Port Scan", self._run_port_scan,
             [("Target","target","",300),("Scan Type","scan_type","standard",150)],
             C["yellow"]),
            ("HTTP Probe", self._run_http_probe,
             [("Hosts File / Target","target","",400)], C["accent"]),
            ("Dir Fuzz", self._run_dir_fuzz,
             [("Target URL","target","",360),("Wordlist","wordlist","",300)], C["red"]),
            ("Tech Detect", self._run_tech_detect,
             [("Target URL","target","",380)], C["purple"]),
            ("WAF Detect", self._run_waf_detect,
             [("Target URL","target","",380)], C["orange"]),
        ]:
            tf = nb.tab(tab_name)
            self._build_simple_recon_subtab(tf, tab_name, run_fn, fields, color)

    def _build_simple_recon_subtab(self, parent, title, run_fn, fields, color):
        vars_map = {}
        for label, key, default, width in fields:
            row = ctk.CTkFrame(parent)
            row.pack(fill="x", pady=4, padx=10)
            ctk.CTkLabel(row, text=label+":",
                         font=F(10, mono=True), width=120, anchor="e").pack(side="left", padx=(0,8))
            v = ctk.StringVar(value=default)
            GlowEntry(row, textvariable=v, height=32, width=width).pack(side="left")
            if key == "target":
                NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                           command=lambda vv=v: vv.set(
                               f"https://{self.project.get()}" if self.project.get() else "")).pack(
                    side="left", padx=6)
            vars_map[key] = v

        term = Terminal(parent, height=14)
        term.pack(fill="both", expand=True, padx=10, pady=(8,4))

        def _run():
            term.clear()
            vals = {k: v.get().strip() for k,v in vars_map.items()}
            threading.Thread(target=lambda: run_fn(vals, term.log, self), daemon=True).start()

        btn_row = ctk.CTkFrame(parent)
        btn_row.pack(fill="x", padx=10, pady=(0,8))
        FilledButton(btn_row, text=f"▶ Run {title}", command=_run, color=color).pack(
            side="left", ipady=4)
        NeonButton(btn_row, text="🗑 Clear", small=True, color=C["text_dim"],
                   command=term.clear).pack(side="left", padx=8)

    def _run_port_scan(self, vals, log, app):
        from modules.recon.active import port_scan
        t = vals.get("target",""); proj = app.project.get() or "default"
        if not t: log("[-] Enter a target", "err"); return
        port_scan(t, proj, vals.get("scan_type","standard"), log_cb=log)
        app.set_status("Port scan done", C["green"])

    def _run_http_probe(self, vals, log, app):
        from modules.recon.active import probe_hosts
        t = vals.get("target",""); proj = app.project.get() or "default"
        if not t: log("[-] Enter target or hosts file", "err"); return
        hosts = [t] if not os.path.isfile(t) else None
        hf    = t if os.path.isfile(t) else None
        probe_hosts(hosts or hf, proj, log_cb=log)
        app.set_status("HTTP probe done", C["green"])

    def _run_dir_fuzz(self, vals, log, app):
        from modules.recon.active import dir_fuzz
        t = vals.get("target",""); proj = app.project.get() or "default"
        if not t: log("[-] Enter target URL", "err"); return
        dir_fuzz(t, proj, wordlist=vals.get("wordlist","") or None, log_cb=log)
        app.set_status("Dir fuzz done", C["green"])

    def _run_tech_detect(self, vals, log, app):
        from modules.recon.active import detect_tech
        t = vals.get("target","")
        if not t: log("[-] Enter URL", "err"); return
        techs = detect_tech(t, log_cb=log)
        log(f"\n[✓] Detected: {', '.join(techs) if techs else 'Nothing'}", "ok")

    def _run_waf_detect(self, vals, log, app):
        from modules.recon.origin_hunter import detect_waf
        t = vals.get("target","").replace("https://","").replace("http://","").split("/")[0]
        if not t: log("[-] Enter URL", "err"); return
        result = detect_waf(t, log_cb=log)
        wafs = result.get("wafs",[])
        log(f"\n[✓] WAFs: {', '.join(wafs) if wafs else 'None detected'}", "ok" if wafs else "dim")

    # ── URL DISCOVERY ──────────────────────────────────────────────
    def _tab_url_discovery(self, frame):
        def _run(vals, log, stop, app):
            from modules.recon.url_discovery import full_url_harvest
            t = vals.get("target","").strip()
            if not t: log("[-] Enter domain", "err"); return
            domain  = t.replace("https://","").replace("http://","").split("/")[0]
            project = app.project.get() or domain
            result  = full_url_harvest(domain, project, log_cb=log)
            save_scan_result(project, "url_discovery", "URL Discovery",
                             file_path=str(_proj_dir(project,app)/"all_urls.txt"),
                             line_count=result.get("total",0))
            app.set_status(f"URLs: {result.get('total',0)} found", C["green"])

        self._mk_recon_tab(frame,
            "URL DISCOVERY — Wayback + CommonCrawl + GAU + Katana", "🕷",
            "Sources: Wayback Machine · CommonCrawl · GAU · Katana (JS-aware)\n"
            "Python fallback crawler included. Extracts params, JS endpoints, categorizes URLs.",
            _run,
            fields=[("Target Domain","target","",360)],
            btn_label="▶ Harvest URLs", btn_color=C["green"])

    # ── ORIGIN HUNTER ──────────────────────────────────────────────
    def _tab_origin_hunter(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "ORIGIN HUNTER — Find Real IP Behind CDN/WAF", "🛡", C["orange"]).pack(fill="x", pady=(0,10))

        nb = ctk.CTkTabview(pad,
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_unselected_color=C["bg_input"])
        nb.pack(fill="both", expand=True)
        for t in ["WAF Detection","Subdomain Resolve","Origin Hunt","SSL Cert"]:
            nb.add(t)

        for tab_name, run_fn, fields, color in [
            ("WAF Detection",    self._run_waf,       [("Target URL","target","",360)],         C["orange"]),
            ("Subdomain Resolve",self._run_resolve,   [("Subdomains File","file","",360)],       C["accent"]),
            ("Origin Hunt",      self._run_origin,    [("Domain","target","",360)],              C["red"]),
            ("SSL Cert",         self._run_ssl,       [("Target Host","target","",360)],         C["green"]),
        ]:
            self._build_simple_recon_subtab(nb.tab(tab_name), tab_name, run_fn, fields, color)

    def _run_waf(self, vals, log, app):
        from modules.recon.origin_hunter import detect_waf
        t = vals.get("target","").replace("https://","").replace("http://","").split("/")[0]
        if not t: log("[-] Enter URL", "err"); return
        r = detect_waf(t, log_cb=log)
        log(f"\n[✓] WAFs: {r.get('wafs',[])}  CDNs: {r.get('cdns',[])}", "ok")

    def _run_resolve(self, vals, log, app):
        from modules.recon.origin_hunter import resolve_subdomains
        f = vals.get("file","")
        if not f or not os.path.isfile(f):
            # Try project subs
            proj_dir = _proj_dir(app.project.get(), app)
            for fname in ["subdomains_all.txt","subfinder.txt","amass.txt"]:
                fp = proj_dir / fname
                if fp.exists(): f = str(fp); break
        if not f or not os.path.isfile(f):
            log("[-] No subdomains file found. Run passive recon first.", "err"); return
        subs = [l.strip() for l in open(f, errors="replace") if l.strip()]
        r = resolve_subdomains(subs, app.project.get() or "default", log_cb=log)
        log(f"\n[✓] {len(r.get('resolved',{}))} resolved", "ok")

    def _run_origin(self, vals, log, app):
        from modules.recon.origin_hunter import find_origin_ips
        t = vals.get("target","").replace("https://","").replace("http://","").split("/")[0]
        if not t: log("[-] Enter domain", "err"); return
        r = find_origin_ips(t, log_cb=log)
        origins = r.get("origin_ips",{})
        log(f"\n[✓] Origin IPs: {list(origins.keys())}", "ok" if origins else "warn")

    def _run_ssl(self, vals, log, app):
        from modules.recon.origin_hunter import ssl_cert_scan
        t = vals.get("target","").replace("https://","").replace("http://","").split("/")[0]
        if not t: log("[-] Enter hostname", "err"); return
        r = ssl_cert_scan(t, log_cb=log)
        sans = r.get("sans",[])
        log(f"\n[✓] SANs ({len(sans)}): {', '.join(sans[:10])}", "ok" if sans else "warn")

    # ── AUTO RECON ────────────────────────────────────────────────
    def _tab_auto_recon(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "AUTO-RECON — Full 5-Phase Pipeline", "🤖", C["accent"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["accent"])
        info.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(info, text=(
            "Phase 1: Passive recon (all sources)\n"
            "Phase 2: DNS resolution + HTTP probing\n"
            "Phase 3: URL discovery (Wayback + CommonCrawl + Katana)\n"
            "Phase 4: Vulnerability scan (Python checks + Nuclei if available)\n"
            "Phase 5: OSINT (ASN, emails, favicon, cloud assets)"
        ), font=F(10), justify="left", anchor="w").pack(
            anchor="w", padx=14, pady=10)

        row = ctk.CTkFrame(pad); row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text="Target Domain:",
                     font=F(10, mono=True), width=140, anchor="e").pack(side="left", padx=(0,10))
        self._ar_target = ctk.StringVar(value=self.project.get() or "")
        GlowEntry(row, textvariable=self._ar_target, width=380, height=34).pack(side="left")
        NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                   command=lambda v=None: self._ar_target.set(self.project.get() or "")).pack(side="left", padx=6)

        # Phase checkboxes
        self._ar_phases = {}
        phases_row = ctk.CTkFrame(pad); phases_row.pack(fill="x", pady=6)
        for phase, default, color in [
            ("Passive Recon", True, C["accent"]),
            ("HTTP Probe",    True, C["yellow"]),
            ("URL Discovery", True, C["green"]),
            ("Vuln Scan",     True, C["red"]),
            ("OSINT",         True, C["purple"]),
        ]:
            v = ctk.BooleanVar(value=default)
            ctk.CTkCheckBox(phases_row, text=phase, variable=v, fg_color=color,
                            hover_color=color+"aa",
                            font=F(11)).pack(side="left", padx=10)
            self._ar_phases[phase] = v

        self._ar_term = Terminal(pad, height=22)
        self._ar_term.pack(fill="both", expand=True, pady=(10,0))

        # Phase progress
        prog_row = ctk.CTkFrame(pad)
        prog_row.pack(fill="x", pady=(6,0))
        self._ar_phase_labels = {}
        for ph, color in [("Passive","cyan"),("HTTP","yellow"),("URLs","green"),("Vulns","red"),("OSINT","purple")]:
            lbl = ctk.CTkLabel(prog_row, text=f"○ {ph}",
                               font=F(9, mono=True))
            lbl.pack(side="left", padx=10)
            self._ar_phase_labels[ph] = (lbl, C[color])

        btn_row = ctk.CTkFrame(pad)
        btn_row.pack(fill="x", pady=(8,0))
        self._ar_stop = [False]
        FilledButton(btn_row, text="🤖 Start Full Auto-Recon",
                     command=self._run_auto_recon, color=C["accent"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", color=C["red"], small=True,
                   command=lambda v=None: self._ar_stop.__setitem__(0, True)).pack(side="left", padx=8)

    def _run_auto_recon(self):
        target = self._ar_target.get().strip()
        if not target: self.set_status("Enter a target domain", C["red"]); return
        domain  = target.replace("https://","").replace("http://","").split("/")[0]
        project = self.project.get() or domain
        self._ar_stop[0] = False
        self._ar_term.clear()

        def _phase(name, short, color_key):
            lbl, c = self._ar_phase_labels[short]
            self.root.after(0, lambda: lbl.configure(text=f"⏳ {short}"))

        def _phase_done(short, ok=True):
            lbl, c = self._ar_phase_labels[short]
            icon = "✅" if ok else "❌"
            self.root.after(0, lambda: lbl.configure(text=f"{icon} {short}", text_color=c))

        def _go():
            try:
                log = self._ar_term.log
                log(f"[*] AUTO-RECON: {domain}", "hdr")
                log(f"[*] Project:    {project}\n", "dim")

                if self._ar_phases.get("Passive Recon",ctk.BooleanVar(value=True)).get():
                    _phase("Passive","Passive","cyan")
                    from modules.recon.passive import full_passive_recon
                    r = full_passive_recon(domain, project, log_cb=log)
                    _phase_done("Passive", r.get("total",0)>0)
                    if self._ar_stop[0]: log("\n[*] Stopped", "warn"); return

                if self._ar_phases.get("HTTP Probe",ctk.BooleanVar(value=True)).get():
                    _phase("HTTP","HTTP","yellow")
                    from modules.recon.active import probe_hosts
                    subs_file = str(Path(cfg.get("logs_dir","logs"))/project/"subdomains_all.txt")
                    if os.path.isfile(subs_file):
                        probe_hosts(subs_file, project, log_cb=log)
                    _phase_done("HTTP")
                    if self._ar_stop[0]: log("\n[*] Stopped","warn"); return

                if self._ar_phases.get("URL Discovery",ctk.BooleanVar(value=True)).get():
                    _phase("URLs","URLs","green")
                    from modules.recon.url_discovery import full_url_harvest
                    r = full_url_harvest(domain, project, log_cb=log)
                    _phase_done("URLs", r.get("total",0)>0)
                    if self._ar_stop[0]: log("\n[*] Stopped","warn"); return

                if self._ar_phases.get("Vuln Scan",ctk.BooleanVar(value=True)).get():
                    _phase("Vulns","Vulns","red")
                    from modules.vuln.scanner import python_vuln_checks
                    findings = python_vuln_checks(f"https://{domain}", project, log_cb=log)
                    for f in findings:
                        save_scan_result(project, "vuln_scan", "Vulnerability",
                                         scan_data=f, line_count=1)
                    _phase_done("Vulns", len(findings)>0)
                    if self._ar_stop[0]: log("\n[*] Stopped","warn"); return

                if self._ar_phases.get("OSINT",ctk.BooleanVar(value=True)).get():
                    _phase("OSINT","OSINT","purple")
                    from modules.osint.engine import full_osint
                    full_osint(domain, project, log_cb=log)
                    _phase_done("OSINT")

                log(f"\n[✓] AUTO-RECON COMPLETE: {domain}", "ok")
                self.root.after(0, lambda: self.set_status(f"Auto-recon done: {domain}", C["green"]))

            except Exception as _e:
                import traceback
                print(f'[Thread Error] {_e}')
        threading.Thread(target=_go, daemon=True).start()

    # ── TOR RECON ──────────────────────────────────────────────────
    def _tab_tor_recon(self, frame):
        def _run(vals, log, stop, app):
            t = vals.get("target","").strip()
            if not t: log("[-] Enter target URL","err"); return
            if not t.startswith("http"): t = "https://" + t
            try:
                from modules.recon.tor_recon import run_full_tor_recon
                run_full_tor_recon(t, app.project.get() or "default", log_cb=log)
            except Exception as e:
                log(f"[-] Error: {e}","err")
        self._mk_recon_tab(frame,
            "TOR RECON — Anonymous Intelligence", "🧅",
            "Routes all requests through Tor SOCKS5 (localhost:9050)\n"
            "Analyzes: HTTP headers · EXIF metadata · JS secrets · IP leak detection\n"
            "Requirement: sudo service tor start",
            _run, fields=[("Target URL","target","",380)],
            btn_label="▶ Tor Recon", btn_color=C["purple"])

    # ── DORKS ──────────────────────────────────────────────────────
    def _tab_dorks(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "DORKS — 270+ Queries (Google · Shodan · Censys · GitHub)", "🔎",
                C["yellow"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["yellow"])
        info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Enter target → All 270 dorks auto-generated and saved\n"
            "Google: 130 dorks (16 categories) · Shodan: 58 · Censys: 28 · GitHub: 54"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        row = ctk.CTkFrame(pad); row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text="Target Domain:",
                     font=F(10, mono=True), width=140, anchor="e").pack(side="left", padx=(0,10))
        self._dork_target = ctk.StringVar(value=self.project.get() or "")
        GlowEntry(row, textvariable=self._dork_target, width=380, height=34).pack(side="left")
        NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                   command=lambda v=None: self._dork_target.set(self.project.get() or "")).pack(side="left", padx=6)

        self._dork_term = Terminal(pad, height=20)
        self._dork_term.pack(fill="both", expand=True, pady=(10,0))

        def _gen_dorks():
            target  = self._dork_target.get().strip()
            project = self.project.get() or target
            if not target: self.set_status("Enter target domain","red"); return
            self._dork_term.clear()
            def _go():
                from modules.recon.dorks import (
                    build_all_google_dorks, build_shodan_dorks,
                    build_censys_dorks, build_github_dorks)
                proj_dir = _proj_dir(project, self)
                log = self._dork_term.log
                log(f"[*] Generating dorks for: {target}\n","hdr")
                g = build_all_google_dorks(target)
                s = build_shodan_dorks(target)
                c = build_censys_dorks(target)
                gh= build_github_dorks(target)
                for name, dorks, color in [
                    ("Google",g,C["yellow"]),("Shodan",s,C["red"]),
                    ("Censys",c,C["accent"]),("GitHub",gh,C["purple"])]:
                    (proj_dir/f"dorks_{name.lower()}.txt").write_text('\n'.join(dorks))
                    log(f"[✓] {name}: {len(dorks)} dorks → dorks_{name.lower()}.txt","ok")
                all_dorks = g+s+c+gh
                (proj_dir/"dorks_all.txt").write_text('\n'.join(all_dorks))
                log(f"\n[✓] Total: {len(all_dorks)} dorks saved","ok")
                self.root.after(0, lambda: self.set_status(f"Dorks saved: {len(all_dorks)} total", C["green"]))
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="🔎 Generate All Dorks", command=_gen_dorks,
                     color=C["yellow"]).pack(side="left", ipady=4)
