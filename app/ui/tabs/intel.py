import os
import threading
"""TeamCyberOps V5 — Intel Tabs (OSINT, S3, TKO, Param Mining, Cred Stuffing, JWT WL, SAST, API Tester)"""
import customtkinter as ctk, threading, os
from pathlib import Path
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, Terminal, get_terminal_height
from app.core.database import save_finding
from app.core.config import cfg
from pathlib import Path as _Path
LOGS_DIR = _Path(cfg.get("logs_dir","logs"))


class IntelMixin:

    def _mk_intel_tab(self, frame, title, icon, desc, run_fn,
                      fields=None, btn_label="▶ Run", color=None):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="y", expand=True, padx=12, pady=8)
        Section(pad, title, icon, color or C["purple"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=color or C["purple"]); info.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(info, text=desc, font=F(10),
                     justify="left", wraplength=800, anchor="w").pack(anchor="w", padx=14, pady=10)
        vars_map = {}
        for label, key, default, width in (fields or []):
            row = ctk.CTkFrame(pad); row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label,
                         font=F(10, mono=True), width=160, anchor="e").pack(side="left", padx=(0,10))
            v = ctk.StringVar(value=default)
            GlowEntry(row, textvariable=v, width=width or 380, height=32).pack(side="left")
            if "project" in key.lower() or key in ("name","target","domain"):
                NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                           command=lambda vv=v: vv.set(self.project.get() or "")).pack(side="left", padx=6)
            vars_map[key] = v
        sep = ctk.CTkFrame(pad, height=2, fg_color=C["border"]); sep.pack(fill="x", pady=(8,4))
        term = Terminal(pad, height=get_terminal_height()); term.pack(fill="y", expand=True, pady=(4,8))
        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        stop = [False]
        def _run():
            stop[0] = False; term.clear()
            vals = {k: v.get().strip() for k, v in vars_map.items()}
            threading.Thread(target=lambda: run_fn(vals, term.log, stop, self), daemon=True).start()
        FilledButton(btn_row, text=btn_label, command=_run, color=color or C["purple"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", color=C["red"], small=True,
                   command=lambda v=None: stop.__setitem__(0, True)).pack(side="left", padx=8)
        NeonButton(btn_row, text="📋 Copy", small=True, color=C["text_muted"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(term.get_content()),
                                    self.root.update())).pack(side="left", padx=4)
        return vars_map, term

    # ── OSINT ─────────────────────────────────────────────────────
    def _tab_osint(self, frame):
        def _run(vals, log, stop, app):
            from modules.osint.engine import full_osint
            domain  = vals.get("domain","").replace("https://","").replace("http://","").split("/")[0]
            project = app.project.get() or domain
            if not domain: log("[-] Enter domain","err"); return
            full_osint(domain, project, log_cb=log)
            app.root.after(0, lambda: app.set_status(f"OSINT done: {domain}", C["green"]))
        self._mk_intel_tab(frame, "OSINT INTELLIGENCE ENGINE", "🕵",
            "WHOIS (RDAP) · ASN/BGP ranges · Email harvest (Hunter.io) · Favicon hash (Shodan-compatible)\n"
            "DNS history · Passive DNS · Cloud assets (S3/Azure/GCP) · Reverse DNS scan",
            _run, fields=[("Target Domain","domain","",360)],
            btn_label="▶ Full OSINT", color=C["purple"])

    # ── S3 BUCKET HUNTER ─────────────────────────────────────────
    def _tab_s3(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.recon_tools import find_s3_buckets
            name = vals.get("name","")
            if not name: log("[-] Enter company name","err"); return
            r = find_s3_buckets(name, log_cb=log)
            for bucket in r.get("buckets",[]):
                save_finding({"title":f"S3 Bucket: {bucket['bucket']}",
                              "url":bucket["url"],"type":"Cloud Misconfiguration",
                              "severity":"HIGH" if bucket.get("public") else "MEDIUM",
                              "cvss_score":"7.5","description":f"Status: {bucket.get('status')} Public: {bucket.get('public')}",
                              "project":app.project.get() or name,"tool":"S3 Hunter","status":"Open"})
            if r.get("total",0) > 0:
                app.root.after(0, app._refresh_findings)
                app.root.after(0, lambda: app.set_status(f"S3: {r['total']} buckets found", C["yellow"]))
        self._mk_intel_tab(frame, "S3 BUCKET FINDER + TESTER", "🪣",
            "20 naming permutations: company-backup · company-dev · company-assets...\n"
            "PUBLIC = full data access · EXISTS (403) = misconfigured\n"
            "Tests both bucket.s3.amazonaws.com and s3.amazonaws.com/bucket patterns",
            _run, fields=[("Company Name","name","",360)],
            btn_label="▶ Hunt S3 Buckets", color=C["yellow"])

    # ── SUBDOMAIN TKO ─────────────────────────────────────────────
    def _tab_subdomain_tko(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="y", expand=True, padx=20, pady=14)
        Section(pad, "SUBDOMAIN TAKEOVER CHECKER", "🏴", C["red"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=C["red"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "20+ service signatures: GitHub Pages · Heroku · Shopify · Azure · AWS S3 · Fastly...\n"
            "NXDOMAIN + CNAME = potential takeover · Concurrent threads for fast scanning"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        row = ctk.CTkFrame(pad); row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text="Subdomains file:",
                     font=F(10, mono=True), width=140, anchor="e").pack(side="left", padx=(0,10))
        self._tko_file = ctk.StringVar()
        GlowEntry(row, textvariable=self._tko_file, width=340, height=32).pack(side="left")
        NeonButton(row, text="📂 Browse", small=True, color=C["text_dim"],
                   command=self._browse_tko_file).pack(side="left", padx=6)
        NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                   command=self._load_tko_from_project).pack(side="left", padx=4)

        sep = ctk.CTkFrame(pad, height=2, fg_color=C["border"]); sep.pack(fill="x", pady=(8,4))
        term_wrap = ctk.CTkFrame(pad, fg_color="transparent"); term_wrap.pack(fill="both", expand=False)
        self._tko_term = Terminal(term_wrap, height=get_terminal_height())
        self._tko_term.pack(fill="both", pady=(10,0))

        def _run():
            fp = self._tko_file.get().strip()
            if not fp or not os.path.isfile(fp):
                self.set_status("Select a subdomains file first","red"); return
            subs = [l.strip() for l in open(fp, errors="replace") if l.strip()]
            self._tko_term.clear()
            def _go():
                from modules.advanced.recon_tools import check_subdomain_takeover
                r = check_subdomain_takeover(subs, log_cb=self._tko_term.log)
                for v in r.get("vulnerable",[]):
                    save_finding({"title":f"Subdomain TKO: {v['subdomain']}",
                                  "url":f"https://{v['subdomain']}",
                                  "type":"Subdomain Takeover",
                                  "severity":"HIGH","cvss_score":"8.0",
                                  "description":f"Service: {v.get('service','')} CNAME: {v.get('cname','')}",
                                  "project":self.project.get() or "target",
                                  "tool":"TKO Checker","status":"Open"})
                if r.get("count",0) > 0:
                    self.root.after(0, self._refresh_findings)
                    self.root.after(0, lambda: self.set_status(f"TKO: {r['count']} vulnerable",C["red"]))
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="🏴 Check Takeovers", command=_run, color=C["red"]).pack(side="left", ipady=4)

    def _browse_tko_file(self):
        try:
            import tkinter.filedialog as fd
            p = fd.askopenfilename(filetypes=[("Text","*.txt"),("All","*.*")])
            if p: self._tko_file.set(p)
        except Exception: pass

    def _load_tko_from_project(self):
        proj = self.project.get()
        if not proj: return
        proj_dir = Path(cfg.get("logs_dir","logs")) / proj
        for fname in ["subdomains_all.txt","subfinder.txt","amass.txt"]:
            fp = proj_dir / fname
            if fp.exists(): self._tko_file.set(str(fp)); return

    # ── PARAMETER MINING ──────────────────────────────────────────
    def _tab_param_mining(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.recon_tools import mine_parameters
            url = vals.get("url","")
            if not url: log("[-] Enter target URL","err"); return
            proj = app.project.get() or "default"
            proj_dir = Path(cfg.get("logs_dir","logs")) / proj
            proj_dir.mkdir(parents=True, exist_ok=True)
            wbf = proj_dir / "all_urls.txt"
            wb_urls = [l.strip() for l in wbf.read_text(errors="replace").splitlines() if l.strip()] \
                      if wbf.exists() else []
            r = mine_parameters(url, wayback_urls=wb_urls, log_cb=log)
            params = r.get("all",[])
            if params:
                (proj_dir/"parameters.txt").write_text('\n'.join(params))
                log(f"\n[✓] {len(params)} params saved → logs/{proj}/parameters.txt","ok")
                log(f"[!] Interesting: {', '.join(r.get('interesting',[]))[:200]}","ok")
                app.root.after(0, lambda: app.set_status(f"Params: {len(params)} found",C["accent"]))
        self._mk_intel_tab(frame, "PARAMETER MINING", "⛏️",
            "Extracts params from: URL · HTML forms · JS code · Wayback URLs (auto-loaded from project)\n"
            "Flags interesting params: id · user · admin · token · key · file · redirect · cmd\n"
            "Found params → use with SQLi/XSS/SSRF testing",
            _run, fields=[("Target URL","url","",400)],
            btn_label="▶ Mine Parameters", color=C["accent"])

    # ── CREDENTIAL STUFFING ───────────────────────────────────────
    def _tab_cred_stuffing(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.recon_tools import credential_stuff
            url = vals.get("url","")
            if not url: log("[-] Enter login URL","err"); return
            r = credential_stuff(
                url,
                username_field=vals.get("uf","username"),
                password_field=vals.get("pf","password"),
                success_indicator=vals.get("si","dashboard"),
                delay=0.3, log_cb=log)
            if r.get("valid"):
                for cred in r["valid"]:
                    save_finding({"title":f"Valid Creds: {cred['username']}:{cred['password']}",
                                  "url":url,"type":"Credential Exposure",
                                  "severity":"CRITICAL","cvss_score":"9.8",
                                  "description":f"Login {url} — {cred['username']}:{cred['password']}",
                                  "project":app.project.get() or "target",
                                  "tool":"Cred Stuffing","status":"Open"})
                app.root.after(0, app._refresh_findings)
                app.root.after(0, lambda: app.set_status(f"Found {len(r['valid'])} valid credentials!",C["red"]))
        self._mk_intel_tab(frame, "CREDENTIAL STUFFING ENGINE", "🔑",
            "Tests 24+ default credential pairs: admin/admin · admin/password · root/root...\n"
            "Configurable: username field · password field · success indicator string\n"
            "Any valid credentials → CRITICAL finding auto-saved",
            _run, fields=[
                ("Login URL","url","",320),
                ("Username Field","uf","username",160),
                ("Password Field","pf","password",160),
                ("Success String","si","dashboard",200),
            ], btn_label="▶ Start Stuffing", color=C["red"])

    # ── JWT SECRET WORDLIST ───────────────────────────────────────
    def _tab_jwt_wordlist(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="y", expand=True, padx=20, pady=14)
        Section(pad, "JWT SECRET WORDLIST BRUTE-FORCER", "🔐", C["yellow"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=C["yellow"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "100+ built-in JWT secrets: 'secret' · 'password' · 'jwt-secret' · 'SECRET_KEY'...\n"
            "Also loads from project wordlists/passwords.txt automatically\n"
            "Supports HS256 / HS384 / HS512 — found secret shows forged admin token"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        row = ctk.CTkFrame(pad); row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text="JWT Token:",
                     font=F(10, mono=True), width=120, anchor="e").pack(side="left", padx=(0,10))
        self._jwt_wl_token = ctk.StringVar()
        GlowEntry(row, textvariable=self._jwt_wl_token, width=500, height=32).pack(side="left", fill="x", expand=True)

        sep = ctk.CTkFrame(pad, height=2, fg_color=C["border"]); sep.pack(fill="x", pady=(8,4))
        term_wrap = ctk.CTkFrame(pad, fg_color="transparent"); term_wrap.pack(fill="both", expand=False)
        self._jwt_wl_term = Terminal(term_wrap, height=get_terminal_height())
        self._jwt_wl_term.pack(fill="both", pady=(10,0))

        def _run():
            token = self._jwt_wl_token.get().strip()
            if not token: self.set_status("Paste a JWT token first","red"); return
            self._jwt_wl_term.clear()
            def _go():
                from modules.advanced.recon_tools import brute_jwt_secret
                r = brute_jwt_secret(token, log_cb=self._jwt_wl_term.log)
                if r.get("found"):
                    secret = r["found"]
                    self._jwt_wl_term.log(f"\n[!] SECRET FOUND: {secret!r}","ok")
                    self._jwt_wl_term.log(f"[*] Algorithm: {r.get('algorithm')}","info")
                    self._jwt_wl_term.log(f"[*] Now use JWT tab → Forge Payload with this secret","info")
                    save_finding({"title":f"Weak JWT Secret: {secret!r}",
                                  "url":"","type":"JWT Weak Secret",
                                  "severity":"CRITICAL","cvss_score":"9.8",
                                  "description":f"JWT secret: {secret!r} | Algorithm: {r.get('algorithm')}",
                                  "project":self.project.get() or "target",
                                  "tool":"JWT Brute-Force","status":"Open"})
                    self.root.after(0, self._refresh_findings)
                    self.root.after(0, lambda: self.set_status(f"JWT Secret: {secret!r}",C["red"]))
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="🔐 Brute-Force JWT Secret", command=_run, color=C["yellow"]).pack(side="left", ipady=4)

    # ── SAST SCANNER ─────────────────────────────────────────────
    def _tab_sast(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="y", expand=True, padx=20, pady=14)
        Section(pad, "SOURCE CODE SAST SCANNER", "📝", C["purple"]).pack(fill="x", pady=(0,10))

        nb = ctk.CTkTabview(pad,
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_unselected_color=C["bg_input"])
        nb.pack(fill="y", expand=True)
        nb.add("📝 Paste Code"); nb.add("🐙 GitHub Repo")

        # Paste Code
        pc = nb.tab("📝 Paste Code")
        ctk.CTkLabel(pc, text="Paste source code:",
                     font=F(10, mono=True), anchor="w").pack(fill="x", padx=10, pady=(8,4))
        self._sast_code = ctk.CTkTextbox(pc, height=150,
                                          font=F(10, mono=True))
        self._sast_code.pack(fill="x", padx=10, pady=(0,6))
        fn_row = ctk.CTkFrame(pc); fn_row.pack(fill="x", padx=10)
        ctk.CTkLabel(fn_row, text="Filename:", font=F(10, mono=True)).pack(side="left")
        self._sast_fn = ctk.StringVar(value="pasted_code.py")
        GlowEntry(fn_row, textvariable=self._sast_fn, width=220, height=30).pack(side="left", padx=8)
        sep1 = ctk.CTkFrame(pc, height=2, fg_color=C["border"]); sep1.pack(fill="x", pady=(8,4), padx=10)
        term_wrap = ctk.CTkFrame(pc, fg_color="transparent"); term_wrap.pack(fill="both", expand=True)
        self._sast_term1 = Terminal(term_wrap, height=get_terminal_height())
        self._sast_term1.pack(fill="y", expand=True, padx=10, pady=(6,8))
        def _run_paste():
            code = self._sast_code.get("0.0","end")
            if not code.strip(): return
            self._sast_term1.clear()
            threading.Thread(target=lambda: self._do_sast(code, self._sast_fn.get(), self._sast_term1.log),
                             daemon=True).start()
        FilledButton(pc, text="🔬 Analyze Code", command=_run_paste, color=C["purple"]).pack(
            side="left", padx=10, pady=(0,8), ipady=4)

        # GitHub Repo
        gh = nb.tab("🐙 GitHub Repo")
        r1 = ctk.CTkFrame(gh); r1.pack(fill="x", padx=10, pady=(8,4))
        ctk.CTkLabel(r1, text="GitHub Repo URL:",
                     font=F(10, mono=True), width=140, anchor="e").pack(side="left", padx=(0,8))
        self._sast_repo = ctk.StringVar(value="https://github.com/owner/repo")
        GlowEntry(r1, textvariable=self._sast_repo, width=400, height=32).pack(side="left")
        r2 = ctk.CTkFrame(gh); r2.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(r2, text="GitHub Token:",
                     font=F(10, mono=True), width=140, anchor="e").pack(side="left", padx=(0,8))
        self._sast_token = ctk.StringVar(value=cfg.get_api_key("github_token"))
        GlowEntry(r2, textvariable=self._sast_token, show="●", width=380, height=32).pack(side="left")
        sep2 = ctk.CTkFrame(gh, height=2, fg_color=C["border"]); sep2.pack(fill="x", pady=(8,4), padx=10)
        term_wrap = ctk.CTkFrame(gh, fg_color="transparent"); term_wrap.pack(fill="both", expand=True)
        self._sast_term2 = Terminal(term_wrap, height=get_terminal_height())
        self._sast_term2.pack(fill="y", expand=True, padx=10, pady=(6,8))
        def _run_repo():
            repo = self._sast_repo.get().strip()
            if not repo: return
            self._sast_term2.clear()
            def _go():
                from modules.advanced.intel_tools import analyze_github_repo
                r = analyze_github_repo(repo, self._sast_token.get().strip(), self._sast_term2.log)
                if r.get("total",0) > 0:
                    save_finding({"title":f"Secrets in GitHub: {repo.split('/')[-1]}",
                                  "url":repo,"type":"Secret Exposure",
                                  "severity":"CRITICAL","cvss_score":"9.0",
                                  "description":f"{r['total']} secrets/vulns in {r.get('files_scanned',0)} files",
                                  "project":self.project.get() or "target",
                                  "tool":"SAST","status":"Open"})
                    self.root.after(0, self._refresh_findings)
                    self.root.after(0, lambda: self.set_status(f"SAST: {r['total']} findings",C["red"]))
            threading.Thread(target=_go, daemon=True).start()
        FilledButton(gh, text="🐙 Scan GitHub Repo", command=_run_repo, color=C["purple"]).pack(
            side="left", padx=10, pady=(0,8), ipady=4)

    def _do_sast(self, code, filename, log):
        from modules.advanced.intel_tools import analyze_source_code
        r = analyze_source_code(code, filename, log)
        log(f"\n[✓] Secrets: {len(r['findings']['secrets'])}  Vulns: {len(r['findings']['vulnerabilities'])}","ok")

    # ── API TESTER ────────────────────────────────────────────────
    def _tab_api_tester(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="y", expand=True, padx=20, pady=14)
        Section(pad, "API SECURITY TESTER — Swagger / OpenAPI", "🔗", C["accent"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=C["accent"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Import Swagger/OpenAPI spec from URL → auto-tests all endpoints\n"
            "Tests: Auth bypass · IDOR (ID enumeration) · Method override · Rate limiting\n"
            "All findings auto-saved to Findings tab"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        r1 = ctk.CTkFrame(pad); r1.pack(fill="x", pady=4)
        ctk.CTkLabel(r1, text="Swagger/OpenAPI URL:",
                     font=F(10, mono=True), width=180, anchor="e").pack(side="left", padx=(0,10))
        self._api_sw_url = ctk.StringVar(value=f"https://{self.project.get()}/swagger.json" if self.project.get() else "")
        GlowEntry(r1, textvariable=self._api_sw_url, width=400, height=32).pack(side="left")

        r2 = ctk.CTkFrame(pad); r2.pack(fill="x", pady=4)
        ctk.CTkLabel(r2, text="Auth Header:",
                     font=F(10, mono=True), width=180, anchor="e").pack(side="left", padx=(0,10))
        self._api_auth = ctk.StringVar(value="Bearer YOUR_TOKEN")
        GlowEntry(r2, textvariable=self._api_auth, width=360, height=32).pack(side="left")

        # Endpoints tree
        ep_hdr = ctk.CTkFrame(pad, height=30)
        ep_hdr.pack(fill="x", pady=(8,0)); ep_hdr.pack_propagate(False)
        for text, w in [("METHOD",80),("PATH",300),("AUTH",60),("PARAMS",80)]:
            ctk.CTkLabel(ep_hdr, text=text,
                         font=F(9, bold=True, mono=True), width=w, anchor="w").pack(
                side="left", padx=(8 if text=="METHOD" else 0, 0))

        self._api_ep_scroll = ctk.CTkScrollableFrame(pad, height=180,
                                                       scrollbar_button_color=C["bg_hover"],
                                                       scrollbar_button_hover_color=C["accent"])
        self._api_ep_scroll.pack(fill="x")
        self._api_spec = None
        sep_api = ctk.CTkFrame(pad, height=2, fg_color=C["border"]); sep_api.pack(fill="x", pady=(8,4))
        term_wrap = ctk.CTkFrame(pad, fg_color="transparent"); term_wrap.pack(fill="both", expand=True)
        self._api_term = Terminal(term_wrap, height=get_terminal_height())
        self._api_term.pack(fill="y", expand=True, pady=(8,0))

        def _load():
            url = self._api_sw_url.get().strip()
            if not url: return
            self._api_term.clear()
            def _go():
                from modules.advanced.intel_tools import parse_swagger
                spec = parse_swagger(url, log_cb=self._api_term.log)
                if spec:
                    self._api_spec = spec
                    def _upd():
                        for w in self._api_ep_scroll.winfo_children(): w.destroy()
                        m_colors = {"GET":C["green"],"POST":C["yellow"],"DELETE":C["red"],
                                    "PUT":C["orange"],"PATCH":C["accent"]}
                        for ep in spec.get("endpoints",[]):
                            m = ep["method"]
                            mc = m_colors.get(m, C["text_muted"])
                            row = ctk.CTkFrame(self._api_ep_scroll); row.pack(fill="x", pady=1)
                            ctk.CTkLabel(row, text=f" {m} ", text_color=mc,
                                         fg_color=C["bg_hover"], font=F(9, bold=True, mono=True), width=68).pack(side="left", padx=(8,6), pady=4)
                            ctk.CTkLabel(row, text=ep["path"][:60],
                                         font=F(10, mono=True), anchor="w").pack(side="left", fill="x", expand=True)
                            ctk.CTkLabel(row, text="🔒" if ep.get("auth") else "🔓",
                                         font=F(11)).pack(side="right", padx=8)
                        self._api_term.log(f"[✓] {spec['total']} endpoints loaded","ok")
                    self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        def _test_all():
            if not self._api_spec:
                self.set_status("Load Swagger spec first","red"); return
            self._api_term.clear()
            def _go():
                from modules.advanced.intel_tools import test_api_endpoint
                proj = self.project.get() or "target"
                for ep in self._api_spec.get("endpoints",[])[:20]:
                    results = test_api_endpoint(ep, self._api_auth.get().strip(), self._api_term.log)
                    for r in results:
                        save_finding({"title":r.get("type","API Issue"),"url":r.get("url",""),
                                      "type":"API Security","severity":"HIGH","cvss_score":"7.5",
                                      "project":proj,"tool":"API Tester","status":"Open"})
                self.root.after(0, self._refresh_findings)
                self.root.after(0, lambda: self._api_term.log("[✓] All endpoints tested","ok"))
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="📥 Load Swagger", command=_load, color=C["accent"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="🔬 Test All Endpoints", command=_test_all,
                   color=C["red"], small=True).pack(side="left", padx=8)
