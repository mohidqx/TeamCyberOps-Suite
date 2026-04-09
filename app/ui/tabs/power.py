import threading
"""TeamCyberOps V5 — Power Tabs (OAST, JWT, Race, GraphQL, SSRF, 2FA, Smuggling, Web Scanners)"""
import customtkinter as ctk, threading
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, Terminal
from app.core.database import save_finding
from app.core.config import cfg


class PowerMixin:

    def _mk_power_tab(self, frame, title, icon, desc, run_fn,
                      fields=None, btn_label="▶ Run", color=None):
        """Standard power tab builder."""
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, title, icon, color or C["red"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=color or C["red"])
        info.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(info, text=desc, font=F(10),
                     justify="left", wraplength=800, anchor="w").pack(anchor="w", padx=14, pady=10)
        vars_map = {}
        for label, key, default, width in (fields or []):
            row = ctk.CTkFrame(pad); row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label,
                         font=F(10,mono=True), width=160, anchor="e").pack(side="left", padx=(0,10))
            v = ctk.StringVar(value=default)
            GlowEntry(row, textvariable=v, width=width or 380, height=32).pack(side="left")
            if key in ("target","url","host"):
                NeonButton(row, text="← Project", small=True, color=C["text_dim"],
                           command=lambda vv=v: vv.set(
                               f"https://{self.project.get()}" if self.project.get() else "")).pack(
                    side="left", padx=6)
            vars_map[key] = v
        term = Terminal(pad, height=18)
        term.pack(fill="both", expand=True, pady=(10,0))
        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        stop_flag = [False]
        def _run():
            stop_flag[0] = False; term.clear()
            vals = {k:v.get().strip() for k,v in vars_map.items()}
            threading.Thread(target=lambda: run_fn(vals, term.log, stop_flag, self), daemon=True).start()
        FilledButton(btn_row, text=btn_label, command=_run, color=color or C["red"]).pack(
            side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", color=C["red"], small=True,
                   command=lambda v=None: stop_flag.__setitem__(0,True)).pack(side="left", padx=8)
        NeonButton(btn_row, text="📋 Copy", small=True, color=C["text_muted"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(term.get_content()),
                                    self.root.update())).pack(side="left", padx=4)
        return vars_map, term

    # ── OAST SERVER ───────────────────────────────────────────────
    def _tab_oast(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "OAST SERVER — Out-of-Band Testing", "📡", C["accent"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["accent"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Detects: Blind SSRF · Blind XSS · Blind SQLi DNS · Log4Shell · CMDi\n"
            "HTTP listener: port 8877  ·  DNS listener: port 5353  ·  Pure Python (no dependencies)"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        # Config
        cfg_f = ctk.CTkFrame(pad); cfg_f.pack(fill="x", pady=4)
        ctk.CTkLabel(cfg_f, text="Listen IP:",
                     font=F(10,mono=True), width=100, anchor="e").pack(side="left", padx=(0,8))
        self._oast_host = ctk.StringVar(value="0.0.0.0")
        GlowEntry(cfg_f, textvariable=self._oast_host, width=160, height=32).pack(side="left")
        ctk.CTkLabel(cfg_f, text="  HTTP Port:",
                     font=F(10,mono=True)).pack(side="left", padx=(16,8))
        self._oast_http_port = ctk.StringVar(value="8877")
        GlowEntry(cfg_f, textvariable=self._oast_http_port, width=70, height=32).pack(side="left")
        ctk.CTkLabel(cfg_f, text="  DNS Port:",
                     font=F(10,mono=True)).pack(side="left", padx=(16,8))
        self._oast_dns_port = ctk.StringVar(value="5353")
        GlowEntry(cfg_f, textvariable=self._oast_dns_port, width=70, height=32).pack(side="left")

        # Status + URL card
        self._oast_status = ctk.CTkLabel(pad, text="● STOPPED",
                                          font=F(13, bold=True, mono=True), anchor="w")
        self._oast_status.pack(anchor="w", pady=(8,4))
        url_card = Card(pad); url_card.pack(fill="x", pady=(0,8))
        url_row = ctk.CTkFrame(url_card); url_row.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(url_row, text="Listen URL:",
                     font=F(10,mono=True), width=100).pack(side="left")
        self._oast_url_var = ctk.StringVar(value="Start server to get URL")
        ctk.CTkEntry(url_row, textvariable=self._oast_url_var,
                     font=F(11,mono=True), width=450, height=30).pack(side="left", padx=8)
        NeonButton(url_row, text="📋 Copy", small=True, color=C["accent"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(self._oast_url_var.get()),
                                    self.root.update(),
                                    self.set_status("OAST URL copied!",C["green"]))).pack(side="left")

        self._oast_term = Terminal(pad, height=16)
        self._oast_term.pack(fill="both", expand=True, pady=(0,8))

        def _log(m, t="info"):
            self._oast_term.log(m, t)

        def _start():
            host = self._oast_host.get().strip() or "0.0.0.0"
            try: http_port = int(self._oast_http_port.get()); dns_port = int(self._oast_dns_port.get())
            except ValueError: self.set_status("Invalid port","red"); return
            self._oast_term.clear()
            _log("[*] Starting OAST server...","info")
            from modules.advanced.oast_server import start_http_listener, start_dns_listener
            r1 = start_http_listener(host, http_port, _log)
            r2 = start_dns_listener(host, dns_port, _log)
            if r1.get("ok") or r2.get("ok"):
                self._oast_status.configure(text=f"● RUNNING  HTTP:{http_port}  DNS:{dns_port}")
                def _get_ip():
                    try:
                        import urllib.request as _ur, socket
                        try: pub_ip = _ur.urlopen("https://api.ipify.org",timeout=5).read().decode().strip()
                        except Exception:
                            import socket
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                                s.connect(("8.8.8.8",80)); pub_ip = s.getsockname()[0]
                        url = f"http://{pub_ip}:{http_port}"
                        def _upd():
                            self._oast_url_var.set(f"{url}/PAYLOAD_ID")
                            _log(f"[✓] HTTP Listener: {url}","ok")
                            _log(f"[✓] DNS Listener:  {pub_ip}:{dns_port}","ok")
                            _log(f"\n[*] Inject this URL into target inputs:","info")
                            _log(f"    {url}/PAYLOAD_ID","ok")
                            self.set_status(f"OAST running: {url}",C["green"])
                        self.root.after(0, _upd)
                    except Exception as e: _log(f"[-] IP detection: {e}","err")
                threading.Thread(target=_get_ip, daemon=True).start()
            else:
                err = f"HTTP:{r1.get('error','')} DNS:{r2.get('error','')}"
                self._oast_status.configure(text=f"● ERROR: {err[:60]}")
                _log(f"[!] Failed: {err}","err")
                _log("[*] Try: sudo python main.py (low ports need root)","warn")

        def _stop():
            from modules.advanced.oast_server import stop_http_listener
            stop_http_listener()
            self._oast_status.configure(text="● STOPPED")
            self._oast_url_var.set("Start server to get URL")
            _log("[*] OAST server stopped","warn")

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x")
        FilledButton(btn_row, text="▶ Start OAST Server", command=_start, color=C["green"]).pack(
            side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", command=_stop, color=C["red"], small=True).pack(
            side="left", padx=8)

    # ── JWT / OAUTH ────────────────────────────────────────────────
    def _tab_jwt_oauth(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "JWT / OAUTH SECURITY", "🔐", C["yellow"]).pack(fill="x", pady=(0,10))

        nb = ctk.CTkTabview(pad,
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_unselected_color=C["bg_input"])
        nb.pack(fill="both", expand=True)
        for t in ["JWT Analyzer","JWT Attacks","OAuth Detect","OAuth ATO"]:
            nb.add(t)

        # JWT Analyzer
        ja = nb.tab("JWT Analyzer")
        ctk.CTkLabel(ja, text="Paste JWT Token:",
                     font=F(10,mono=True), anchor="w").pack(fill="x", padx=10, pady=(8,4))
        self._jwt_input = ctk.CTkTextbox(ja, height=80,
                                          font=F(10,mono=True))
        self._jwt_input.pack(fill="x", padx=10, pady=(0,6))
        self._jwt_term = Terminal(ja, height=14)
        self._jwt_term.pack(fill="both", expand=True, padx=10, pady=(0,8))
        def _analyze_jwt():
            token = self._jwt_input.get("0.0","end").strip()
            if not token: return
            self._jwt_term.clear()
            def _go():
                from modules.advanced.jwt_oauth import decode_jwt, find_jwt_vulnerabilities
                decoded = decode_jwt(token)
                self._jwt_term.log(f"[*] Header: {decoded.get('header',{})}","info")
                self._jwt_term.log(f"[*] Payload: {decoded.get('payload',{})}","info")
                self._jwt_term.log(f"[*] Algorithm: {decoded.get('header',{}).get('alg','?')}","hdr")
                vulns = find_jwt_vulnerabilities(decoded)
                for v in vulns:
                    self._jwt_term.log(f"[!] {v.get('type')}: {v.get('detail')}","ok")
            threading.Thread(target=_go, daemon=True).start()
        FilledButton(ja, text="🔍 Analyze JWT", command=_analyze_jwt, color=C["yellow"]).pack(
            side="left", padx=10, pady=(0,8), ipady=4)

        # JWT Attacks
        jatk = nb.tab("JWT Attacks")
        ctk.CTkLabel(jatk, text="JWT Token to Attack:",
                     font=F(10,mono=True), anchor="w").pack(fill="x", padx=10, pady=(8,4))
        self._jatk_input = ctk.CTkTextbox(jatk, height=70,
                                           font=F(10,mono=True))
        self._jatk_input.pack(fill="x", padx=10)
        self._jatk_term = Terminal(jatk, height=14)
        self._jatk_term.pack(fill="both", expand=True, padx=10, pady=(6,8))
        for atk_name, atk_fn, color in [
            ("alg=none",   "attack_alg_none",    C["red"]),
            ("Brute Secret","brute_force_secret", C["yellow"]),
            ("Forge Payload","forge_payload",     C["orange"]),
        ]:
            def _run_attack(fn=atk_fn):
                token = self._jatk_input.get("0.0","end").strip()
                if not token: return
                self._jatk_term.clear()
                def _go():
                    import importlib
                    mod = importlib.import_module("modules.advanced.jwt_oauth")
                    fn_callable = getattr(mod, fn, None)
                    if fn_callable:
                        result = fn_callable(token, log_cb=self._jatk_term.log)
                        if isinstance(result, list):
                            for r in result:
                                self._jatk_term.log(f"[✓] {r}","ok")
                threading.Thread(target=_go, daemon=True).start()
            NeonButton(jatk, text=f"⚔ {atk_name}", command=_run_attack,
                       color=color, small=True).pack(side="left", padx=(10 if atk_name=="alg=none" else 4), pady=(0,8))

        # OAuth
        for tab_name, fn_name, color, desc in [
            ("OAuth Detect","analyze_oauth_url",   C["purple"],"Paste OAuth authorization URL → detect CSRF, PKCE, implicit flow issues"),
            ("OAuth ATO",   "test_oauth_ato",      C["red"],   "Full OAuth Account Takeover tester → generates attack URLs"),
        ]:
            ot = nb.tab(tab_name)
            ctk.CTkLabel(ot, text=desc,
                         font=F(10), anchor="w").pack(fill="x", padx=10, pady=(8,4))
            o_input = ctk.CTkTextbox(ot, height=70,
                                      font=F(10,mono=True))
            o_input.pack(fill="x", padx=10)
            o_term = Terminal(ot, height=14)
            o_term.pack(fill="both", expand=True, padx=10, pady=(6,8))
            def _run_oauth(inp=o_input, t=o_term, fn=fn_name):
                url = inp.get("0.0","end").strip()
                if not url: return
                t.clear()
                def _go():
                    from modules.advanced.web_scanners import test_oauth_ato
                    if fn == "test_oauth_ato":
                        r = test_oauth_ato(url, log_cb=t.log)
                    else:
                        t.log(f"[*] Analyzing OAuth URL...","info")
                        from modules.advanced.jwt_oauth import analyze_oauth
                        r = analyze_oauth(url, log_cb=t.log)
                threading.Thread(target=_go, daemon=True).start()
            FilledButton(ot, text=f"▶ {tab_name}", command=_run_oauth, color=color).pack(
                side="left", padx=10, pady=(0,8), ipady=4)

    # ── RACE CONDITION ────────────────────────────────────────────
    def _tab_race(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.race_condition import run_race_test
            url = vals.get("url","")
            if not url: log("[-] Enter endpoint URL","err"); return
            try: n = int(vals.get("threads","20"))
            except: n = 20
            log(f"[*] Race condition test: {url} ({n} threads)","hdr")
            result = run_race_test(url, concurrent=n,
                                   method=vals.get("method","POST"),
                                   headers={"Authorization":vals.get("auth","")} if vals.get("auth") else {},
                                   log_cb=log)
            if result.get("vulnerable"):
                log("[!] RACE CONDITION CONFIRMED!","ok")
                save_finding({"title":f"Race Condition: {url}","url":url,
                              "type":"Race Condition","severity":"CRITICAL","cvss_score":"8.5",
                              "project":app.project.get() or "target","tool":"Race Tester","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,
            "RACE CONDITION TESTER", "⚡",
            "Synchronized barrier: ALL threads launch simultaneously (not pseudo-parallel)\n"
            "Find: Double-spend · Rate limit bypass · Coupon abuse · Free upgrades\n"
            "Bounties: $500–$50,000 depending on impact",
            _run,
            fields=[("Endpoint URL","url","",340),("Method","method","POST",100),
                    ("Threads","threads","20",80),("Auth Header","auth","",280)],
            btn_label="⚡ Launch Race Attack", color=C["yellow"])

    # ── GRAPHQL ───────────────────────────────────────────────────
    def _tab_graphql(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.graphql_tester import full_graphql_audit
            t = vals.get("target","")
            if not t: log("[-] Enter target URL","err"); return
            proj = app.project.get() or "target"
            result = full_graphql_audit(t, log_cb=log)
            for finding in result.get("findings",[]):
                save_finding({"title":f"GraphQL: {finding.get('type','')}","url":t,
                              "type":"GraphQL Security","severity":finding.get("severity","HIGH"),
                              "project":proj,"tool":"GraphQL Tester","status":"Open"})
            app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,
            "GRAPHQL SECURITY TESTER", "🕸",
            "Auto-discover 16 GraphQL paths · Introspection · Batching (rate limit bypass)\n"
            "IDOR via ID enumeration · Injection (SQLi/NoSQLi/SSTI/XSS) · Field suggestions",
            _run,
            fields=[("Target URL","target","",400)],
            btn_label="▶ Full GraphQL Audit", color=C["purple"])

    # ── SSRF SUITE ────────────────────────────────────────────────
    def _tab_ssrf(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.ssrf_suite import (generate_ssrf_bypasses,
                                                       fetch_aws_metadata, test_ssrf_quick)
            url = vals.get("url","")
            if not url: log("[-] Enter endpoint URL","err"); return
            param = vals.get("param","url")
            oast  = vals.get("oast","")
            log("[*] Running SSRF quick detection...","hdr")
            r = test_ssrf_quick(url, param, oast, log_cb=log)
            log("\n[*] Generating 36 bypass payloads:","info")
            bypasses = generate_ssrf_bypasses("169.254.169.254")
            for b in bypasses[:10]: log(f"  {b}","dim")
            log(f"\n[+] {len(bypasses)} total bypasses generated","ok")
        self._mk_power_tab(frame,
            "SSRF SUITE", "☁️",
            "Quick detection + 36 bypass techniques (decimal, hex, octal, IPv6, DNS rebinding...)\n"
            "Cloud metadata extractor: AWS IAM credentials · GCP OAuth · Azure Managed Identity\n"
            "Internal port scanner via SSRF",
            _run,
            fields=[("Target URL","url","",320),("SSRF Param","param","url",100),
                    ("OAST Host","oast","",220)],
            btn_label="▶ Run SSRF Suite", color=C["orange"])

    # ── 2FA BYPASS ────────────────────────────────────────────────
    def _tab_mfa(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.mfa_bypass import run_full_audit
            config = {"login_url":vals.get("login",""),"verify_url":vals.get("verify",""),
                      "username":vals.get("user",""),"password":vals.get("pass","")}
            if not config["login_url"]: log("[-] Enter login URL","err"); return
            result = run_full_audit(config, log_cb=log)
            if result.get("vulnerable_count",0) > 0:
                save_finding({"title":f"2FA Bypass: {config['login_url']}",
                              "url":config["login_url"],"type":"2FA Bypass",
                              "severity":"CRITICAL","cvss_score":"9.0",
                              "project":app.project.get() or "target",
                              "tool":"2FA Suite","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,
            "2FA BYPASS SUITE", "🔑",
            "OTP leakage in response · Rate limit check (no lockout?) · OTP reuse\n"
            "Response manipulation (success:false → true) · Backup code brute-force\n"
            "Any confirmed bypass → CRITICAL auto-saved to Findings",
            _run,
            fields=[("Login URL","login","",320),("Verify URL","verify","",320),
                    ("Username","user","admin",200),("Password","pass","",200)],
            btn_label="▶ Run Full 2FA Audit", color=C["yellow"])

    # ── HTTP SMUGGLING ────────────────────────────────────────────
    def _tab_smuggling(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "HTTP REQUEST SMUGGLING", "🔀", C["red"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["red"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Timing-based detection: CL.TE · TE.CL · 14 TE.TE variants\n"
            "Raw socket attack — probe takes 5+ sec = back-end waiting = VULNERABLE\n"
            "Bounties: $10,000–$50,000 · Also runs built-in smuggler.py"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        row = ctk.CTkFrame(pad); row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text="Host:",
                     font=F(10,mono=True), width=80, anchor="e").pack(side="left", padx=(0,8))
        self._smug_host = ctk.StringVar(value=self.project.get() or "")
        GlowEntry(row, textvariable=self._smug_host, width=280, height=32).pack(side="left")
        ctk.CTkLabel(row, text="  Port:", font=F(10,mono=True)).pack(side="left", padx=(12,8))
        self._smug_port = ctk.StringVar(value="443")
        ctk.CTkComboBox(row, variable=self._smug_port, values=["443","80","8080","8443"],
                        width=80, height=32, font=F(11,mono=True)).pack(side="left")
        ctk.CTkLabel(row, text="  Path:", font=F(10,mono=True)).pack(side="left", padx=(12,8))
        self._smug_path = ctk.StringVar(value="/")
        GlowEntry(row, textvariable=self._smug_path, width=150, height=32).pack(side="left")
        self._smug_tls = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(row, text="TLS", variable=self._smug_tls+"aa",
                        font=F(11)).pack(side="left", padx=12)

        self._smug_term = Terminal(pad, height=18)
        self._smug_term.pack(fill="both", expand=True, pady=(10,0))

        def _run_builtin():
            host = self._smug_host.get().strip()
            if not host: self.set_status("Enter host","red"); return
            port = int(self._smug_port.get())
            self._smug_term.clear()
            def _go():
                from modules.advanced.http_smuggling import full_smuggling_scan
                r = full_smuggling_scan(host, port, self._smug_path.get() or "/",
                                        self._smug_term.log)
                if r.get("vulnerable"):
                    save_finding({"title":f"HTTP Smuggling: {host}",
                                  "url":f"https://{host}{self._smug_path.get()}",
                                  "type":"HTTP Request Smuggling","severity":"CRITICAL",
                                  "cvss_score":"9.8","project":self.project.get() or host,
                                  "tool":"HTTP Smuggling","status":"Open"})
                    self.root.after(0, self._refresh_findings)
            threading.Thread(target=_go, daemon=True).start()

        def _run_smuggler_py():
            host = self._smug_host.get().strip()
            if not host: return
            tls = self._smug_tls.get()
            url = f"{'https' if tls else 'http'}://{host}{self._smug_path.get() or '/'}"
            self._smug_term.clear()
            def _go():
                import importlib.util
                from pathlib import Path
                sp = Path(__file__).parent.parent.parent.parent / "tools" / "smuggler.py"
                if not sp.exists(): self._smug_term.log("[-] tools/smuggler.py not found","err"); return
                spec = importlib.util.spec_from_file_location("smuggler",sp)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                r = mod.scan(url, log_fn=self._smug_term.log)
                if r.get("vulnerable"):
                    save_finding({"title":f"HTTP Smuggling (smuggler.py): {host}",
                                  "url":url,"type":"HTTP Request Smuggling",
                                  "severity":"CRITICAL","cvss_score":"9.8",
                                  "project":self.project.get() or host,"tool":"smuggler.py","status":"Open"})
                    self.root.after(0, self._refresh_findings)
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="🔍 Auto-Detect", command=_run_builtin, color=C["red"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="🐍 smuggler.py", command=_run_smuggler_py,
                   color=C["purple"], small=True).pack(side="left", padx=8)

    # ── WEB SCANNERS (Prototype Pollution, Cache, CORS, Redirect, NoSQL, WebSocket, XXE) ──
    def _tab_proto_poll(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import scan_prototype_pollution
            url = vals.get("url","")
            if not url: log("[-] Enter URL","err"); return
            r = scan_prototype_pollution(url, log_cb=log)
            if r.get("vulnerable"):
                save_finding({"title":f"Prototype Pollution: {url}","url":url,
                              "type":"Prototype Pollution","severity":"HIGH","cvss_score":"7.5",
                              "project":app.project.get() or "target","tool":"Proto Scanner","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"PROTOTYPE POLLUTION SCANNER","🧬",
            "__proto__ / constructor.prototype injection · GET params + POST body\n"
            "Node.js server-side prototype pollution → RCE possible",
            _run, fields=[("Target URL","url","",420)], btn_label="▶ Scan", color=C["purple"])

    def _tab_cache_poison(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import scan_cache_poisoning
            r = scan_cache_poisoning(vals.get("url",""), log_cb=log)
            if r.get("vulnerable"):
                save_finding({"title":f"Cache Poisoning: {vals['url']}","url":vals["url"],
                              "type":"Cache Poisoning","severity":"HIGH","cvss_score":"7.5",
                              "project":app.project.get() or "target","tool":"Cache Scanner","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"CACHE POISONING TESTER","🌊",
            "Unkeyed headers: X-Forwarded-Host · X-Host · X-Forwarded-Server\n"
            "Fat GET injection · Reflected headers in cached response",
            _run, fields=[("Target URL","url","",420)], btn_label="▶ Test Cache", color=C["orange"])

    def _tab_cors(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import scan_cors
            r = scan_cors(vals.get("url",""), log_cb=log)
            for f in r.get("findings",[]):
                save_finding({"title":f"CORS: {f.get('issue','')}","url":vals["url"],
                              "type":"CORS Misconfiguration","severity":f.get("severity","HIGH"),
                              "project":app.project.get() or "target","tool":"CORS Scanner","status":"Open"})
            if r.get("findings"): app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"CORS EXPLOIT CHAIN","🔓",
            "Tests: wildcard * · reflected origin · null origin bypass\n"
            "Checks: Access-Control-Allow-Credentials: true (CRITICAL when combined)\n"
            "Generates full PoC exploit code",
            _run, fields=[("Target URL","url","",420)], btn_label="▶ Test CORS", color=C["accent"])

    def _tab_redirect(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import scan_open_redirect
            r = scan_open_redirect(vals.get("url",""), log_cb=log)
            if r.get("vulnerable"):
                save_finding({"title":f"Open Redirect: {vals['url']}","url":vals["url"],
                              "type":"Open Redirect","severity":"MEDIUM","cvss_score":"6.1",
                              "project":app.project.get() or "target","tool":"Redirect Scanner","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"OPEN REDIRECT SCANNER","↪️",
            "Tests 18 redirect params × 14 bypass techniques\n"
            "URL encoding · path confusion · javascript: · data: URI bypass",
            _run, fields=[("Target URL","url","",420)], btn_label="▶ Scan Redirects", color=C["yellow"])

    def _tab_nosql(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import scan_nosql
            r = scan_nosql(vals.get("url",""), endpoint=vals.get("ep","/api/login"), log_cb=log)
            if r.get("vulnerable"):
                save_finding({"title":f"NoSQL Injection: {vals['url']}","url":vals["url"],
                              "type":"NoSQL Injection","severity":"CRITICAL","cvss_score":"9.0",
                              "project":app.project.get() or "target","tool":"NoSQL Scanner","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"NOSQL INJECTION SUITE","💉",
            "MongoDB $ne/$gt/$regex login bypass · Time-based blind detection\n"
            "Data extraction via $or/$in/$where operators",
            _run, fields=[("Target URL","url","",340),("API Endpoint","ep","/api/login",180)],
            btn_label="▶ Test NoSQL", color=C["red"])

    def _tab_websocket(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import test_websocket
            url = vals.get("url","")
            if not url.startswith("ws"): url = "wss://" + url.replace("https://","").replace("http://","")
            r = test_websocket(url, log_cb=log)
            if r.get("vulnerable"):
                save_finding({"title":f"WebSocket Issue: {url}","url":url,
                              "type":"WebSocket Security","severity":"HIGH",
                              "project":app.project.get() or "target","tool":"WS Tester","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"WEBSOCKET SECURITY TESTER","🔌",
            "WebSocket handshake · Message injection (SQLi, XSS, Prototype Pollution)\n"
            "Error/info leakage in WS responses · CSWSH detection",
            _run, fields=[("WebSocket URL (ws:// or wss://)","url","",380)],
            btn_label="▶ Test WebSocket", color=C["accent"])

    def _tab_xxe(self, frame):
        def _run(vals, log, stop, app):
            from modules.advanced.web_scanners import scan_xxe
            r = scan_xxe(vals.get("url",""), oast_host=vals.get("oast",""), log_cb=log)
            if r.get("vulnerable"):
                save_finding({"title":f"XXE: {vals['url']}","url":vals["url"],
                              "type":"XXE Injection","severity":"CRITICAL","cvss_score":"9.1",
                              "project":app.project.get() or "target","tool":"XXE Scanner","status":"Open"})
                app.root.after(0, app._refresh_findings)
        self._mk_power_tab(frame,"XXE AUTO-EXPLOITER","📄",
            "File read: /etc/passwd · /windows/win.ini · PHP filter\n"
            "OOB DNS/HTTP via OAST · Billion laughs DoS · SSRF via XXE",
            _run, fields=[("Target URL","url","",320),("OAST Host","oast","",220)],
            btn_label="▶ Test XXE", color=C["red"])

    # Standalone OAuth ATO tab (also accessible via JWT/OAuth tab)
    def _tab_oauth_ato_standalone(self, frame):
        frame.configure(fg_color=C["bg_app"])
        pad = ctk.CTkScrollableFrame(frame, fg_color="transparent",
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "OAUTH ACCOUNT TAKEOVER AUTO-TESTER", "🔗", C["purple"]).pack(fill="x", pady=(0,10))
        info = Card(pad, accent=C["purple"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Tests: CSRF (missing state) · redirect_uri bypass · PKCE downgrade · implicit flow\n"
            "Generates 6 attack URLs: open redirect · subdomain · scope escalation...\n"
            "Paste the full OAuth /authorize URL to test"
        ), text_color=C["text_muted"], font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        ctk.CTkLabel(pad, text="OAuth Authorization URL (full URL with params):",
                     text_color=C["text_muted"], font=F(10, mono=True), anchor="w").pack(anchor="w", pady=(8,4))
        oauth_txt = ctk.CTkTextbox(pad, height=80, fg_color=C["bg_input"],
                                    border_color=C["border"], text_color=C["accent"],
                                    font=F(10, mono=True), border_width=1)
        oauth_txt.pack(fill="x", pady=(0,8))
        oauth_txt.insert("0.0","https://auth.example.com/oauth/authorize?client_id=APP_ID&redirect_uri=https://app.com/callback&response_type=code&scope=openid+email&state=RANDOM_STATE")

        term = Terminal(pad, height=16)
        term.pack(fill="both", expand=True, pady=(0,8))

        attack_url_scroll = ctk.CTkScrollableFrame(pad, fg_color=C["bg_panel"],
                                                    border_color=C["border"], border_width=1,
                                                    corner_radius=6, height=120,
                                                    scrollbar_button_color=C["bg_hover"],
                                                    scrollbar_button_hover_color=C["accent"])
        attack_url_scroll.pack(fill="x", pady=(0,8))
        ctk.CTkLabel(attack_url_scroll, text="Attack URLs (double-click to copy):",
                     text_color=C["accent"], font=F(9, bold=True, mono=True), anchor="w").pack(anchor="w", padx=8, pady=(6,2))
        self._oauth_atk_rows = []

        def _run():
            url = oauth_txt.get("0.0","end").strip()
            if not url or not url.startswith("http"):
                self.set_status("Paste a full OAuth URL","red"); return
            term.clear()
            for w in attack_url_scroll.winfo_children()[1:]: w.destroy()
            def _go():
                from modules.advanced.web_scanners import test_oauth_ato
                from app.core.database import save_finding
                r = test_oauth_ato(url, log_cb=term.log)
                def _upd():
                    for name, aurl in r.get("attack_urls",{}).items():
                        row = ctk.CTkFrame(attack_url_scroll, fg_color="transparent", cursor="hand2")
                        row.pack(fill="x", padx=4, pady=1)
                        ctk.CTkLabel(row, text=f"{name}:", text_color=C["yellow"],
                                     font=F(8,bold=True,mono=True), width=140).pack(side="left")
                        ctk.CTkLabel(row, text=aurl[:80], text_color=C["text"],
                                     font=F(8,mono=True), anchor="w").pack(side="left", fill="x")
                        def _copy(u=aurl):
                            self.root.clipboard_clear(); self.root.clipboard_append(u); self.root.update()
                            self.set_status("URL copied!",C["green"])
                        for w in [row]: w.bind("<Double-1>", lambda e,fn=_copy: fn())
                    if r.get("vulnerable"):
                        for f in r.get("findings",[]):
                            save_finding({"title":f"OAuth: {f.get('type','')}","url":url,
                                          "type":"OAuth Misconfiguration","severity":f.get("severity","HIGH"),
                                          "project":self.project.get() or "target","tool":"OAuth ATO","status":"Open"})
                        self._refresh_findings()
                        self.set_status(f"OAuth issues found: {len(r['findings'])}",C["red"])
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad, fg_color="transparent"); btn_row.pack(fill="x")
        FilledButton(btn_row, text="🔗 Test OAuth Flow", command=_run, color=C["purple"]).pack(side="left", ipady=4)
