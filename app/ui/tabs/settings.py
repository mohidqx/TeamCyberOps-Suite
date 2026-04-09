import subprocess
import shutil
import threading
"""TeamCyberOps V5 — Settings, Wordlists, Tool Installer"""
import customtkinter as ctk, threading, subprocess, shutil
from pathlib import Path
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry
from app.core.config import cfg
from app.core.database import set_config


class SettingsMixin:

    def _tab_settings(self, frame):
        frame.configure()
        scroll = ctk.CTkScrollableFrame(frame,
                                         scrollbar_button_color=C["bg_hover"],
                                         scrollbar_button_hover_color=C["accent"])
        scroll.pack(fill="both", expand=True, padx=20, pady=14)
        Section(scroll, "SETTINGS & API KEYS", "⚙️", C["text_muted"]).pack(fill="x", pady=(0,12))

        # ── API Keys ──────────────────────────────────────────────
        api_card = Card(scroll, accent=C["accent"]); api_card.pack(fill="x", pady=(0,14))
        ctk.CTkLabel(api_card, text="  API KEYS",
                     font=F(11, bold=True, mono=True), anchor="w").pack(anchor="w", padx=14, pady=(10,6))

        api_fields = [
            ("Gemini API Key",       "gemini_api_key",   "Free at: aistudio.google.com",          True),
            ("Claude API Key",       "claude_api_key",   "console.anthropic.com",                 True),
            ("Shodan API Key",       "shodan",           "shodan.io/account",                     True),
            ("Censys API ID",        "censys_id",        "censys.io → Account → API",             False),
            ("Censys API Secret",    "censys_secret",    "censys.io → Account → API",             True),
            ("GitHub Token",         "github_token",     "github.com → Settings → Tokens",        True),
            ("Hunter.io API Key",    "hunter",           "hunter.io/api-keys",                    True),
            ("VirusTotal API Key",   "virustotal",       "virustotal.com/gui/my-apikey",           True),
            ("NVD API Key",          "nvd_api_key",      "nvd.nist.gov/developers/request-an-api-key", True),
        ]
        self._api_vars = {}
        for label, key, hint, secret in api_fields:
            row = ctk.CTkFrame(api_card); row.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(row, text=label+":",
                         font=F(10, mono=True), width=160, anchor="e").pack(side="left", padx=(0,8))
            v = ctk.StringVar(value=cfg.get_api_key(key))
            e = GlowEntry(row, textvariable=v, show="●" if secret else "", width=340, height=30)
            e.pack(side="left")
            if secret:
                def _toggle(entry=e, var=v, shown=[False]):
                    shown[0] = not shown[0]
                    entry.configure(show="" if shown[0] else "●")
                NeonButton(row, text="👁", command=_toggle, color=C["text_dim"],
                           small=True, width=32).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=hint,
                         font=F(8)).pack(side="left", padx=8)
            self._api_vars[key] = v

        def _save_keys():
            for key, v in self._api_vars.items():
                val = v.get().strip()
                if val: cfg.set_api_key(key, val)
            self.set_status("API keys saved!",C["green"])

        FilledButton(api_card, text="💾 Save All API Keys", command=_save_keys,
                     color=C["green"]).pack(anchor="w", padx=14, pady=(8,14))

        # ── Proxy ─────────────────────────────────────────────────
        proxy_card = Card(scroll, accent=C["yellow"]); proxy_card.pack(fill="x", pady=(0,14))
        ctk.CTkLabel(proxy_card, text="  PROXY (Burp Suite / OWASP ZAP)", font=F(11, bold=True, mono=True), anchor="w").pack(
            anchor="w", padx=14, pady=(10,6))
        pr = ctk.CTkFrame(proxy_card); pr.pack(fill="x", padx=14, pady=(0,4))
        self._proxy_enabled = ctk.BooleanVar(value=cfg.get("proxy.enabled", False))
        ctk.CTkSwitch(pr, text="Enable Proxy", variable=self._proxy_enabled, progress_color=C["yellow"],
                      font=F(11)).pack(side="left")
        pr2 = ctk.CTkFrame(proxy_card); pr2.pack(fill="x", padx=14, pady=4)
        self._proxy_host = ctk.StringVar(value=cfg.get("proxy.host","127.0.0.1"))
        self._proxy_port = ctk.StringVar(value=cfg.get("proxy.port","8080"))
        for lbl, var, w in [("Host:", self._proxy_host, 200),("Port:", self._proxy_port, 80)]:
            ctk.CTkLabel(pr2, text=lbl, font=F(10,mono=True)).pack(side="left")
            GlowEntry(pr2, textvariable=var, width=w, height=28).pack(side="left", padx=(4,12))

        def _save_proxy():
            cfg.set("proxy.enabled", self._proxy_enabled.get())
            cfg.set("proxy.host", self._proxy_host.get())
            cfg.set("proxy.port", self._proxy_port.get())
            self.set_status("Proxy settings saved",C["yellow"])

        FilledButton(proxy_card, text="💾 Save Proxy", command=_save_proxy,
                     color=C["yellow"]).pack(anchor="w", padx=14, pady=(0,14))

        # ── Scan Settings ──────────────────────────────────────────
        scan_card = Card(scroll, accent=C["accent"]); scan_card.pack(fill="x", pady=(0,14))
        ctk.CTkLabel(scan_card, text="  SCAN SETTINGS", font=F(11, bold=True, mono=True), anchor="w").pack(
            anchor="w", padx=14, pady=(10,6))
        sc = ctk.CTkFrame(scan_card); sc.pack(fill="x", padx=14, pady=(0,4))
        self._sc_threads = ctk.StringVar(value=str(cfg.get("scan.threads", 50)))
        self._sc_timeout = ctk.StringVar(value=str(cfg.get("scan.timeout", 10)))
        for lbl, var, hint in [
            ("Threads:", self._sc_threads, "Default: 50"),
            ("  Timeout (s):", self._sc_timeout, "Default: 10"),
        ]:
            ctk.CTkLabel(sc, text=lbl, font=F(10,mono=True)).pack(side="left")
            GlowEntry(sc, textvariable=var, width=70, height=28).pack(side="left", padx=(4,0))
            ctk.CTkLabel(sc, text=hint, font=F(8)).pack(side="left", padx=(6,16))

        def _save_scan():
            try:
                cfg.set("scan.threads", int(self._sc_threads.get()))
                cfg.set("scan.timeout", int(self._sc_timeout.get()))
                self.set_status("Scan settings saved",C["accent"])
            except ValueError:
                self.set_status("Invalid values","red")

        FilledButton(scan_card, text="💾 Save", command=_save_scan,
                     color=C["accent"]).pack(anchor="w", padx=14, pady=(0,14))

        # ── Notifications ─────────────────────────────────────────
        notif_card = Card(scroll, accent=C["purple"]); notif_card.pack(fill="x", pady=(0,14))
        ctk.CTkLabel(notif_card, text="  NOTIFICATIONS (Telegram / Discord)", font=F(11, bold=True, mono=True), anchor="w").pack(
            anchor="w", padx=14, pady=(10,6))
        self._notif_vars = {}
        for label, key in [
            ("Telegram Bot Token", "telegram_token"),
            ("Telegram Chat ID",   "telegram_chat_id"),
            ("Discord Webhook",    "discord_webhook"),
        ]:
            row = ctk.CTkFrame(notif_card); row.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(row, text=label+":",
                         font=F(10,mono=True), width=180, anchor="e").pack(side="left", padx=(0,8))
            v = ctk.StringVar(value=cfg.get(f"notifications.{key}",""))
            GlowEntry(row, textvariable=v, show="●", width=340, height=30).pack(side="left")
            self._notif_vars[key] = v

        def _test_telegram():
            token = self._notif_vars.get("telegram_token",ctk.StringVar()).get()
            chat  = self._notif_vars.get("telegram_chat_id",ctk.StringVar()).get()
            if not token or not chat: self.set_status("Enter Telegram token + chat ID","red"); return
            def _go():
                import urllib.request as _ur
                try:
                    url  = f"https://api.telegram.org/bot{token}/sendMessage"
                    data = f"chat_id={chat}&text=TeamCyberOps+V5+%E2%80%94+Notifications+working!".encode()
                    _ur.urlopen(url, data=data, timeout=10)
                    self.root.after(0, lambda: self.set_status("Telegram test sent!",C["green"]))
                except Exception as e:
                    self.root.after(0, lambda: self.set_status(f"Telegram error: {e}",C["red"]))
            threading.Thread(target=_go, daemon=True).start()

        def _save_notif():
            for key, v in self._notif_vars.items():
                cfg.set(f"notifications.{key}", v.get().strip())
            self.set_status("Notifications saved",C["purple"])

        nb_row = ctk.CTkFrame(notif_card); nb_row.pack(anchor="w", padx=14, pady=(4,14))
        FilledButton(nb_row, text="💾 Save", command=_save_notif, color=C["purple"]).pack(side="left", ipady=2)
        NeonButton(nb_row, text="📱 Test Telegram", command=_test_telegram,
                   color=C["accent"], small=True).pack(side="left", padx=8)

    def _tab_wordlists(self, frame):
        frame.configure()
        scroll = ctk.CTkScrollableFrame(frame,
                                         scrollbar_button_color=C["bg_hover"],
                                         scrollbar_button_hover_color=C["accent"])
        scroll.pack(fill="both", expand=True, padx=20, pady=14)
        Section(scroll, "WORDLIST MANAGER", "📦", C["yellow"]).pack(fill="x", pady=(0,12))

        wl_dir = Path("wordlists"); wl_dir.mkdir(exist_ok=True)
        wl_files = list(wl_dir.glob("*.txt"))
        info = Card(scroll, accent=C["yellow"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=f"Wordlists directory: {wl_dir.absolute()}\nFiles found: {len(wl_files)}", font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        for wf in sorted(wl_files):
            try:
                sz = wf.stat().st_size
                lc = len(wf.read_text(errors="replace").splitlines())
                row = ctk.CTkFrame(scroll); row.pack(fill="x", pady=3)
                ctk.CTkLabel(row, text=wf.name,
                             font=F(11,mono=True), anchor="w").pack(side="left", padx=14, pady=8)
                ctk.CTkLabel(row, text=f"{lc:,} lines  {sz//1024}KB", font=F(9,mono=True)).pack(side="right", padx=14)
            except Exception: pass

        # Wordlist config paths
        Section(scroll, "CONFIGURE PATHS", "🔗", C["accent"]).pack(fill="x", pady=(14,8))
        self._wl_path_vars = {}
        for label, key in [
            ("Directories", "directories"),
            ("Subdomains",  "subdomains"),
            ("Passwords",   "passwords"),
            ("Parameters",  "parameters"),
        ]:
            row = ctk.CTkFrame(scroll); row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label+":",
                         font=F(10,mono=True), width=120, anchor="e").pack(side="left", padx=(0,8))
            v = ctk.StringVar(value=cfg.get_wordlist(key) or f"wordlists/{key}.txt")
            GlowEntry(row, textvariable=v, width=380, height=30).pack(side="left")
            self._wl_path_vars[key] = v

        def _save_paths():
            for key, v in self._wl_path_vars.items():
                cfg.set(f"wordlists.{key}", v.get().strip())
            self.set_status("Wordlist paths saved",C["green"])
        FilledButton(scroll, text="💾 Save Paths", command=_save_paths, color=C["accent"]).pack(
            anchor="w", pady=(8,0))

    def _tab_tools(self, frame):
        frame.configure()
        scroll = ctk.CTkScrollableFrame(frame,
                                         scrollbar_button_color=C["bg_hover"],
                                         scrollbar_button_hover_color=C["accent"])
        scroll.pack(fill="both", expand=True, padx=20, pady=14)
        Section(scroll, "TOOL INSTALLER", "🔧", C["accent"]).pack(fill="x", pady=(0,12))

        info = Card(scroll, accent=C["accent"]); info.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(info, text=(
            "Install recommended tools for maximum capability\n"
            "Python fallbacks are available for all tools — but installed tools are much faster"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        tools = [
            # (name, check_cmd, install_cmd, description)
            ("subfinder",    "subfinder",    "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",  "Subdomain enumeration — Go"),
            ("httpx",        "httpx",        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",             "HTTP probing — Go"),
            ("nuclei",       "nuclei",       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",        "Vulnerability scanner — Go"),
            ("katana",       "katana",       "go install github.com/projectdiscovery/katana/cmd/katana@latest",           "Web crawler — Go"),
            ("dnsx",         "dnsx",         "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",               "DNS resolver — Go"),
            ("gau",          "gau",          "go install github.com/lc/gau/v2/cmd/gau@latest",                           "URL fetcher — Go"),
            ("dalfox",       "dalfox",       "go install github.com/hahwul/dalfox/v2@latest",                            "XSS scanner — Go"),
            ("ffuf",         "ffuf",         "go install github.com/ffuf/ffuf/v2@latest",                                 "Web fuzzer — Go"),
            ("amass",        "amass",        "go install github.com/owasp-amass/amass/v4/...@master",                     "Subdomain enum — Go"),
            ("nmap",         "nmap",         "apt install -y nmap",                                                        "Port scanner — apt"),
            ("nikto",        "nikto",        "apt install -y nikto",                                                       "Web scanner — apt"),
            ("sqlmap",       "sqlmap",       "apt install -y sqlmap",                                                      "SQLi scanner — apt"),
            ("tor",          "tor",          "apt install -y tor",                                                         "Tor anonymity — apt"),
            ("waybackurls",  "waybackurls",  "go install github.com/tomnomnom/waybackurls@latest",                        "Wayback URLs — Go"),
        ]

        self._tool_status = {}
        log_txt = Terminal(scroll, height=10)
        log_txt.pack(fill="x", pady=(0,8))

        for name, check, install, desc in tools:
            installed = shutil.which(check) is not None
            row = ctk.CTkFrame(scroll)
            row.pack(fill="x", pady=3)
            dot_c = C["green"] if installed else C["text_dim"]
            dot_t = "✅" if installed else "○"
            status_lbl = ctk.CTkLabel(row, text=dot_t, text_color=dot_c,
                                       font=F(12), width=28)
            status_lbl.pack(side="left", padx=(10,6), pady=8)
            ctk.CTkLabel(row, text=name if installed else C["text_muted"],
                         font=F(11, bold=True, mono=True), width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=desc,
                         font=F(9), anchor="w").pack(side="left", fill="x", expand=True)
            self._tool_status[name] = (status_lbl, installed)

            if not installed:
                def _install(n=name, cmd=install, lbl=status_lbl):
                    log_txt.log(f"[*] Installing {n}...","info")
                    def _go():
                        try:
                            parts = cmd.split()
                            r = subprocess.run(parts, capture_output=True, text=True, timeout=300)
                            ok = shutil.which(n) is not None
                            def _upd():
                                lbl.configure(text="✅" if ok else "❌" if ok else C["red"])
                                log_txt.log(f"[{'✓' if ok else '✗'}] {n}: {'installed' if ok else r.stderr[:100]}",
                                            "ok" if ok else "err")
                            self.root.after(0, _upd)
                        except Exception as e:
                            self.root.after(0, lambda: log_txt.log(f"[-] {n} error: {e}","err"))
                    threading.Thread(target=_go, daemon=True).start()
                NeonButton(row, text="📥 Install", command=_install,
                           color=C["accent"], small=True).pack(side="right", padx=10)

        def _check_all():
            for name, (lbl, _) in self._tool_status.items():
                installed = shutil.which(name) is not None
                lbl.configure(text="✅" if installed else "○" if installed else C["text_dim"])
            self.set_status("Tool check done",C["green"])

        NeonButton(scroll, text="🔄 Re-check All Tools", command=_check_all,
                   color=C["text_muted"], small=True).pack(anchor="w", pady=(8,0))
