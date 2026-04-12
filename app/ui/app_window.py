"""
TeamCyberOps V5 — Main Application Window
v5.0.2: Sidebar height fix, Tcl bgerror suppressed, logs/projects sync
"""
import customtkinter as ctk
import threading
import traceback
from app.ui.theme import C, F, NeonButton, FilledButton, GlowEntry, CAT_COLORS
from app.core.database import (get_projects, create_project,
                                 update_project_active, sync_logs_to_projects)
from app.core.config import cfg

TABS = [
    ("MAIN",    "Dashboard",       "_tab_dashboard"),
    ("MAIN",    "Projects",        "_tab_projects"),
    ("MAIN",    "Live Monitor",    "_tab_live_monitor"),
    ("RECON",   "Auto-Recon",      "_tab_auto_recon"),
    ("RECON",   "Passive Recon",   "_tab_passive_recon"),
    ("RECON",   "Active Recon",    "_tab_active_recon"),
    ("RECON",   "Tor Recon",       "_tab_tor_recon"),
    ("RECON",   "URL Discovery",   "_tab_url_discovery"),
    ("RECON",   "Dorks",           "_tab_dorks"),
    ("RECON",   "Origin Hunter",   "_tab_origin_hunter"),
    ("SCAN",    "Vuln Scanner",    "_tab_vuln_scanner"),
    ("SCAN",    "Nuclei Mgr",      "_tab_nuclei_mgr"),
    ("SCAN",    "Analysis",        "_tab_analysis"),
    ("SCAN",    "CVE Intel",       "_tab_cve_intel"),
    ("SCAN",    "Shodan Exploit",  "_tab_shodan_exploit"),
    ("SCAN",    "Mass Scanner",    "_tab_mass_scanner"),
    ("EXPLOIT", "Exploitation",    "_tab_exploitation"),
    ("EXPLOIT", "Payload Mgr",     "_tab_payload_mgr"),
    ("EXPLOIT", "Chain Builder",   "_tab_chain_builder"),
    ("POWER",   "OAST Server",     "_tab_oast"),
    ("POWER",   "JWT / OAuth",     "_tab_jwt_oauth"),
    ("POWER",   "Race Condition",  "_tab_race"),
    ("POWER",   "GraphQL",         "_tab_graphql"),
    ("POWER",   "SSRF Suite",      "_tab_ssrf"),
    ("POWER",   "2FA Bypass",      "_tab_mfa"),
    ("POWER",   "HTTP Smuggling",  "_tab_smuggling"),
    ("POWER",   "Proto Pollution", "_tab_proto_poll"),
    ("POWER",   "Cache Poison",    "_tab_cache_poison"),
    ("POWER",   "CORS Exploit",    "_tab_cors"),
    ("POWER",   "Open Redirect",   "_tab_redirect"),
    ("POWER",   "NoSQL Inject",    "_tab_nosql"),
    ("POWER",   "WebSocket",       "_tab_websocket"),
    ("POWER",   "XXE Exploiter",   "_tab_xxe"),
    ("POWER",   "OAuth ATO",       "_tab_oauth_ato_standalone"),
    ("INTEL",   "OSINT",           "_tab_osint"),
    ("INTEL",   "S3 Bucket Hunt",  "_tab_s3"),
    ("INTEL",   "Subdomain TKO",   "_tab_subdomain_tko"),
    ("INTEL",   "Param Mining",    "_tab_param_mining"),
    ("INTEL",   "Cred Stuffing",   "_tab_cred_stuffing"),
    ("INTEL",   "JWT Wordlist",    "_tab_jwt_wordlist"),
    ("INTEL",   "SAST Scanner",    "_tab_sast"),
    ("INTEL",   "API Tester",      "_tab_api_tester"),
    ("RESULTS", "Findings",        "_tab_findings"),
    ("RESULTS", "Results",         "_tab_results"),
    ("RESULTS", "Reports",         "_tab_reports"),
    ("AI",      "AI Assistant",    "_tab_ai_assistant"),
    ("AI",      "AI Auto-Exploit", "_tab_ai_exploit"),
    ("AI",      "Smart Reporter",  "_tab_smart_reporter"),
    ("AI",      "Nuclei AI Gen",   "_tab_nuclei_ai"),
    ("SYSTEM",  "Settings",        "_tab_settings"),
    ("SYSTEM",  "Wordlists",       "_tab_wordlists"),
    ("SYSTEM",  "Tool Installer",  "_tab_tools"),
]

# ── Sidebar row height ────────────────────────────────────────────
# Single source of truth — change this to resize all sidebar rows
_SB_ROW_H = 26   # pixels per tab row (fit-to-text)
_SB_FONT  = 11   # sidebar font size


class AppWindow:
    def __init__(self, user: dict):
        self.user        = user
        self._tab_frames = {}
        self._sb_rows    = []
        self._cur_idx    = -1
        self._cur_frame  = None

        # ── CRITICAL ORDER: root first, then StringVar ────────────
        self.root = ctk.CTk()
        self.root.title(f"TeamCyberOps V5  //  {user['username'].upper()}")
        self.root.configure(fg_color=C["bg_app"])
        self.root.minsize(1280, 720)

        self.project = ctk.StringVar(value="")

        try:    self.root.state("zoomed")
        except Exception:
            try:    self.root.attributes("-zoomed", True)
            except Exception: self.root.geometry("1440x860")

        # ── Suppress Tcl background errors at the Tcl interpreter level ──
        # This catches "invalid command name NNNupdate" + "check_dpi_scaling"
        # before they ever reach Python/stderr.
        try:
            self.root.tk.eval("""
                proc bgerror {msg} {
                    global errorInfo
                    if {[string match "*invalid command name*" $msg]} { return }
                    if {[string match "*check_dpi*" $msg]}           { return }
                    if {[string match "*update*" $msg] &&
                        [string match "*after*" $errorInfo]}         { return }
                    catch {puts stderr "TCL bgerror: $msg"}
                }
            """)
        except Exception:
            pass

        # Sync logs folder → DB projects (background, non-blocking)
        threading.Thread(target=self._sync_projects, daemon=True).start()

        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._switch_to(0)
        self.root.mainloop()

    def _sync_projects(self):
        """Scan logs/ folder and register any missing projects into DB."""
        try:
            sync_logs_to_projects()
            # Refresh combo after sync
            self.root.after(800, self._refresh_project_combo)
        except Exception:
            pass

    def _refresh_project_combo(self):
        try:
            names = self._get_proj_names()
            self._proj_combo.configure(values=names)
            if names and not self.project.get():
                self.project.set(names[0])
        except Exception:
            pass

    def _on_close(self):
        """Clean shutdown — cancel pending after() then destroy."""
        try:
            for after_id in self.root.tk.eval('after info').split():
                try: self.root.after_cancel(after_id)
                except Exception: pass
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def _build(self):
        ctk.CTkFrame(self.root, height=2, fg_color=C["accent"],
                     corner_radius=0).pack(fill="x", side="top")
        self._build_topbar()
        self._build_statusbar()
        body = ctk.CTkFrame(self.root, fg_color="transparent")
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)
        self._build_content(body)

    # ── TOP BAR ───────────────────────────────────────────────────
    def _build_topbar(self):
        bar = ctk.CTkFrame(self.root, height=48,
                           fg_color=C["bg_panel"], corner_radius=0)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        ctk.CTkFrame(bar, height=1, fg_color=C["border_accent"],
                     corner_radius=0).place(relx=0, rely=1,
                                            relwidth=1, anchor="sw")

        from pathlib import Path
        logo_path = Path(__file__).parent / "org_logo.jpg"
        if not logo_path.exists():
            logo_path = Path(__file__).parent / "org_logo.png"
        if logo_path.exists():
            try:
                from PIL import Image
                img = Image.open(logo_path)
                w, h = img.size; s = min(w, h)
                img = img.crop(((w-s)//2,(h-s)//2,(w+s)//2,(h+s)//2))
                img = img.resize((30, 30), Image.LANCZOS)
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(30,30))
                ctk.CTkLabel(bar, image=ctk_img, text="",
                             width=34).pack(side="left", padx=(10, 0))
            except Exception:
                pass

        wm = ctk.CTkFrame(bar, fg_color="transparent")
        wm.pack(side="left", padx=(6, 0))
        ctk.CTkLabel(wm, text="TeamCyberOps", text_color=C["accent"],
                     font=F(13, bold=True)).pack(side="left")
        ctk.CTkLabel(wm, text="  v5", text_color=C["text_dim"],
                     font=F(10, mono=True)).pack(side="left")

        ctk.CTkFrame(bar, width=1, fg_color=C["border_mid"]
                     ).pack(side="left", fill="y", pady=10, padx=10)

        pf = ctk.CTkFrame(bar, fg_color="transparent")
        pf.pack(side="left")
        ctk.CTkLabel(pf, text="PROJECT:", text_color=C["text_dim"],
                     font=F(7, bold=True, mono=True)).pack(anchor="w")
        pr = ctk.CTkFrame(pf, fg_color="transparent")
        pr.pack()
        self._proj_combo = ctk.CTkComboBox(
            pr, variable=self.project,
            values=self._get_proj_names(),
            width=210, height=26,
            fg_color=C["bg_input"],
            border_color=C["border_mid"], border_width=1,
            button_color=C["bg_hover"],
            button_hover_color=C["accent"],
            dropdown_fg_color=C["bg_card"],
            dropdown_hover_color=C["bg_hover"],
            text_color=C["text"],
            font=F(11, mono=True),
            corner_radius=3,
            command=lambda v=None: self._on_project_change())
        self._proj_combo.pack(side="left")
        NeonButton(pr, text="+", command=self._new_project,
                   color=C["green"], small=True,
                   width=26, height=26).pack(side="left", padx=(3, 0))

        ctk.CTkFrame(bar, width=1, fg_color=C["border_mid"]
                     ).pack(side="right", fill="y", pady=10, padx=8)
        uf = ctk.CTkFrame(bar, fg_color="transparent")
        uf.pack(side="right", padx=8)
        role_c = C["accent"] if self.user.get("role") == "admin" else C["green"]
        ctk.CTkLabel(uf, text=f"[{self.user['username'].upper()}]",
                     text_color=role_c,
                     font=F(10, bold=True, mono=True)).pack()

        for label, cmd, color in [
            ("[SETTINGS]", lambda: self.goto_tab("Settings"), C["text_muted"]),
            ("[LOGOUT]",   self._on_close,                    C["red"]),
        ]:
            NeonButton(bar, text=label, command=cmd, color=color,
                       small=True).pack(side="right", padx=4, pady=9)

    # ── STATUS BAR ────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self.root, height=30,
                           fg_color=C["bg_panel"], corner_radius=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        ctk.CTkFrame(bar, height=1, fg_color=C["border_red"],
                     corner_radius=0).pack(fill="x", side="top")

        self._status_var = ctk.StringVar(value="  >>  READY")
        self._status_lbl = ctk.CTkLabel(
            bar, textvariable=self._status_var,
            text_color=C["accent"], font=F(10, mono=True), anchor="w")
        self._status_lbl.pack(side="left", padx=10)

        import sys
        ctk.CTkLabel(bar,
                     text=f"Python {sys.version[:6]}  |  SQLite  |  Gemini AI  |  TCO v5.0.2",
                     text_color=C["text_dim"], font=F(9)
                     ).pack(side="right", padx=10)
        self._ip_lbl = ctk.CTkLabel(bar, text="",
                                     text_color=C["text_dim"], font=F(9))
        self._ip_lbl.pack(side="right", padx=8)
        threading.Thread(target=self._fetch_ip, daemon=True).start()

    # ── SIDEBAR ───────────────────────────────────────────────────
    def _build_sidebar(self, parent):
        sb = ctk.CTkFrame(parent, width=210,
                          fg_color=C["bg_sidebar"],
                          border_width=0, corner_radius=0)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)
        ctk.CTkFrame(sb, width=1, fg_color=C["border_accent"],
                     corner_radius=0).pack(side="right", fill="y")

        # Header
        ctk.CTkLabel(sb, text="  \u25a0 NAVIGATION",
                     text_color=C["text_dim"],
                     font=F(8, bold=True, mono=True),
                     anchor="w").pack(fill="x", padx=6, pady=(6, 2))
        ctk.CTkFrame(sb, height=1, fg_color=C["border_mid"],
                     corner_radius=0).pack(fill="x", padx=6)

        # Search
        sf = ctk.CTkFrame(sb, fg_color="transparent")
        sf.pack(fill="x", padx=6, pady=(5, 3))
        self._sb_q = ctk.StringVar()
        ctk.CTkEntry(sf, textvariable=self._sb_q,
                     placeholder_text="// search...",
                     fg_color=C["bg_input"],
                     border_color=C["border_mid"], border_width=1,
                     text_color=C["text"],
                     placeholder_text_color=C["text_dim"],
                     font=F(9, mono=True), height=24,
                     corner_radius=3).pack(fill="x")
        self._sb_q.trace_add("write", self._filter_sidebar)

        # Scrollable list
        self._sb_scroll = ctk.CTkScrollableFrame(
            sb, fg_color="transparent",
            scrollbar_button_color=C["bg_hover"],
            scrollbar_button_hover_color=C["accent"])
        self._sb_scroll.pack(fill="both", expand=True)

        last_cat = None
        for i, (cat, name, _) in enumerate(TABS):
            cat_c = CAT_COLORS.get(cat, C["text_muted"])

            if cat != last_cat:
                if last_cat:
                    ctk.CTkFrame(self._sb_scroll, height=1,
                                 fg_color=C["border"],
                                 corner_radius=0).pack(fill="x", padx=6, pady=2)
                ctk.CTkLabel(self._sb_scroll,
                             text=f"  // {cat}",
                             text_color=cat_c,
                             font=F(8, bold=True, mono=True),
                             anchor="w").pack(fill="x", padx=6, pady=(5, 0))
                last_cat = cat

            # ── ROW: fixed height = _SB_ROW_H, NEVER expand ──────
            row = ctk.CTkFrame(self._sb_scroll,
                                fg_color="transparent",
                                border_width=0,
                                cursor="hand2",
                                corner_radius=0,
                                height=_SB_ROW_H)
            row.pack_propagate(False)   # ← KEY: lock height to _SB_ROW_H
            row.pack(fill="x", padx=3, pady=0)

            # Left indicator bar (2px wide, hidden by default)
            ind = ctk.CTkFrame(row, width=2,
                                fg_color="transparent",
                                border_width=0, corner_radius=0)
            ind.pack(side="left", fill="y")
            ind.pack_propagate(False)

            # Tab name label
            name_lbl = ctk.CTkLabel(
                row,
                text=f"  {name}",
                text_color=C["text_muted"],
                font=F(_SB_FONT),
                anchor="w",
                height=_SB_ROW_H)
            name_lbl.pack(side="left", fill="x", expand=True)

            self._sb_rows.append((row, name_lbl, cat_c, ind))

            def _enter(e, r=row, nl=name_lbl, idx=i):
                if idx != self._cur_idx:
                    r.configure(fg_color=C["bg_hover"])
                    nl.configure(text_color=C["text"])

            def _leave(e, r=row, nl=name_lbl, idx=i):
                if idx != self._cur_idx:
                    r.configure(fg_color="transparent")
                    nl.configure(text_color=C["text_muted"])

            for w in [row, name_lbl, ind]:
                w.bind("<Button-1>", lambda e, idx=i: self._switch_to(idx))
                w.bind("<Enter>", _enter)
                w.bind("<Leave>", _leave)

    # ── CONTENT AREA ──────────────────────────────────────────────
    def _build_content(self, parent):
        self._content = ctk.CTkFrame(parent, fg_color=C["bg_app"],
                                      border_width=0, corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

    # ── Navigation ────────────────────────────────────────────────
    def _switch_to(self, idx: int):
        if 0 <= self._cur_idx < len(self._sb_rows):
            row, nl, cc, ind = self._sb_rows[self._cur_idx]
            row.configure(fg_color="transparent")
            nl.configure(text_color=C["text_muted"], font=F(_SB_FONT))
            ind.configure(fg_color="transparent", width=2)

        if self._cur_frame:
            self._cur_frame.pack_forget()

        if idx not in self._tab_frames:
            frame = ctk.CTkFrame(self._content, fg_color=C["bg_app"],
                                  border_width=0, corner_radius=0)
            frame.pack(fill="both", expand=True)
            method = getattr(self, TABS[idx][2], None)
            if method:
                try:    method(frame)
                except Exception as ex:
                    self._err_tab(frame, TABS[idx][1], ex)
            else:
                self._stub_tab(frame, TABS[idx][1])
            self._tab_frames[idx] = frame
        else:
            self._tab_frames[idx].pack(fill="both", expand=True)

        if 0 <= idx < len(self._sb_rows):
            row, nl, cc, ind = self._sb_rows[idx]
            row.configure(fg_color=C["bg_selected"])
            nl.configure(text_color=cc, font=F(_SB_FONT, bold=True))
            ind.configure(fg_color=cc, width=3)

        self._cur_idx   = idx
        self._cur_frame = self._tab_frames.get(idx)

    def goto_tab(self, name: str):
        for i, (_, n, _) in enumerate(TABS):
            if n == name:
                self._switch_to(i)
                return

    def _filter_sidebar(self, *_):
        q = self._sb_q.get().lower().strip()
        for i, (row, nl, cc, ind) in enumerate(self._sb_rows):
            nm  = TABS[i][1].lower()
            cat = TABS[i][0].lower()
            show = not q or q in nm or q in cat
            if show:
                row.pack(fill="x", padx=3, pady=0)
            else:
                row.pack_forget()

    def _err_tab(self, frame, name, ex):
        sc = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        sc.pack(fill="both", expand=True, padx=20, pady=16)
        ctk.CTkLabel(sc, text=f"[ERR] Failed to load: {name}",
                     text_color=C["red"],
                     font=F(13, bold=True, mono=True)).pack(anchor="w")
        ctk.CTkLabel(sc, text=f"{type(ex).__name__}: {ex}",
                     text_color=C["yellow"], font=F(11, mono=True),
                     anchor="w", justify="left").pack(anchor="w", pady=6)
        tb = ctk.CTkTextbox(sc, fg_color=C["term_bg"],
                             text_color=C["red"],
                             font=F(9, mono=True),
                             height=200, corner_radius=3)
        tb.pack(fill="x")
        tb.insert("0.0", traceback.format_exc())
        tb.configure(state="disabled")

    def _stub_tab(self, frame, name):
        ctk.CTkLabel(frame,
                     text=f"// {name}\n\n[ under construction ]",
                     text_color=C["text_dim"],
                     font=F(13, mono=True)).pack(expand=True)

    # ── Helpers ───────────────────────────────────────────────────
    def set_status(self, msg: str, color: str = None):
        try:
            self._status_var.set(f"  >>  {msg}")
            self._status_lbl.configure(text_color=color or C["text_muted"])
        except Exception:
            pass

    def _get_proj_names(self):
        try:    return [p["name"] for p in get_projects()] or [""]
        except Exception: return [""]

    def _new_project(self):
        win = ctk.CTkToplevel(self.root)
        win.title("New Project")
        win.configure(fg_color=C["bg_app"])
        win.geometry("360x130")
        win.lift(); win.grab_set()
        ctk.CTkFrame(win, height=2, fg_color=C["accent"],
                     corner_radius=0).pack(fill="x")
        ctk.CTkLabel(win, text="  // new project",
                     text_color=C["accent"],
                     font=F(11, bold=True, mono=True),
                     anchor="w").pack(fill="x", padx=14, pady=(10, 4))
        v = ctk.StringVar(master=win)
        GlowEntry(win, textvariable=v,
                  placeholder_text="target.com",
                  height=32).pack(fill="x", padx=14)
        result = [None]

        def _ok():
            result[0] = v.get().strip()
            win.destroy()

        FilledButton(win, text=">> CREATE", command=_ok,
                     color=C["green"], height=32).pack(fill="x", padx=14, pady=8)
        win.bind("<Return>", lambda e: _ok())
        win.wait_window()
        name = result[0]
        if name:
            create_project(name)
            names = self._get_proj_names()
            try:    self._proj_combo.configure(values=names)
            except Exception: pass
            self.project.set(name)
            self._on_project_change()

    def _on_project_change(self, *_):
        proj = self.project.get()
        if proj:
            try:    update_project_active(proj)
            except Exception: pass
            self.set_status(f"PROJECT: {proj}", C["accent"])

    def _fetch_ip(self):
        try:
            import urllib.request
            ip = urllib.request.urlopen(
                "https://api.ipify.org", timeout=5).read().decode()
            def _upd():
                try:
                    self._ip_lbl.configure(text=f"IP:{ip}",
                                           text_color=C["text_dim"])
                except Exception:
                    pass
            try: self.root.after(0, _upd)
            except Exception: pass
        except Exception:
            pass


# ── Mixin imports ─────────────────────────────────────────────────
from app.ui.tabs.dashboard import DashboardMixin
from app.ui.tabs.projects  import ProjectsMixin
from app.ui.tabs.findings  import FindingsMixin
from app.ui.tabs.recon     import ReconMixin
from app.ui.tabs.scanner   import ScannerMixin
from app.ui.tabs.power     import PowerMixin
from app.ui.tabs.intel     import IntelMixin
from app.ui.tabs.ai_tabs   import AIMixin
from app.ui.tabs.results   import ResultsMixin
from app.ui.tabs.settings  import SettingsMixin
from app.ui.tabs.exploit   import ExploitMixin


class App(AppWindow,
          DashboardMixin, ProjectsMixin, FindingsMixin,
          ReconMixin, ScannerMixin, PowerMixin, IntelMixin,
          AIMixin, ResultsMixin, SettingsMixin, ExploitMixin):
    pass
