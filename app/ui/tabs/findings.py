"""TeamCyberOps V5 — Findings Tab (SQLite-backed, fully working)"""
import customtkinter as ctk
import threading, json
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, SEV_COLORS, SeverityBadge
from app.core.database import load_findings, save_finding, update_finding, delete_finding, get_finding_stats


class FindingsMixin:

    def _tab_findings(self, frame):
        frame.configure()
        self._findings_data = []

        # ── Top bar ────────────────────────────────────────────────
        topbar = ctk.CTkFrame(frame, height=52)
        topbar.pack(fill="x", padx=0, pady=0)
        topbar.pack_propagate(False)

        bar = ctk.CTkFrame(topbar)
        bar.pack(fill="x", padx=16, pady=8)

        # Search
        self._find_search = ctk.StringVar()
        GlowEntry(bar, textvariable=self._find_search,
                  placeholder_text="🔍 Search findings...",
                  width=260, height=32).pack(side="left", padx=(0, 8))
        self._find_search.trace_add("write", lambda *_: self._filter_findings())

        # Severity filter
        self._find_sev = ctk.StringVar(value="All")
        ctk.CTkComboBox(bar, variable=self._find_sev,
                        values=["All","CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                        width=120, height=32, font=F(11, mono=True),
                        command=lambda v=None: self._filter_findings()).pack(side="left", padx=(0,8))

        # Status filter
        self._find_status = ctk.StringVar(value="All")
        ctk.CTkComboBox(bar, variable=self._find_status,
                        values=["All","Open","In Progress","Reported","Duplicate","Resolved"],
                        width=140, height=32, font=F(11, mono=True),
                        command=lambda v=None: self._filter_findings()).pack(side="left", padx=(0,8))

        # Stats label
        self._find_stats_lbl = ctk.CTkLabel(bar, text="", font=F(10, mono=True))
        self._find_stats_lbl.pack(side="left", padx=8)

        # Right buttons
        FilledButton(bar, text="+ Add Finding", command=self._add_finding_dialog,
                     color=C["green"], height=32).pack(side="right", padx=(4,0))
        NeonButton(bar, text="🔄", command=self._refresh_findings,
                   color=C["text_muted"], small=True).pack(side="right", padx=(4,0))
        NeonButton(bar, text="🗑 Delete", command=self._delete_finding,
                   color=C["red"], small=True).pack(side="right", padx=(4,0))

        # ── Split pane ──────────────────────────────────────────────
        pane = ctk.CTkFrame(frame)
        pane.pack(fill="both", expand=True)

        # Findings list (left)
        list_frame = ctk.CTkFrame(pane)
        list_frame.pack(side="left", fill="both", expand=True, padx=(0,0))

        # Column headers
        hdr = ctk.CTkFrame(list_frame, height=32)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        for text, w in [("SEV",70),("TITLE",300),("TYPE",120),("URL",200),("STATUS",100),("TOOL",100)]:
            ctk.CTkLabel(hdr, text=text,
                         font=F(9, bold=True, mono=True), width=w, anchor="w").pack(
                side="left", padx=(8 if text=="SEV" else 0, 0))

        # Scrollable findings list
        self._findings_scroll = ctk.CTkScrollableFrame(
            list_frame,
            scrollbar_button_color=C["bg_hover"],
            scrollbar_button_hover_color=C["accent"])
        self._findings_scroll.pack(fill="both", expand=True)

        # Detail panel (right)
        self._find_detail_panel = ctk.CTkFrame(pane,
                                                width=420)
        self._find_detail_panel.pack(side="right", fill="y", padx=(1,0))
        self._find_detail_panel.pack_propagate(False)
        self._build_finding_detail_panel()

        self._refresh_findings()

    def _refresh_findings(self):
        proj = self.project.get()
        self._findings_data = load_findings(project=proj if proj else None)
        self._filter_findings()

    # Keep reference so AppWindow can call it
    _findings_refresh = _refresh_findings

    def _filter_findings(self):
        if not hasattr(self, "_findings_scroll"): return
        search = self._find_search.get().strip().lower() if hasattr(self, "_find_search") else ""
        sev    = self._find_sev.get()    if hasattr(self, "_find_sev")    else "All"
        status = self._find_status.get() if hasattr(self, "_find_status") else "All"

        # Clear existing rows
        for w in self._findings_scroll.winfo_children():
            w.destroy()

        shown = 0
        for f in self._findings_data:
            if sev != "All" and f.get("severity","").upper() != sev: continue
            if status != "All" and f.get("status","") != status: continue
            if search:
                haystack = " ".join([
                    f.get("title",""), f.get("type",""), f.get("url",""),
                    f.get("description",""), f.get("project","")
                ]).lower()
                if search not in haystack: continue
            self._add_finding_row(f)
            shown += 1

        stats = get_finding_stats(self.project.get() if self.project.get() else None)
        if hasattr(self, "_find_stats_lbl"):
            self._find_stats_lbl.configure(
                text=f"Showing: {shown}  │  🔴 {stats['CRITICAL']}  🟠 {stats['HIGH']}  🔵 {stats['MEDIUM']}  Total: {stats['total']}")

    def _add_finding_row(self, f):
        sev   = f.get("severity","INFO").upper()
        color = SEV_COLORS.get(sev, C["text_muted"])
        row   = ctk.CTkFrame(self._findings_scroll,
                              cursor="hand2")
        row.pack(fill="x", pady=1)

        # Hover effects
        def _enter(e, r=row): r.configure()
        def _leave(e, r=row): r.configure()
        row.bind("<Enter>", _enter); row.bind("<Leave>", _leave)
        row.bind("<Button-1>", lambda e, fi=f: self._show_finding_detail(fi))

        # Severity badge
        sev_lbl = ctk.CTkLabel(row, text=f" {sev[:4]} ", text_color=color,
                                fg_color=color+"22", font=F(9, bold=True, mono=True), width=60)
        sev_lbl.pack(side="left", padx=(8,6), pady=6)
        sev_lbl.bind("<Button-1>", lambda e, fi=f: self._show_finding_detail(fi))

        title = ctk.CTkLabel(row, text=f.get("title","")[:55],
                              font=F(11), anchor="w", width=290)
        title.pack(side="left", padx=(0,6))
        title.bind("<Button-1>", lambda e, fi=f: self._show_finding_detail(fi))

        typ = ctk.CTkLabel(row, text=f.get("type","")[:18],
                            font=F(10, mono=True), width=110)
        typ.pack(side="left", padx=(0,4))
        typ.bind("<Button-1>", lambda e, fi=f: self._show_finding_detail(fi))

        st  = f.get("status","Open")
        st_c= {"Open":C["accent"],"Reported":C["green"],"Duplicate":C["yellow"],
                "Resolved":C["text_dim"],"In Progress":C["accent"]}.get(st, C["text_muted"])
        status_lbl = ctk.CTkLabel(row, text=st, text_color=st_c,
                                   font=F(9, mono=True), width=95)
        status_lbl.pack(side="right", padx=(0,8))
        status_lbl.bind("<Button-1>", lambda e, fi=f: self._show_finding_detail(fi))

    def _build_finding_detail_panel(self):
        p = self._find_detail_panel
        ctk.CTkLabel(p, text="SELECT A FINDING",
                     font=F(12, mono=True)).pack(expand=True)

    def _show_finding_detail(self, f):
        p = self._find_detail_panel
        for w in p.winfo_children(): w.destroy()

        # Header
        hdr = ctk.CTkFrame(p)
        hdr.pack(fill="x")
        sev   = f.get("severity","INFO").upper()
        color = SEV_COLORS.get(sev, C["text_muted"])
        ctk.CTkFrame(p, height=2, fg_color=color).pack(fill="x")
        ctk.CTkLabel(hdr, text=f" {sev} ", text_color=color,
                     fg_color=color+"22", font=F(10, bold=True, mono=True)).pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(hdr, text=f"CVSS: {f.get('cvss_score','N/A')}",
                     text_color=color, font=F(10, bold=True, mono=True)).pack(side="right", padx=12)

        # Scrollable content
        scroll = ctk.CTkScrollableFrame(p,
                                         scrollbar_button_color=C["bg_hover"],
                                         scrollbar_button_hover_color=C["accent"])
        scroll.pack(fill="both", expand=True, pady=0)

        def _field(label, value, color=C["text"], copyable=False):
            if not value: return
            f_row = ctk.CTkFrame(scroll)
            f_row.pack(fill="x", padx=14, pady=(6,0))
            ctk.CTkLabel(f_row, text=label.upper(),
                         font=F(8, bold=True, mono=True), anchor="w").pack(anchor="w")
            lbl = ctk.CTkLabel(f_row, text=str(value)[:300],
                                text_color=color, font=F(10, mono=True),
                                anchor="w", wraplength=380, justify="left")
            lbl.pack(anchor="w")
            if copyable:
                def _copy():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(str(value))
                    self.set_status("Copied!", C["green"])
                lbl.bind("<Button-3>", lambda e: _copy())

        _field("Title",       f.get("title",""),       C["text"],      True)
        _field("Type",        f.get("type",""),         C["accent"])
        _field("URL",         f.get("url",""),          C["accent"],    True)
        _field("Project",     f.get("project_name", f.get("project","")), C["text_muted"])
        _field("Tool",        f.get("tool",""),         C["text_muted"])
        _field("Description", f.get("description",""),  C["text"])
        _field("PoC",         f.get("poc",""),          C["yellow"],    True)
        _field("Impact",      f.get("impact",""),       C["red"])
        _field("Remediation", f.get("remediation",""),  C["green"])

        # Separator
        ctk.CTkFrame(scroll, height=1).pack(fill="x", padx=14, pady=10)

        # Status update
        st_row = ctk.CTkFrame(scroll)
        st_row.pack(fill="x", padx=14, pady=(0,8))
        ctk.CTkLabel(st_row, text="STATUS:",
                     font=F(9, bold=True, mono=True)).pack(side="left")
        st_var = ctk.StringVar(value=f.get("status","Open"))
        ctk.CTkComboBox(st_row, variable=st_var,
                        values=["Open","In Progress","Reported","Duplicate","Not a Bug","Resolved"],
                        width=140, height=28, font=F(10, mono=True)).pack(side="left", padx=8)
        NeonButton(st_row, text="Save", small=True, color=C["green"],
                   command=lambda v=None: self._update_finding_status(f, st_var.get())).pack(side="left")

        # Action buttons
        btn_row = ctk.CTkFrame(scroll)
        btn_row.pack(fill="x", padx=14, pady=(0,14))
        NeonButton(btn_row, text="📋 Copy Title+URL", small=True, color=C["accent"],
                   command=lambda v=None: (
                       self.root.clipboard_clear(),
                       self.root.clipboard_append(f"{f.get('title','')} - {f.get('url','')}"),
                       self.root.update(),
                       self.set_status("Copied!", C["green"]))).pack(side="left", padx=(0,4))
        if f.get("url"):
            NeonButton(btn_row, text="🌐 Open URL", small=True, color=C["accent"],
                       command=lambda v=None: __import__("webbrowser").open(f["url"])).pack(side="left", padx=(0,4))

    def _update_finding_status(self, f, new_status):
        fid = f.get("find_id") or f.get("id")
        if fid:
            update_finding(str(fid), {"status": new_status})
            self._refresh_findings()
            self.set_status(f"Status updated: {new_status}", C["green"])

    def _add_finding_dialog(self):
        win = ctk.CTkToplevel(self.root)
        win.title("Add Finding")
        win.configure()
        win.geometry("600x680")
        win.lift(); win.focus_force()

        ctk.CTkFrame(win, height=2).pack(fill="x")
        ctk.CTkLabel(win, text="  ➕ ADD NEW FINDING", font=F(13, bold=True, mono=True),
                     anchor="w").pack(fill="x", padx=16, pady=(10,6))

        scroll = ctk.CTkScrollableFrame(win,
                                         scrollbar_button_color=C["bg_hover"])
        scroll.pack(fill="both", expand=True, padx=16)

        vars_map = {}
        fields = [
            ("Title *",       "title",       "", False),
            ("Type",          "type",        "", False),
            ("Severity",      "severity",    "HIGH", True),
            ("CVSS Score",    "cvss_score",  "", False),
            ("URL",           "url",         "", False),
            ("Description",   "description", "", False),
            ("PoC",           "poc",         "", False),
            ("Impact",        "impact",      "", False),
            ("Remediation",   "remediation", "", False),
            ("Tool",          "tool",        "", False),
        ]
        sev_options = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]

        for label, key, default, is_combo in fields:
            ctk.CTkLabel(scroll, text=label,
                         font=F(9, bold=True, mono=True), anchor="w").pack(anchor="w", pady=(8,2))
            if is_combo:
                v = ctk.StringVar(value=default)
                ctk.CTkComboBox(scroll, variable=v, values=sev_options, font=F(11, mono=True),
                                height=34).pack(fill="x")
            elif key in ("description","poc","impact","remediation"):
                v = ctk.StringVar(value=default)
                txt = ctk.CTkTextbox(scroll, height=60, font=F(11, mono=True))
                txt.pack(fill="x")
                v._textbox = txt
                v._is_textbox = True
            else:
                v = ctk.StringVar(value=default)
                GlowEntry(scroll, textvariable=v, height=34).pack(fill="x")
            vars_map[key] = v

        def _save():
            finding = {}
            for key, v in vars_map.items():
                if hasattr(v, "_is_textbox"):
                    finding[key] = v._textbox.get("0.0", "end").strip()
                else:
                    finding[key] = v.get().strip()
            if not finding.get("title"):
                self.set_status("Title is required!", C["red"]); return
            finding["project"] = self.project.get() or "default"
            save_finding(finding)
            self._refresh_findings()
            self.set_status(f"Finding saved: {finding['title'][:40]}", C["green"])
            win.destroy()

        btn_row = ctk.CTkFrame(win)
        btn_row.pack(fill="x", padx=16, pady=12)
        FilledButton(btn_row, text="💾 Save Finding", command=_save,
                     color=C["green"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="Cancel", command=win.destroy,
                   color=C["text_muted"], small=True).pack(side="left", padx=8)

    def _delete_finding(self):
        # Find selected (last clicked)
        if hasattr(self, "_selected_finding") and self._selected_finding:
            f   = self._selected_finding
            fid = f.get("find_id") or str(f.get("id",""))
            try:
                dialog = ctk.CTkInputDialog(
                    text=f"Type 'DELETE' to confirm deleting:\n{f.get('title','')[:50]}",
                    title="Confirm Delete")
                confirm = dialog.get_input()
            except Exception:
                confirm = "DELETE"
            if confirm == "DELETE":
                delete_finding(fid)
                self._refresh_findings()
                self.set_status("Finding deleted", C["yellow"])
