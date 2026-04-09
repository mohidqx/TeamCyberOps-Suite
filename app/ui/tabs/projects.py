import threading
"""TeamCyberOps V5 — Projects Tab"""
import customtkinter as ctk
from pathlib import Path
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, SEV_COLORS
from app.core.database import (get_projects, create_project, delete_project,
                                 load_findings, get_finding_stats, update_project_active)
from app.core.config import cfg
from pathlib import Path as _Path
LOGS_DIR = _Path(cfg.get("logs_dir","logs"))


class ProjectsMixin:

    def _tab_projects(self, frame):
        frame.configure()
        pane = ctk.CTkFrame(frame)
        pane.pack(fill="both", expand=True)

        # ── LEFT: Project list ─────────────────────────────────────
        left = ctk.CTkFrame(pane, width=300)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        # Header
        hdr = ctk.CTkFrame(left, height=40)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="  PROJECTS", text_color=C["accent"],
                     font=F(11, bold=True, mono=True), anchor="w").pack(side="left", padx=10, pady=10)
        NeonButton(hdr, text="+", command=self._new_project, color=C["green"],
                   small=True, width=30).pack(side="right", padx=8)

        # Search
        self._proj_search_v = ctk.StringVar()
        left_search = ctk.CTkEntry(left, textvariable=self._proj_search_v,
                                    placeholder_text="🔍 search...",
                                    text_color=C["text"], font=F(10, mono=True),
                                    height=30)
        left_search.pack(fill="x")
        self._proj_search_v.trace_add("write", lambda *_: self._refresh_proj_list())

        self._proj_list_scroll = ctk.CTkScrollableFrame(
            left,
            scrollbar_button_color=C["bg_hover"],
            scrollbar_button_hover_color=C["accent"])
        self._proj_list_scroll.pack(fill="both", expand=True)

        # ── RIGHT: Project detail ──────────────────────────────────
        right = ctk.CTkFrame(pane)
        right.pack(side="left", fill="both", expand=True)

        # Detail header
        self._proj_detail_hdr = ctk.CTkFrame(right, height=52)
        self._proj_detail_hdr.pack(fill="x"); self._proj_detail_hdr.pack_propagate(False)
        self._proj_name_lbl = ctk.CTkLabel(self._proj_detail_hdr,
                                            text="  Select a project →",
                                            text_color=C["text_muted"],
                                            font=F(14, bold=True, mono=True), anchor="w")
        self._proj_name_lbl.pack(side="left", padx=14, fill="y")
        self._proj_action_row = ctk.CTkFrame(self._proj_detail_hdr)
        self._proj_action_row.pack(side="right", padx=10)

        # Detail tabs
        self._proj_tab_view = ctk.CTkTabview(
            right,
            segmented_button_fg_color=C["bg_input"],
            segmented_button_selected_color=C["bg_selected"],
            segmented_button_selected_hover_color=C["bg_hover"],
            segmented_button_unselected_color=C["bg_input"],
            text_color=C["text"])
        self._proj_tab_view.pack(fill="both", expand=True, padx=0)
        self._proj_tab_view.add("🚩 Findings")
        self._proj_tab_view.add("📄 Files")
        self._proj_tab_view.add("📊 Stats")

        # Findings subtab
        self._proj_finds_scroll = ctk.CTkScrollableFrame(
            self._proj_tab_view.tab("🚩 Findings"),
            scrollbar_button_color=C["bg_hover"], scrollbar_button_hover_color=C["accent"])
        self._proj_finds_scroll.pack(fill="both", expand=True)

        # Files subtab
        self._proj_files_scroll = ctk.CTkScrollableFrame(
            self._proj_tab_view.tab("📄 Files"),
            scrollbar_button_color=C["bg_hover"], scrollbar_button_hover_color=C["accent"])
        self._proj_files_scroll.pack(fill="both", expand=True)

        # Stats subtab
        self._proj_stats_frame = ctk.CTkFrame(
            self._proj_tab_view.tab("📊 Stats"))
        self._proj_stats_frame.pack(fill="both", expand=True)

        self._current_proj_name = None
        self._refresh_proj_list()

    def _refresh_proj_list(self):
        if not hasattr(self, "_proj_list_scroll"): return
        for w in self._proj_list_scroll.winfo_children(): w.destroy()
        q       = getattr(self, "_proj_search_v", ctk.StringVar()).get().lower()
        projs   = get_projects()
        active  = self.project.get()

        for p in projs:
            name = p["name"]
            if q and q not in name.lower(): continue
            is_active = (name == active)
            bg   = C["bg_selected"] if is_active else "transparent"
            row  = ctk.CTkFrame(self._proj_list_scroll, fg_color=bg, cursor="hand2")
            row.pack(fill="x", padx=4, pady=2)
            if is_active:
                ctk.CTkFrame(row, width=3).pack(side="left", fill="y")
            icon = ctk.CTkLabel(row, text="📁", font=F(13), text_color=C["accent"],
                                 width=30)
            icon.pack(side="left", padx=(6,4), pady=8)
            info = ctk.CTkFrame(row)
            info.pack(side="left", fill="x", expand=True, pady=6)
            ctk.CTkLabel(info, text=name, text_color=C["text"] if not is_active else C["accent"],
                         font=F(11, bold=is_active), anchor="w").pack(anchor="w")
            fc = p.get("finding_count", 0)
            ctk.CTkLabel(info, text=f"{fc} findings", text_color=C["text_dim"],
                         font=F(9)).pack(anchor="w")
            for w in [row, icon, info]:
                w.bind("<Button-1>", lambda e, n=name: self._select_project(n))
            def _enter(e, r=row, ia=is_active):
                if not ia: r.configure()
            def _leave(e, r=row, ia=is_active):
                if not ia: r.configure()
            row.bind("<Enter>", _enter); row.bind("<Leave>", _leave)

    def _select_project(self, name):
        self._current_proj_name = name
        self._proj_name_lbl.configure(text=f"  📁  {name}", text_color=C["accent"])
        # Clear action buttons
        for w in self._proj_action_row.winfo_children(): w.destroy()
        FilledButton(self._proj_action_row, text="✅ Set Active",
                     command=lambda v=None: self._set_active_project(name),
                     color=C["accent"], height=30).pack(side="left", padx=(0,4))
        NeonButton(self._proj_action_row, text="📂 Folder",
                   command=lambda v=None: self._open_proj_folder(name),
                   color=C["text_muted"], small=True).pack(side="left", padx=(0,4))
        NeonButton(self._proj_action_row, text="🗑 Delete",
                   command=lambda v=None: self._delete_project(name),
                   color=C["red"], small=True, danger=True).pack(side="left")
        self._load_proj_detail(name)

    def _load_proj_detail(self, name):
        # Findings
        for w in self._proj_finds_scroll.winfo_children(): w.destroy()
        findings = load_findings(project=name)
        if not findings:
            ctk.CTkLabel(self._proj_finds_scroll, text="No findings for this project",
                         text_color=C["text_dim"], font=F(11)).pack(pady=20)
        else:
            for f in findings:
                sev   = f.get("severity","INFO").upper()
                color = SEV_COLORS.get(sev, C["text_muted"])
                row   = ctk.CTkFrame(self._proj_finds_scroll, cursor="hand2")
                row.pack(fill="x", padx=8, pady=2)
                ctk.CTkLabel(row, text=f" {sev[:4]} ", text_color=color,
                             fg_color=color+"22", font=F(9, bold=True, mono=True), width=54).pack(side="left", padx=(8,6), pady=6)
                ctk.CTkLabel(row, text=f.get("title","")[:65], text_color=C["text"],
                             font=F(10), anchor="w").pack(side="left", fill="x", expand=True)
                st_c = {"Open":C["accent"],"Reported":C["green"]}.get(f.get("status","Open"), C["text_dim"])
                ctk.CTkLabel(row, text=f.get("status",""), text_color=st_c,
                             font=F(9, mono=True)).pack(side="right", padx=8)
                row.bind("<Button-1>", lambda e, fi=f: (
                    self.goto_tab("Findings"),
                    self._show_finding_detail(fi) if hasattr(self, "_show_finding_detail") else None))

        # Files
        for w in self._proj_files_scroll.winfo_children(): w.destroy()
        logs_dir = Path(cfg.get("logs_dir", "logs")) / name
        files    = sorted(logs_dir.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True) \
                   if logs_dir.exists() else []
        files    = [f for f in files if f.is_file() and f.stat().st_size > 0]
        if not files:
            ctk.CTkLabel(self._proj_files_scroll, text="No log files yet",
                         text_color=C["text_dim"], font=F(11)).pack(pady=20)
        else:
            for fp in files[:100]:
                sz   = fp.stat().st_size
                sz_s = f"{sz//1024}KB" if sz > 1024 else f"{sz}B"
                row  = ctk.CTkFrame(self._proj_files_scroll,
                                    cursor="hand2")
                row.pack(fill="x", padx=8, pady=1)
                ext_color = {".txt":C["green"],".json":C["accent"],".md":C["purple"]}.get(fp.suffix, C["text_muted"])
                ctk.CTkLabel(row, text=fp.suffix or "?", text_color=ext_color,
                             font=F(9, bold=True, mono=True), width=38).pack(side="left", padx=(8,4), pady=6)
                ctk.CTkLabel(row, text=fp.name[:50], text_color=C["text"],
                             font=F(10, mono=True), anchor="w").pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(row, text=sz_s, text_color=C["text_dim"],
                             font=F(9, mono=True)).pack(side="right", padx=8)
                row.bind("<Button-1>", lambda e, f=fp: self._open_file_viewer(f))
                def _enter(e, r=row): r.configure()
                def _leave(e, r=row): r.configure()
                row.bind("<Enter>", _enter); row.bind("<Leave>", _leave)

        # Stats
        for w in self._proj_stats_frame.winfo_children(): w.destroy()
        stats  = get_finding_stats(name)
        scol   = ctk.CTkFrame(self._proj_stats_frame)
        scol.pack(fill="x", padx=20, pady=20)
        for sev, cnt, color in [
            ("CRITICAL", stats["CRITICAL"], C["sev_critical"]),
            ("HIGH",     stats["HIGH"],     C["sev_high"]),
            ("MEDIUM",   stats["MEDIUM"],   C["sev_medium"]),
            ("LOW",      stats["LOW"],       C["sev_low"]),
            ("INFO",     stats["INFO"],      C["text_muted"]),
        ]:
            bar_row = ctk.CTkFrame(scol)
            bar_row.pack(fill="x", pady=4)
            ctk.CTkLabel(bar_row, text=f" {sev} ", text_color=color,
                         fg_color=color+"22", font=F(10, bold=True, mono=True), width=80).pack(side="left")
            max_cnt = max(stats["total"], 1)
            bar_w   = max(4, int(300 * cnt / max_cnt))
            ctk.CTkFrame(bar_row, width=bar_w, height=20,
                         fg_color=color).pack(side="left", padx=8)
            ctk.CTkLabel(bar_row, text=str(cnt), text_color=color,
                         font=F(11, bold=True, mono=True)).pack(side="left")

    def _set_active_project(self, name):
        self.project.set(name)
        update_project_active(name)
        names = [p["name"] for p in get_projects()]
        self._proj_combo.configure(values=names)
        self.set_status(f"Active project: {name}", C["accent"])
        self._refresh_proj_list()

    def _open_proj_folder(self, name):
        import subprocess, platform
        folder = Path(cfg.get("logs_dir","logs")) / name
        folder.mkdir(parents=True, exist_ok=True)
        try:
            if platform.system() == "Windows":
                subprocess.run(["explorer", str(folder)])
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(folder)])
            else:
                subprocess.run(["xdg-open", str(folder)])
        except Exception: pass

    def _delete_project(self, name):
        try:
            d = ctk.CTkInputDialog(text=f"Type '{name}' to confirm delete:", title="Delete Project")
            confirm = d.get_input()
        except Exception:
            confirm = name  # fallback: just confirm
        if confirm == name:
            delete_project(name)
            self._refresh_proj_list()
            self.set_status(f"Deleted: {name}", C["yellow"])

    def _open_file_viewer(self, fpath):
        try:
            content = fpath.read_text(errors="replace")
        except Exception as e:
            content = f"Error reading file: {e}"
        win = ctk.CTkToplevel(self.root)
        win.title(f"📄 {fpath.name}")
        win.configure()
        win.geometry("900x600"); win.lift()
        ctk.CTkFrame(win, height=2).pack(fill="x")
        ctk.CTkLabel(win, text=f"  {fpath}", text_color=C["text_dim"],
                     font=F(9, mono=True), anchor="w").pack(fill="x", padx=8, pady=4)
        txt = ctk.CTkTextbox(win, text_color=C["term_fg"],
                              font=F(10, mono=True), wrap="none")
        txt.pack(fill="both", expand=True, padx=8, pady=4)
        txt.insert("0.0", content)
        txt.configure(state="disabled")
        btn_row = ctk.CTkFrame(win)
        btn_row.pack(fill="x", padx=8, pady=6)
        NeonButton(btn_row, text="📋 Copy All", small=True, color=C["accent"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(content),
                                    self.root.update())).pack(side="left", padx=4)
        NeonButton(btn_row, text="✕ Close", small=True, color=C["text_muted"],
                   command=win.destroy).pack(side="right", padx=4)
