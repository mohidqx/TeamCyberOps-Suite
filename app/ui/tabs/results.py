import json
import threading
"""TeamCyberOps V5 — Results, Reports, Live Monitor Tabs"""
import customtkinter as ctk, threading, json
from pathlib import Path
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, Terminal
from app.core.database import load_scan_results, get_finding_stats, load_findings
from app.core.config import cfg
from pathlib import Path as _Path
LOGS_DIR = _Path(cfg.get("logs_dir","logs"))


class ResultsMixin:

    def _tab_results(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=12, pady=8)
        Section(pad, "SCAN RESULTS", "📊", C["green"]).pack(fill="x", pady=(0,10))

        # Stats cards
        proj  = self.project.get()
        stats = get_finding_stats(proj if proj else None)
        row   = ctk.CTkFrame(pad); row.pack(fill="x", pady=(0,14))
        for col in range(5): row.columnconfigure(col, weight=1)
        for col, (label, value, color) in enumerate([
            ("CRITICAL", str(stats["CRITICAL"]), C["sev_critical"]),
            ("HIGH",     str(stats["HIGH"]),     C["sev_high"]),
            ("MEDIUM",   str(stats["MEDIUM"]),   C["sev_medium"]),
            ("LOW",      str(stats["LOW"]),       C["sev_low"]),
            ("TOTAL",    str(stats["total"]),     C["green"]),
        ]):
            card = ctk.CTkFrame(row)
            card.grid(row=0, column=col, padx=5, sticky="ew")
            ctk.CTkFrame(card, height=3, fg_color=color).pack(fill="x")
            ctk.CTkLabel(card, text=value, text_color=color,
                         font=F(28, bold=True, mono=True)).pack(pady=(10,2))
            ctk.CTkLabel(card, text=label,
                         font=F(10)).pack(pady=(0,10))

        # Log files
        Section(pad, "PROJECT LOG FILES", "📄", C["accent"]).pack(fill="x", pady=(8,8))
        proj_dir = Path(cfg.get("logs_dir","logs")) / (proj or "default")
        files    = sorted(proj_dir.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True) \
                   if proj_dir.exists() else []
        files    = [f for f in files if f.is_file() and f.stat().st_size > 0]

        if not files:
            ctk.CTkLabel(pad, text="No log files found for this project. Run a scan first.", font=F(11)).pack(pady=20)
        else:
            for fp in files[:50]:
                sz = fp.stat().st_size
                sz_s = f"{sz//1024}KB" if sz > 1024 else f"{sz}B"
                row2 = ctk.CTkFrame(pad, cursor="hand2")
                row2.pack(fill="x", pady=1)
                ext_c = {".txt":C["green"],".json":C["accent"],".md":C["purple"],".yaml":C["yellow"]}.get(fp.suffix, C["text_muted"])
                ctk.CTkLabel(row2, text=fp.suffix or "?", text_color=ext_c,
                             font=F(9, bold=True, mono=True), width=40).pack(side="left", padx=(8,6), pady=6)
                ctk.CTkLabel(row2, text=fp.name[:60],
                             font=F(10, mono=True), anchor="w").pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(row2, text=sz_s,
                             font=F(9, mono=True)).pack(side="right", padx=8)
                row2.bind("<Button-1>", lambda e, f=fp: self._open_file_viewer(f) if hasattr(self,"_open_file_viewer") else None)
                def _enter(e, r=row2): r.configure()
                def _leave(e, r=row2): r.configure()
                row2.bind("<Enter>", _enter); row2.bind("<Leave>", _leave)

    def _tab_reports(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=12, pady=8)
        Section(pad, "REPORT GENERATOR", "📋", C["accent"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["accent"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Generate reports from findings — Markdown / JSON / CSV\n"
            "Use AI Smart Reporter for professional HackerOne/Bugcrowd format reports"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        r1 = ctk.CTkFrame(pad); r1.pack(fill="x", pady=4)
        ctk.CTkLabel(r1, text="Format:",
                     font=F(10,mono=True), width=100, anchor="e").pack(side="left", padx=(0,8))
        self._rep_fmt = ctk.StringVar(value="Markdown")
        ctk.CTkComboBox(r1, variable=self._rep_fmt,
                        values=["Markdown","JSON","CSV","HTML"],
                        width=140, height=32, font=F(11,mono=True)).pack(side="left")

        self._rep_output = ctk.CTkTextbox(pad, font=F(10, mono=True))
        self._rep_output.pack(fill="both", expand=True, pady=(10,0))

        def _generate():
            proj  = self.project.get()
            finds = load_findings(project=proj if proj else None)
            fmt   = self._rep_fmt.get()
            if fmt == "Markdown":
                stats = get_finding_stats(proj if proj else None)
                lines = [f"# Security Report — {proj or 'All Projects'}\n",
                         f"Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}\n",
                         f"\n## Summary\n",
                         f"- CRITICAL: {stats['CRITICAL']}\n",
                         f"- HIGH: {stats['HIGH']}\n",
                         f"- MEDIUM: {stats['MEDIUM']}\n",
                         f"- LOW: {stats['LOW']}\n",
                         f"- Total: {stats['total']}\n\n",
                         "## Findings\n\n"]
                for f in finds:
                    lines.append(f"### [{f.get('severity','')}] {f.get('title','')}\n")
                    lines.append(f"- **Type:** {f.get('type','')}\n")
                    lines.append(f"- **URL:** {f.get('url','')}\n")
                    lines.append(f"- **Status:** {f.get('status','')}\n")
                    if f.get("description"): lines.append(f"- **Description:** {f.get('description','')}\n")
                    if f.get("poc"):         lines.append(f"- **PoC:** `{f.get('poc','')}`\n")
                    if f.get("impact"):      lines.append(f"- **Impact:** {f.get('impact','')}\n")
                    lines.append("\n")
                content = "".join(lines)
            elif fmt == "JSON":
                content = json.dumps(finds, indent=2, default=str)
            elif fmt == "CSV":
                import csv, io
                buf = io.StringIO()
                w   = csv.DictWriter(buf, fieldnames=["find_id","title","type","severity","url","status","project","tool","created_at"])
                w.writeheader()
                for f in finds:
                    w.writerow({k: f.get(k,"") for k in ["find_id","title","type","severity","url","status","project_name","tool","created_at"]})
                content = buf.getvalue()
            else:
                parts = "".join(f"<div><h3>{fi.get('title','')}</h3><p>{fi.get('description','')}</p></div>" for fi in finds)
                content = f"<html><body><h1>Report</h1>{parts}</body></html>"

            self._rep_output.configure()
            self._rep_output.delete("0.0","end")
            self._rep_output.insert("0.0", content)
            self._rep_output.configure()
            # Save
            out_dir = Path(cfg.get("reports_dir","reports")); out_dir.mkdir(parents=True, exist_ok=True)
            ext = {"Markdown":".md","JSON":".json","CSV":".csv","HTML":".html"}.get(fmt,".txt")
            fname = f"report_{proj or 'all'}{ext}"
            (out_dir/fname).write_text(content, encoding="utf-8")
            self.set_status(f"Report saved: {fname}",C["green"])

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="📋 Generate Report", command=_generate, color=C["accent"]).pack(
            side="left", ipady=4)
        NeonButton(btn_row, text="📋 Copy", small=True, color=C["text_muted"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(self._rep_output.get("0.0","end")),
                                    self.root.update())).pack(side="left", padx=8)
        NeonButton(btn_row, text="🤖 AI Report →", small=True, color=C["purple"],
                   command=lambda v=None: self.goto_tab("Smart Reporter")).pack(side="left", padx=4)

    def _tab_live_monitor(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=12, pady=8)
        Section(pad, "LIVE RECON DASHBOARD — 24/7 Monitor", "📡", C["accent"]).pack(fill="x", pady=(0,10))

        cfg_card = Card(pad, accent=C["accent"]); cfg_card.pack(fill="x", pady=(0,10))
        ci = ctk.CTkFrame(cfg_card); ci.pack(fill="x", padx=12, pady=10)
        r1 = ctk.CTkFrame(ci); r1.pack(fill="x", pady=2)
        ctk.CTkLabel(r1, text="Target Domain:",
                     font=F(10,mono=True), width=140, anchor="e").pack(side="left", padx=(0,8))
        self._lm_target = ctk.StringVar(value=self.project.get() or "")
        GlowEntry(r1, textvariable=self._lm_target, width=280, height=30).pack(side="left")
        ctk.CTkLabel(r1, text="  Interval (min):", font=F(10,mono=True)).pack(side="left", padx=(16,8))
        self._lm_interval = ctk.StringVar(value="15")
        GlowEntry(r1, textvariable=self._lm_interval, width=60, height=30).pack(side="left")

        r2 = ctk.CTkFrame(ci); r2.pack(fill="x", pady=6)
        ctk.CTkLabel(r2, text="Monitor:",
                     font=F(10,mono=True), width=140, anchor="e").pack(side="left", padx=(0,8))
        self._lm_checks = {}
        for lbl, key in [("New Subdomains","subs"),("HTTP Changes","http"),("New Findings","vulns")]:
            v = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(r2, text=lbl, variable=v,
                            font=F(11)).pack(side="left", padx=10)
            self._lm_checks[key] = v

        self._lm_status = ctk.CTkLabel(pad, text="● STOPPED",
                                        font=F(13, bold=True, mono=True), anchor="w")
        self._lm_status.pack(anchor="w", pady=(4,8))

        pane = ctk.CTkFrame(pad); pane.pack(fill="both", expand=True)

        left = ctk.CTkFrame(pane)
        left.pack(side="left", fill="both", expand=True, padx=(0,8))
        ctk.CTkLabel(left, text="  LIVE LOG",
                     font=F(10, bold=True, mono=True), anchor="w").pack(anchor="w", padx=10, pady=(8,4))
        self._lm_log = Terminal(left, height=16)
        self._lm_log.pack(fill="both", expand=True, padx=8, pady=(0,8))

        right = ctk.CTkFrame(pane, width=320)
        right.pack(side="right", fill="y"); right.pack_propagate(False)
        ctk.CTkLabel(right, text="  CHANGES DETECTED",
                     font=F(10, bold=True, mono=True), anchor="w").pack(anchor="w", padx=10, pady=(8,4))
        self._lm_changes = ctk.CTkScrollableFrame(right,
                                                    scrollbar_button_color=C["bg_hover"],
                                                    scrollbar_button_hover_color=C["accent"])
        self._lm_changes.pack(fill="both", expand=True, padx=8, pady=(0,8))

        self._lm_running = False
        self._lm_job     = None
        self._lm_snaps   = {}

        def _add_change(typ, detail, color=C["green"]):
            from datetime import datetime
            ts = datetime.now().strftime("%H:%M:%S")
            row = ctk.CTkFrame(self._lm_changes)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=ts,
                         font=F(8,mono=True), width=60).pack(side="left", padx=(6,4), pady=4)
            ctk.CTkLabel(row, text=f"{typ}: {detail[:40]}", text_color=color,
                         font=F(9,mono=True), anchor="w").pack(side="left", fill="x")

        def _do_check():
            if not self._lm_running: return
            domain = self._lm_target.get().strip()
            if not domain:
                self._lm_log.log("[-] No target set","err"); return
            self._lm_log.log(f"[*] Checking: {domain}","dim")
            import urllib.request as _ur, re as _re
            # Subdomain check
            if self._lm_checks.get("subs", ctk.BooleanVar()).get():
                try:
                    r = _ur.urlopen(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
                    data = json.loads(r.read())
                    current = set(d.get("name_value","").replace("*.","") for d in data if domain in d.get("name_value",""))
                    prev    = self._lm_snaps.get("subs", set())
                    new_s   = current - prev
                    if new_s and prev:
                        for s in new_s:
                            self._lm_log.log(f"[NEW SUB] {s}","ok")
                            self.root.after(0, lambda ss=s: _add_change("New Subdomain", ss, C["green"]))
                    self._lm_snaps["subs"] = current
                except Exception: pass
            # HTTP check
            if self._lm_checks.get("http", ctk.BooleanVar()).get():
                try:
                    req = _ur.Request(f"https://{domain}", headers={"User-Agent":"TeamCyberOps/5"})
                    with _ur.urlopen(req, timeout=8) as resp:
                        hdrs = dict(resp.headers)
                    prev_h = self._lm_snaps.get("http_hdrs", {})
                    changed = {k:v for k,v in hdrs.items() if prev_h.get(k) != v}
                    if changed and prev_h:
                        for k, v in list(changed.items())[:2]:
                            self._lm_log.log(f"[HTTP CHANGE] {k}: {v[:40]}","warn")
                            self.root.after(0, lambda kk=k,vv=v: _add_change("HTTP Change", f"{kk}: {vv[:25]}", C["yellow"]))
                    self._lm_snaps["http_hdrs"] = hdrs
                except Exception: pass
            # Findings check
            if self._lm_checks.get("vulns", ctk.BooleanVar()).get():
                all_f = load_findings(project=domain)
                prev_c = self._lm_snaps.get("vuln_count", 0)
                if len(all_f) > prev_c and prev_c > 0:
                    diff = len(all_f) - prev_c
                    self._lm_log.log(f"[NEW FINDING] +{diff} findings!","ok")
                    self.root.after(0, lambda d=diff: _add_change("New Finding", f"+{d} findings", C["red"]))
                self._lm_snaps["vuln_count"] = len(all_f)
            try: interval = max(1, int(self._lm_interval.get())) * 60 * 1000
            except Exception: interval = 15 * 60 * 1000
            if self._lm_running:
                self._lm_job = self.root.after(interval, _do_check)
                self._lm_log.log(f"[*] Next check in {interval//60000} min","dim")

        def _start():
            domain = self._lm_target.get().strip()
            if not domain: self.set_status("Enter target domain","red"); return
            self._lm_running = True; self._lm_snaps = {}
            self._lm_status.configure(text=f"● RUNNING — {domain}")
            self._lm_log.clear()
            for w in self._lm_changes.winfo_children(): w.destroy()
            self._lm_log.log(f"[*] Started monitoring: {domain}","ok")
            self._lm_log.log(f"[*] Interval: {self._lm_interval.get()} min","dim")
            _do_check()

        def _stop():
            self._lm_running = False
            if self._lm_job: self.root.after_cancel(self._lm_job); self._lm_job = None
            self._lm_status.configure(text="● STOPPED")
            self._lm_log.log("[*] Monitoring stopped","warn")

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(10,0))
        FilledButton(btn_row, text="▶ Start Monitor", command=_start, color=C["green"]).pack(side="left", ipady=4)
        NeonButton(btn_row, text="⬛ Stop", command=_stop, color=C["red"], small=True).pack(side="left", padx=8)
        NeonButton(btn_row, text="🔄 Check Now",
                   command=lambda v=None: threading.Thread(target=_do_check, daemon=True).start(),
                   color=C["accent"], small=True).pack(side="left", padx=4)
