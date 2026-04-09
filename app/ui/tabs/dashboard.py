"""TeamCyberOps V5 — Dashboard Tab"""
import customtkinter as ctk
from app.ui.theme import C, F, Card, Section, StatCard, NeonButton, SEV_COLORS
from app.core.database import get_finding_stats, load_findings, get_projects


class DashboardMixin:
    def _tab_dashboard(self, frame):
        frame.configure()
        scroll = ctk.CTkScrollableFrame(frame,
                                         scrollbar_button_color=C["bg_hover"],
                                         scrollbar_button_hover_color=C["accent"])
        scroll.pack(fill="both", expand=True, padx=20, pady=16)

        # Hero
        hero = Card(scroll, accent=C["accent"])
        hero.pack(fill="x", pady=(0, 18))
        inner = ctk.CTkFrame(hero)
        inner.pack(fill="x", padx=24, pady=16)
        ctk.CTkLabel(inner, text="⬡  TeamCyberOps Suite  v5.0",
                     text_color=C["accent"], font=F(22, bold=True, mono=True),
                     anchor="w").pack(anchor="w")
        ctk.CTkLabel(inner, text="Elite Bug Bounty Framework  ·  AI-Powered  ·  Production Ready",
                     text_color=C["text_muted"], font=F(11)).pack(anchor="w")

        # Stats
        proj  = self.project.get()
        stats = get_finding_stats(proj if proj else None)
        projs = get_projects()
        row   = ctk.CTkFrame(scroll)
        row.pack(fill="x", pady=(0, 18))
        for col in range(6): row.columnconfigure(col, weight=1)
        for col, (label, value, color) in enumerate([
            ("Projects", str(len(projs)),        C["accent"]),
            ("CRITICAL", str(stats["CRITICAL"]), C["sev_critical"]),
            ("HIGH",     str(stats["HIGH"]),      C["sev_high"]),
            ("MEDIUM",   str(stats["MEDIUM"]),    C["sev_medium"]),
            ("LOW",      str(stats["LOW"]),        C["sev_low"]),
            ("TOTAL",    str(stats["total"]),      C["green"]),
        ]):
            StatCard(row, label=label, value=value, color=color).grid(
                row=0, column=col, padx=5, sticky="ew")

        # Quick actions
        Section(scroll, "QUICK ACTIONS", "⚡", C["accent"]).pack(fill="x", pady=(0, 8))
        qa = ctk.CTkFrame(scroll)
        qa.pack(fill="x", pady=(0, 18))
        for text, tab, color in [
            ("🤖 Auto-Recon",    "Auto-Recon",     C["accent"]),
            ("⚡ Vuln Scanner",  "Vuln Scanner",   C["yellow"]),
            ("📡 OAST Server",   "OAST Server",    C["red"]),
            ("🚩 Findings",      "Findings",       C["green"]),
            ("🧠 AI Exploit",    "AI Auto-Exploit",C["purple"]),
            ("⚙️ Settings",      "Settings",       C["text_muted"]),
        ]:
            NeonButton(qa, text=text, color=color, small=True,
                       command=lambda n=tab: self.goto_tab(n)).pack(
                side="left", padx=4, ipady=3)

        # Recent findings
        Section(scroll, "RECENT FINDINGS", "🚩", C["green"]).pack(fill="x", pady=(0, 8))
        fc = Card(scroll); fc.pack(fill="x", pady=(0, 18))
        recent = load_findings(project=proj if proj else None)[:10]
        if not recent:
            ctk.CTkLabel(fc, text="No findings yet — run a scan",
                         text_color=C["text_dim"], font=F(11)).pack(pady=20)
        else:
            for f in recent:
                sev   = f.get("severity", "INFO").upper()
                color = SEV_COLORS.get(sev, C["text_muted"])
                r     = ctk.CTkFrame(fc); r.pack(fill="x", padx=16, pady=2)
                ctk.CTkLabel(r, text=f" {sev} ", text_color=color,
                             fg_color=color+"22", font=F(9, bold=True, mono=True), width=74).pack(side="left", padx=(0,8))
                ctk.CTkLabel(r, text=f.get("title","")[:70], text_color=C["text"],
                             font=F(11), anchor="w").pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(r, text=f.get("project",""), text_color=C["text_dim"],
                             font=F(9)).pack(side="right")

        # Refresh button
        NeonButton(scroll, text="🔄 Refresh Dashboard", color=C["accent"], small=True,
                   command=lambda v=None: self._refresh_findings() if hasattr(self,"_refresh_findings") else None).pack(
            anchor="w", pady=(0, 20))
