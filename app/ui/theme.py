"""
TeamCyberOps V5 — Design System
Style: HUD/Sci-Fi FUI × Cybersecurity Platform × OLED Dark Mode
FIXED: All colors are valid 6-digit hex (#RRGGBB) — no 8-digit alpha (#RRGGBBAA)
       Tkinter only accepts #RGB or #RRGGBB — alpha must be pre-blended
"""
import customtkinter as ctk
import platform

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_SYS = platform.system()

FONT_MONO = (
    "Cascadia Code"  if _SYS == "Windows" else
    "JetBrains Mono" if _SYS == "Darwin"  else
    "Monospace"
)
FONT_BODY = (
    "Segoe UI"   if _SYS == "Windows" else
    "SF Pro Text" if _SYS == "Darwin" else
    "Ubuntu"
)

def F(size=12, bold=False, mono=False):
    return ctk.CTkFont(
        family=FONT_MONO if mono else FONT_BODY,
        size=size,
        weight="bold" if bold else "normal"
    )


# ── Color System ─────────────────────────────────────────────────
# ALL values are valid 6-digit hex — NO alpha suffixes like "1a"
# Hover/tint colors are pre-blended against bg_app (#060b12)
C = {
    # Backgrounds
    "bg_void":      "#000000",
    "bg_deepest":   "#010305",
    "bg_app":       "#060b12",
    "bg_panel":     "#080f1a",
    "bg_card":      "#0b1520",
    "bg_input":     "#0d1b28",
    "bg_hover":     "#102030",
    "bg_selected":  "#132638",
    "bg_sidebar":   "#030810",

    # Text
    "text":         "#c8dff0",
    "text_bright":  "#e8f4ff",
    "text_muted":   "#5a7a96",
    "text_dim":     "#243a4e",
    "text_code":    "#7ec8a0",

    # Accents — phosphor cyan
    "accent":       "#00bfff",
    "accent_bright":"#33ccff",
    "accent_dim":   "#006080",

    # Pre-blended hover tints (accent on bg_app) — VALID 6-digit hex
    "accent_tint":  "#051d2a",   # #00bfff @ 10% on #060b12
    "green_tint":   "#05201d",   # #00d97e @ 10% on #060b12
    "red_tint":     "#1a0308",   # #ff2b45 @ 10% on #060b12
    "yellow_tint":  "#191200",   # #f5c400 @ 10% on #060b12
    "purple_tint":  "#160820",   # #a855f7 @ 10% on #060b12
    "orange_tint":  "#1a0a02",   # #ff7a1a @ 10% on #060b12
    "teal_tint":    "#041e1b",   # #00c8a0 @ 10% on #060b12
    "pink_tint":    "#1a0410",   # #ff4da6 @ 10% on #060b12
    "muted_tint":   "#0a1118",   # #5a7a96 @ 10% on #060b12

    # Solid colors
    "green":        "#00d97e",
    "green_bright": "#00ff9f",
    "green_dim":    "#005a35",
    "red":          "#ff2b45",
    "red_bright":   "#ff4455",
    "red_dim":      "#660018",
    "yellow":       "#f5c400",
    "yellow_bright":"#ffd700",
    "yellow_dim":   "#604e00",
    "purple":       "#a855f7",
    "purple_dim":   "#3b1a5a",
    "orange":       "#ff7a1a",
    "orange_dim":   "#5c2800",
    "teal":         "#00c8a0",
    "teal_dim":     "#004d3d",
    "pink":         "#ff4da6",
    "pink_dim":     "#5c0033",

    # Borders
    "border":       "#0c1e2e",
    "border_mid":   "#152840",
    "border_bright":"#1e3a55",

    # Terminal
    "term_bg":      "#000508",
    "term_fg":      "#00d97e",
    "term_cursor":  "#00bfff",

    # Severity
    "sev_critical": "#ff2b45",
    "sev_high":     "#f5c400",
    "sev_medium":   "#00bfff",
    "sev_low":      "#00d97e",
    "sev_info":     "#5a7a96",
}

SEV_COLORS = {
    "CRITICAL": C["sev_critical"],
    "HIGH":     C["sev_high"],
    "MEDIUM":   C["sev_medium"],
    "LOW":      C["sev_low"],
    "INFO":     C["sev_info"],
}

SEV_BG = {
    "CRITICAL": "#200008",
    "HIGH":     "#1a1200",
    "MEDIUM":   "#001828",
    "LOW":      "#001a0a",
    "INFO":     "#080e14",
}

# Category colors for sidebar
CAT_COLORS = {
    "MAIN":    C["accent"],
    "RECON":   C["teal"],
    "SCAN":    C["yellow"],
    "EXPLOIT": C["red"],
    "POWER":   C["orange"],
    "INTEL":   C["purple"],
    "RESULTS": C["green"],
    "AI":      C["pink"],
    "SYSTEM":  C["text_muted"],
}

# Tint map — used by NeonButton hover
_TINT = {
    C["accent"]:   C["accent_tint"],
    C["green"]:    C["green_tint"],
    C["red"]:      C["red_tint"],
    C["yellow"]:   C["yellow_tint"],
    C["purple"]:   C["purple_tint"],
    C["orange"]:   C["orange_tint"],
    C["teal"]:     C["teal_tint"],
    C["pink"]:     C["pink_tint"],
    C["text_muted"]: C["muted_tint"],
    C["accent_dim"]: C["accent_tint"],
    C["green_dim"]:  C["green_tint"],
    C["red_dim"]:    C["red_tint"],
    C["text_dim"]:   C["muted_tint"],
}


def get_tint(color: str) -> str:
    """Return a pre-blended tint for hover — always valid 6-digit hex."""
    return _TINT.get(color, C["bg_hover"])


# ══════════════════════════════════════════════════════════════════
#  WIDGETS — All override-friendly via defaults.update(kw)
# ══════════════════════════════════════════════════════════════════

class NeonButton(ctk.CTkButton):
    """Ghost outline button. Hover uses pre-blended tint (valid hex)."""
    def __init__(self, parent, text="", command=None, color=None,
                 small=False, danger=False, **kw):
        c = C["red"] if danger else (color or C["accent"])
        sz = 10 if small else 12
        defaults = dict(
            text=text, command=command,
            font=F(sz, bold=True, mono=True),
            fg_color="transparent",
            hover_color=C["bg_hover"],
            border_color=c,
            border_width=1,
            text_color=c,
            corner_radius=3,
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)
        self._c    = defaults["text_color"]
        self._tint = get_tint(self._c)   # pre-blended, always valid
        self.bind("<Enter>", self._hi)
        self.bind("<Leave>", self._lo)

    def _hi(self, e=None):
        try:
            self.configure(fg_color=self._tint,
                           text_color=C["text_bright"])
        except Exception:
            pass

    def _lo(self, e=None):
        try:
            self.configure(fg_color="transparent",
                           text_color=self._c)
        except Exception:
            pass


class FilledButton(ctk.CTkButton):
    """Solid CTA button."""
    def __init__(self, parent, text="", command=None, color=None, **kw):
        c = color or C["accent"]
        bright = (C["accent"], C["green"], C["yellow"],
                  C["teal"], C["accent_bright"])
        tc = C["bg_void"] if c in bright else C["text_bright"]
        defaults = dict(
            text=text, command=command,
            font=F(12, bold=True),
            fg_color=c,
            hover_color=C["bg_hover"],
            text_color=tc,
            corner_radius=3,
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)


class GlowEntry(ctk.CTkEntry):
    """Input with accent focus ring."""
    def __init__(self, parent, placeholder="", **kw):
        defaults = dict(
            fg_color=C["bg_input"],
            border_color=C["border_mid"],
            text_color=C["text"],
            placeholder_text_color=C["text_dim"],
            placeholder_text=placeholder,
            font=F(11, mono=True),
            border_width=1,
            corner_radius=3,
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)
        self.bind("<FocusIn>",  self._on)
        self.bind("<FocusOut>", self._off)

    def _on(self, e=None):
        try: self.configure(border_color=C["accent"],
                            fg_color=C["bg_hover"])
        except Exception: pass

    def _off(self, e=None):
        try: self.configure(border_color=C["border_mid"],
                            fg_color=C["bg_input"])
        except Exception: pass


class Card(ctk.CTkFrame):
    """Panel card with optional 2px top accent stripe."""
    def __init__(self, parent, accent=None, **kw):
        defaults = dict(
            fg_color=C["bg_card"],
            border_color=C["border_mid"],
            border_width=1,
            corner_radius=4,
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)
        if accent:
            ctk.CTkFrame(self, height=2, fg_color=accent,
                         corner_radius=0).pack(fill="x", side="top")


class Section(ctk.CTkFrame):
    """Section header label + horizontal rule."""
    def __init__(self, parent, title="", icon="", color=None, **kw):
        defaults = dict(fg_color="transparent")
        defaults.update(kw)
        super().__init__(parent, **defaults)
        c = color or C["accent"]
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x")
        lbl = f"{icon}  {title}" if icon else title
        ctk.CTkLabel(row, text=lbl, text_color=c,
                     font=F(10, bold=True, mono=True),
                     anchor="w").pack(side="left")
        ctk.CTkFrame(row, height=1,
                     fg_color=C["border_mid"]).pack(
            side="left", fill="x", expand=True, padx=(8, 0))


class Terminal(ctk.CTkTextbox):
    """OLED terminal — phosphor green on void black."""
    TAG_COLORS = {
        "ok":   C["green"],
        "warn": C["yellow"],
        "err":  C["red"],
        "info": C["accent"],
        "dim":  C["text_dim"],
        "hdr":  C["accent_bright"],
        "sys":  C["text_muted"],
    }

    def __init__(self, parent, **kw):
        defaults = dict(
            fg_color=C["term_bg"],
            text_color=C["term_fg"],
            font=F(10, mono=True),
            border_width=1,
            border_color=C["border"],
            corner_radius=3,
            wrap="none",
            state="disabled",
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)
        for tag, color in self.TAG_COLORS.items():
            self._textbox.tag_configure(tag, foreground=color)

    def log(self, msg: str, tag: str = ""):
        self.configure(state="normal")
        if tag and tag in self.TAG_COLORS:
            self._textbox.insert("end", str(msg) + "\n", tag)
        else:
            self.insert("end", str(msg) + "\n")
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("0.0", "end")
        self.configure(state="disabled")

    def get_content(self) -> str:
        return self.get("0.0", "end")


class SeverityBadge(ctk.CTkLabel):
    def __init__(self, parent, severity="INFO", **kw):
        sev = severity.upper()
        fg  = SEV_COLORS.get(sev, C["text_muted"])
        bg  = SEV_BG.get(sev, C["bg_panel"])
        defaults = dict(
            text=f" {sev} ",
            text_color=fg, fg_color=bg,
            font=F(9, bold=True, mono=True),
            corner_radius=2,
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, label="", value="0", color=None, **kw):
        c = color or C["accent"]
        defaults = dict(
            fg_color=C["bg_card"],
            border_color=C["border_mid"],
            border_width=1, corner_radius=4,
        )
        defaults.update(kw)
        super().__init__(parent, **defaults)
        ctk.CTkFrame(self, height=2, fg_color=c,
                     corner_radius=0).pack(fill="x")
        ctk.CTkLabel(self, text=str(value), text_color=c,
                     font=F(26, bold=True, mono=True)).pack(pady=(10, 0))
        ctk.CTkLabel(self, text=label.upper(), text_color=C["text_muted"],
                     font=F(8, bold=True, mono=True)).pack(pady=(2, 10))


class Separator(ctk.CTkFrame):
    def __init__(self, parent, orient="h", **kw):
        d = (dict(height=1, fg_color=C["border_mid"], corner_radius=0)
             if orient == "h" else
             dict(width=1, fg_color=C["border_mid"], corner_radius=0))
        d.update(kw)
        super().__init__(parent, **d)
