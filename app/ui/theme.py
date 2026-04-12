"""
TeamCyberOps V5 — Design System
Style: HUD/Sci-Fi FUI × Cybersecurity Platform × OLED Dark Mode
FIXED: All colors are valid 6-digit hex (#RRGGBB) — no 8-digit alpha (#RRGGBBAA)
       Tkinter only accepts #RGB or #RRGGBB — alpha must be pre-blended
"""
import customtkinter as ctk
import platform

ctk.set_appearance_mode("dark")
# Use custom theme for proper dark colors
import os as _os
_theme_path = _os.path.join(_os.path.dirname(__file__), "tco_theme.json")
if _os.path.exists(_theme_path):
    ctk.set_default_color_theme(_theme_path)
else:
    ctk.set_default_color_theme("blue")

_SYS = platform.system()

FONT_MONO = (
    "Cascadia Code"  if _SYS == "Windows" else
    "JetBrains Mono" if _SYS == "Darwin"  else
    "Monospace"
)
FONT_BODY = (
    "Segoe UI"    if _SYS == "Windows" else
    "SF Pro Text" if _SYS == "Darwin" else
    "Ubuntu"
)

# Base font size multiplier — increase to scale ALL text up
_FS = 1  # set to 1.2 for 20% bigger; default 1

def F(size=12, bold=False, mono=False):
    """Font factory. All sizes pass through _FS multiplier for global scaling."""
    scaled = max(10, int(size * _FS))
    return ctk.CTkFont(
        family=FONT_MONO if mono else FONT_BODY,
        size=scaled,
        weight="bold" if bold else "normal"
    )


# ── Color System ─────────────────────────────────────────────────
# C2 / Military / Dark Red + Light Blue scheme
# OLED-optimized: true blacks, high contrast accents
C = {
    # Backgrounds — true OLED black hierarchy
    "bg_void":      "#000000",
    "bg_deepest":   "#020305",
    "bg_app":       "#06090f",
    "bg_panel":     "#090e17",
    "bg_card":      "#0c1420",
    "bg_input":     "#0e1a28",
    "bg_hover":     "#111e2e",
    "bg_selected":  "#14243a",
    "bg_sidebar":   "#04060d",

    # Text
    "text":         "#c8e0f5",
    "text_bright":  "#eaf4ff",
    "text_muted":   "#4a6a86",
    "text_dim":     "#1e3040",
    "text_code":    "#7ec8a0",

    # Primary accent — electric ice blue (C2 comms style)
    "accent":       "#00c8ff",
    "accent_bright":"#33d6ff",
    "accent_dim":   "#005580",

    # Pre-blended hover tints
    "accent_tint":  "#05202e",
    "green_tint":   "#05221e",
    "red_tint":     "#1e0308",
    "yellow_tint":  "#1a1200",
    "purple_tint":  "#170826",
    "orange_tint":  "#1c0c02",
    "teal_tint":    "#041e1a",
    "pink_tint":    "#1c0415",
    "muted_tint":   "#0a1018",
    "darkred_tint": "#200206",
    "crimson_tint": "#220305",

    # Solid colors
    "green":        "#00e888",
    "green_bright": "#00ff9f",
    "green_dim":    "#005c38",
    "red":          "#ff2040",
    "red_bright":   "#ff3355",
    "red_dim":      "#6a0018",

    # C2 signature: dark red + crimson
    "darkred":      "#aa0018",
    "crimson":      "#cc0022",
    "blood":        "#880011",

    "yellow":       "#f5c400",
    "yellow_bright":"#ffd700",
    "yellow_dim":   "#604e00",
    "purple":       "#a855f7",
    "purple_dim":   "#3a1858",
    "orange":       "#ff7a1a",
    "orange_dim":   "#5c2800",
    "teal":         "#00c8a0",
    "teal_dim":     "#004d3d",
    "pink":         "#ff4da6",
    "pink_dim":     "#5c0033",

    # Borders — dark steel
    "border":       "#0d1e30",
    "border_mid":   "#162840",
    "border_bright":"#1e3a58",
    "border_red":   "#330010",
    "border_accent":"#004466",

    # Terminal
    "term_bg":      "#000305",
    "term_fg":      "#00e888",
    "term_cursor":  "#00c8ff",

    # Aliases (for backward compatibility)
    "cyan":         "#00c8ff",   # alias for accent
    "magenta":      "#ff4da6",   # alias for pink
    "white":        "#eaf4ff",   # alias for text_bright
    "blue":         "#0080ff",   # alias

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

# Category colors for sidebar — C2 Military style
CAT_COLORS = {
    "MAIN":    C["accent"],
    "RECON":   C["teal"],
    "SCAN":    C["yellow"],
    "EXPLOIT": C["crimson"],
    "POWER":   C["red"],
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
    C["darkred"]:  C["darkred_tint"],
    C["crimson"]:  C["crimson_tint"],
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
