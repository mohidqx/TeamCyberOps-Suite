"""
TeamCyberOps V5 — Login Window
FIX: ctk.CTk() created BEFORE any ctk.StringVar (root window required)
LOGO: TeamCyberOps Owl Badge — app/ui/org_logo.jpg
"""
import customtkinter as ctk
import threading
from pathlib import Path
from app.ui.theme import C, F, NeonButton, FilledButton, GlowEntry
from app.core.database import verify_user

_HERE = Path(__file__).parent


class LoginWindow:
    def __init__(self):
        self.user = None

        # ── CRITICAL: root MUST be created before ANY StringVar ──
        self.root = ctk.CTk()
        self.root.title("TeamCyberOps V5  //  Monitor & Protect")
        self.root.configure(fg_color=C["bg_void"])
        self.root.resizable(False, False)

        W, H = 460, 640
        try:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
        except Exception:
            sw, sh = 1920, 1080
        self.root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        # ── StringVars AFTER root ─────────────────────────────────
        self._uv = ctk.StringVar(value="admin")
        self._pv = ctk.StringVar()

        self._build()
        self.root.mainloop()

    def _build(self):
        r = self.root

        # ── Top accent bar (2px phosphor cyan) ───────────────────
        ctk.CTkFrame(r, height=2, fg_color=C["accent"],
                     corner_radius=0).pack(fill="x", side="top")

        # ── Header strip ─────────────────────────────────────────
        hdr = ctk.CTkFrame(r, height=28, fg_color=C["bg_panel"],
                           corner_radius=0)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="  TEAMCYBEROPS  V5.0",
                     text_color=C["accent"],
                     font=F(9, bold=True, mono=True),
                     anchor="w").pack(side="left", padx=12)
        self._hdr_dot = ctk.CTkLabel(hdr, text="SYS:READY",
                                      text_color=C["green"],
                                      font=F(9, mono=True))
        self._hdr_dot.pack(side="right", padx=12)
        ctk.CTkFrame(r, height=1, fg_color=C["border_mid"],
                     corner_radius=0).pack(fill="x", side="top")

        # ── Body ──────────────────────────────────────────────────
        body = ctk.CTkFrame(r, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=32, pady=16)

        # ── Org Logo (TeamCyberOps Owl Badge) ─────────────────────
        logo_path = _HERE / "org_logo.jpg"
        if not logo_path.exists():
            logo_path = _HERE / "org_logo.png"

        if logo_path.exists():
            try:
                from PIL import Image
                img = Image.open(logo_path)
                # Crop to square, center
                w, h = img.size
                s = min(w, h)
                img = img.crop(((w-s)//2, (h-s)//2, (w+s)//2, (h+s)//2))
                img = img.resize((110, 110), Image.LANCZOS)
                ctk_img = ctk.CTkImage(light_image=img,
                                        dark_image=img,
                                        size=(110, 110))
                logo_f = ctk.CTkFrame(body, fg_color="transparent")
                logo_f.pack(pady=(0, 8))
                ctk.CTkLabel(logo_f, image=ctk_img,
                             text="").pack()
            except Exception as e:
                self._text_logo(body)
        else:
            self._text_logo(body)

        # ── Title block ───────────────────────────────────────────
        ctk.CTkLabel(body, text="TeamCyberOps Suite",
                     text_color=C["text_bright"],
                     font=F(18, bold=True)).pack()
        ctk.CTkLabel(body,
                     text="MONITOR  AND  PROTECT",
                     text_color=C["accent"],
                     font=F(9, bold=True, mono=True)).pack(pady=(1, 0))
        ctk.CTkLabel(body,
                     text="Elite Bug Bounty Framework  //  AI-Powered  //  v5.0",
                     text_color=C["text_muted"],
                     font=F(8, mono=True)).pack(pady=(1, 0))
        ctk.CTkLabel(body,
                     text="github.com/mohidqx",
                     text_color=C["accent_dim"],
                     font=F(8, mono=True),
                     cursor="hand2").pack(pady=(1, 0))

        # ── Tag pills ─────────────────────────────────────────────
        tf = ctk.CTkFrame(body, fg_color="transparent")
        tf.pack(pady=(10, 12))
        for tag, fg, bg in [
            ("[BUG-BOUNTY]", C["accent"],  C["bg_input"]),
            ("[KALI-LINUX]", C["green"],   C["bg_input"]),
            ("[GEMINI-AI]",  C["purple"],  C["bg_input"]),
            ("[v5.0]",       C["yellow"],  C["bg_input"]),
        ]:
            ctk.CTkLabel(tf, text=tag, text_color=fg,
                         fg_color=bg,
                         font=F(8, bold=True, mono=True),
                         corner_radius=2).pack(side="left", padx=2)

        # ── Auth card ─────────────────────────────────────────────
        card = ctk.CTkFrame(body, fg_color=C["bg_card"],
                             border_color=C["border_mid"],
                             border_width=1, corner_radius=4)
        card.pack(fill="x")

        # Card accent bar
        ctk.CTkFrame(card, height=2, fg_color=C["accent"],
                     corner_radius=0).pack(fill="x")

        # Card header
        ch = ctk.CTkFrame(card, fg_color=C["bg_panel"],
                          corner_radius=0)
        ch.pack(fill="x")
        ctk.CTkLabel(ch, text="  >> SECURE ACCESS",
                     text_color=C["accent"],
                     font=F(10, bold=True, mono=True),
                     anchor="w").pack(side="left", padx=12, pady=8)
        self._dot = ctk.CTkLabel(ch, text="[READY]",
                                  text_color=C["green"],
                                  font=F(9, mono=True))
        self._dot.pack(side="right", padx=12)
        ctk.CTkFrame(card, height=1, fg_color=C["border"],
                     corner_radius=0).pack(fill="x")

        # Form
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=20, pady=16)

        self._pass_entry = None
        for field, var, is_pass in [
            ("USERNAME", self._uv, False),
            ("PASSWORD", self._pv, True),
        ]:
            ctk.CTkLabel(form, text=f"  {field}",
                         text_color=C["text_muted"],
                         font=F(8, bold=True, mono=True),
                         anchor="w").pack(fill="x", pady=(0, 2))

            row = ctk.CTkFrame(form, fg_color=C["bg_input"],
                                border_color=C["border_mid"],
                                border_width=1, corner_radius=3)
            row.pack(fill="x", pady=(0, 10))

            ctk.CTkLabel(row, text=">",
                         text_color=C["accent"],
                         font=F(11, bold=True, mono=True),
                         width=28).pack(side="left", padx=(8, 0))

            entry = GlowEntry(row, textvariable=var,
                               show="*" if is_pass else "",
                               height=32,
                               border_width=0,
                               fg_color="transparent",
                               corner_radius=0)
            entry.pack(side="left", fill="x",
                        expand=True, padx=(2, 6))

            if is_pass:
                self._pass_entry = entry
                _sv = ctk.BooleanVar(value=False)
                def _toggle(e=entry, s=_sv):
                    s.set(not s.get())
                    e.configure(show="" if s.get() else "*")
                ctk.CTkButton(
                    row, text="[*]", width=32, height=28,
                    fg_color="transparent",
                    hover_color=C["bg_hover"],
                    text_color=C["text_muted"],
                    font=F(9, mono=True),
                    border_width=0, corner_radius=0,
                    command=_toggle).pack(side="right", padx=(0, 4))
                entry.bind("<Return>", lambda e: self._login())

        # Error label
        self._err = ctk.CTkLabel(form, text="",
                                   text_color=C["red"],
                                   font=F(9, mono=True))
        self._err.pack(pady=(0, 6))

        # Login button
        FilledButton(form,
                      text="  >>  AUTHENTICATE  >>",
                      command=self._login,
                      color=C["accent"],
                      height=38).pack(fill="x")

        # Card footer
        ctk.CTkFrame(card, height=1, fg_color=C["border"],
                     corner_radius=0).pack(fill="x")
        foot = ctk.CTkFrame(card, fg_color="transparent")
        foot.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(foot, text="default:  admin / admin",
                     text_color=C["text_dim"],
                     font=F(8, mono=True)).pack(side="left")
        ctk.CTkLabel(foot, text="v5.0",
                     text_color=C["text_dim"],
                     font=F(8, mono=True)).pack(side="right")

        # ── Bottom bars ───────────────────────────────────────────
        ctk.CTkFrame(r, height=1, fg_color=C["border_mid"],
                     corner_radius=0).pack(fill="x", side="bottom")
        ctk.CTkFrame(r, height=2, fg_color=C["teal"],
                     corner_radius=0).pack(fill="x", side="bottom")

    def _text_logo(self, parent):
        """Fallback text logo if image fails."""
        lf = ctk.CTkFrame(parent, fg_color="transparent")
        lf.pack(pady=(0, 8))
        for ln, col in [
            (" /==========\\ ", C["accent"]),
            (" |  TEAM     | ", C["accent"]),
            (" |  CYBEROPS | ", C["green"]),
            (" \\==========/ ", C["accent_dim"]),
        ]:
            ctk.CTkLabel(lf, text=ln, text_color=col,
                         font=F(11, bold=True, mono=True)).pack()

    def _login(self):
        u = self._uv.get().strip()
        p = self._pv.get().strip()
        if not u or not p:
            self._err.configure(text="[ERR] enter credentials")
            return
        self._dot.configure(text="[CHECKING...]",
                             text_color=C["yellow"])
        self._err.configure(text="")
        self.root.update()

        def _check():
            user = verify_user(u, p)
            def _done():
                if user:
                    self.user = user
                    self._dot.configure(text="[AUTH-OK]",
                                        text_color=C["green"])
                    self.root.after(220, self.root.destroy)
                else:
                    self._dot.configure(text="[DENIED]",
                                        text_color=C["red"])
                    self._err.configure(
                        text="[ERR] invalid credentials")
                    self._pv.set("")
                    self.root.after(2500, lambda: self._dot.configure(
                        text="[READY]", text_color=C["green"]))
            self.root.after(0, _done)

        threading.Thread(target=_check, daemon=True).start()
