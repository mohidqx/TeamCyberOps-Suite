"""TeamCyberOps V5 — AI Tabs (Gemini-powered)"""
import customtkinter as ctk, threading, json
from app.ui.theme import C, F, Card, Section, NeonButton, FilledButton, GlowEntry, Terminal
from app.core.database import load_findings, save_finding
from app.core.config import cfg


def _gemini(prompt, system="You are a cybersecurity expert.", api_key="", max_tokens=2048):
    """Call Gemini API — returns text response."""
    import urllib.request, urllib.parse
    if not api_key:
        api_key = cfg.get_api_key("gemini_api_key")
    if not api_key:
        return "ERROR: Gemini API key not set. Go to Settings → API Keys."
    try:
        model = cfg.get("ai.gemini_model", "gemini-2.0-flash-exp")
        url   = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        body  = json.dumps({"contents":[{"parts":[{"text":f"{system}\n\n{prompt}"}]}],
                             "generationConfig":{"maxOutputTokens":max_tokens}}).encode()
        req   = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8","replace")
        return f"API Error {e.code}: {body[:200]}"
    except Exception as ex:
        return f"Error: {ex}"


class AIMixin:

    def _tab_ai_assistant(self, frame):
        frame.configure()
        pad = ctk.CTkFrame(frame)
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "AI SECURITY ASSISTANT — Gemini Flash", "🤖", C["purple"]).pack(fill="x", pady=(0,10))

        # API key row
        key_row = ctk.CTkFrame(pad); key_row.pack(fill="x", pady=(0,6))
        ctk.CTkLabel(key_row, text="Gemini API Key:",
                     font=F(10, mono=True), width=130, anchor="e").pack(side="left", padx=(0,8))
        self._ai_key = ctk.StringVar(value=cfg.get_api_key("gemini_api_key"))
        GlowEntry(key_row, textvariable=self._ai_key, show="●", width=380, height=32).pack(side="left")
        NeonButton(key_row, text="💾 Save", small=True, color=C["green"],
                   command=lambda v=None: (cfg.set_api_key("gemini_api_key", self._ai_key.get().strip()),
                                    self.set_status("Gemini key saved!",C["green"]))).pack(side="left", padx=8)
        ctk.CTkLabel(key_row, text="Free at: aistudio.google.com", font=F(9)).pack(side="left", padx=8)

        # Chat area
        self._ai_chat = ctk.CTkTextbox(pad, font=F(11))
        self._ai_chat.pack(fill="both", expand=True, pady=(8,8))
        self._ai_chat._textbox.tag_configure("user", foreground=C["accent"])
        self._ai_chat._textbox.tag_configure("ai",   foreground=C["text"])
        self._ai_chat._textbox.tag_configure("sys",  foreground=C["text_muted"])

        # Input
        inp_row = ctk.CTkFrame(pad); inp_row.pack(fill="x")
        self._ai_input = GlowEntry(inp_row, placeholder_text="Ask anything about cybersecurity, vulns, exploits...",
                                    height=36)
        self._ai_input.pack(side="left", fill="x", expand=True)
        self._ai_input.bind("<Return>", lambda e: self._ai_send())
        FilledButton(inp_row, text="  ▶ Send  ", command=self._ai_send,
                     color=C["purple"]).pack(side="left", padx=(8,0), ipady=2)

        # Quick prompts
        qp_row = ctk.CTkFrame(pad); qp_row.pack(fill="x", pady=(6,0))
        for label, prompt in [
            ("XSS Bypass WAF",    "Give me 10 advanced XSS payloads that bypass WAFs (Cloudflare, Akamai)"),
            ("SQLi Techniques",   "Explain 5 advanced SQL injection techniques with PoC examples"),
            ("SSRF to RCE",       "How can SSRF be chained to achieve RCE? Give step-by-step attack chain"),
            ("JWT Attacks",       "What are all JWT attack techniques? Include PoC for each"),
            ("API Security",      "Top 10 API security vulnerabilities with exploitation examples"),
        ]:
            NeonButton(qp_row, text=label, small=True, color=C["text_dim"],
                       command=lambda p=prompt: (self._ai_input.delete(0,"end"),
                                                  self._ai_input.insert(0,p))).pack(side="left", padx=3)

        self._ai_chat_history = []
        self._ai_log("Welcome to AI Security Assistant powered by Gemini Flash.\n"
                      "Ask about vulnerabilities, exploits, techniques, or get help with findings.\n","sys")

    def _ai_log(self, text, tag="ai"):
        self._ai_chat.configure()
        self._ai_chat.insert("end", text, tag)
        self._ai_chat.see("end")
        self._ai_chat.configure()

    def _ai_send(self):
        msg = self._ai_input.get().strip()
        if not msg: return
        self._ai_input.delete(0,"end")
        self._ai_log(f"\n👤 You: {msg}\n","user")
        self._ai_log("⏳ Gemini is thinking...\n","sys")
        proj = self.project.get()
        # Add project context
        system = ("You are an elite bug bounty hunter and penetration tester. "
                  "Give precise, technical, actionable answers. Include PoC code when relevant. "
                  f"Current project: {proj}" if proj else
                  "You are an elite bug bounty hunter and penetration tester. "
                  "Give precise, technical, actionable answers. Include PoC code when relevant.")
        def _go():
            try:
                response = _gemini(msg, system=system, api_key=self._ai_key.get().strip())
                def _upd():
                    # Remove "thinking" message
                    content = self._ai_chat.get("0.0","end")
                    content = content.replace("⏳ Gemini is thinking...\n","")
                    self._ai_chat.configure()
                    self._ai_chat.delete("0.0","end")
                    self._ai_chat.insert("0.0", content)
                    self._ai_log(f"\n🤖 Gemini:\n{response}\n\n","ai")
                    self.set_status("AI response received",C["purple"])
                self.root.after(0, _upd)
            except Exception as _e:
                import traceback
                print(f'[Thread Error] {_e}')
        threading.Thread(target=_go, daemon=True).start()

    # ── AI AUTO-EXPLOIT ───────────────────────────────────────────
    def _tab_ai_exploit(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "AI AUTO-EXPLOIT ENGINE — Gemini Flash", "🧠", C["red"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["red"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Select any finding → Gemini generates: PoC code · Attack chain · Impact analysis\n"
            "Chain Analyzer: find exploit chains across ALL findings\n"
            "Bounty Estimator: estimated payout + severity justification"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        # API key
        key_row = ctk.CTkFrame(pad); key_row.pack(fill="x", pady=(0,8))
        ctk.CTkLabel(key_row, text="Gemini API Key:",
                     font=F(10, mono=True), width=130, anchor="e").pack(side="left", padx=(0,8))
        self._ae_key = ctk.StringVar(value=cfg.get_api_key("gemini_api_key"))
        GlowEntry(key_row, textvariable=self._ae_key, show="●", width=340, height=32).pack(side="left")

        nb = ctk.CTkTabview(pad,
                             segmented_button_fg_color=C["bg_input"],
                             segmented_button_selected_color=C["bg_selected"],
                             segmented_button_unselected_color=C["bg_input"])
        nb.pack(fill="both", expand=True)
        for t in ["💣 PoC Generator","🔗 Chain Analyzer","💰 Bounty Estimator","🎯 Attack Suggester"]:
            nb.add(t)

        # PoC Generator
        pg = nb.tab("💣 PoC Generator")
        ctk.CTkLabel(pg, text="Select Finding:",
                     font=F(10, mono=True), anchor="w").pack(fill="x", padx=10, pady=(8,4))
        findings = load_findings(project=self.project.get() if self.project.get() else None)
        choices  = [f"[{f.get('severity','?')}] {f.get('title','?')[:60]}" for f in findings]
        self._ae_finding = ctk.StringVar(value=choices[0] if choices else "No findings — run a scan first")
        self._ae_combo = ctk.CTkComboBox(pg, variable=self._ae_finding, values=choices or ["No findings"], font=F(11, mono=True),
                                          width=600, height=34)
        self._ae_combo.pack(fill="x", padx=10)
        self._ae_term_poc = Terminal(pg, height=16)
        self._ae_term_poc.pack(fill="both", expand=True, padx=10, pady=(6,8))
        def _gen_poc():
            sel = self._ae_finding.get()
            if not sel or "No findings" in sel: return
            idx  = choices.index(sel) if sel in choices else 0
            f    = findings[idx] if idx < len(findings) else {}
            self._ae_term_poc.clear()
            self._ae_term_poc.log("⏳ Generating PoC with Gemini...","sys")
            def _go():
                prompt = (f"Generate a complete, working PoC (Proof of Concept) exploit for this vulnerability:\n\n"
                          f"Title: {f.get('title','')}\n"
                          f"Type: {f.get('type','')}\n"
                          f"Severity: {f.get('severity','')}\n"
                          f"URL: {f.get('url','')}\n"
                          f"Description: {f.get('description','')}\n\n"
                          f"Include: 1) Step-by-step exploitation 2) Working PoC code (Python/curl/JS) "
                          f"3) Impact demonstration 4) Remediation recommendation")
                result = _gemini(prompt, api_key=self._ae_key.get().strip())
                self.root.after(0, lambda: (self._ae_term_poc.clear(),
                                            self._ae_term_poc.log(result,"ok")))
            threading.Thread(target=_go, daemon=True).start()
        NeonButton(pg, text="📋 Refresh Findings", small=True, color=C["text_dim"],
                   command=lambda v=None: self._refresh_ae_findings()).pack(side="left", padx=10, pady=(0,4))
        FilledButton(pg, text="💣 Generate PoC", command=_gen_poc, color=C["red"]).pack(
            side="left", padx=4, pady=(0,8), ipady=4)

        # Chain Analyzer
        ca = nb.tab("🔗 Chain Analyzer")
        self._ae_term_chain = Terminal(ca, height=20)
        self._ae_term_chain.pack(fill="both", expand=True, padx=10, pady=8)
        def _analyze_chains():
            proj  = self.project.get()
            finds = load_findings(project=proj if proj else None)
            if not finds:
                self.set_status("No findings to analyze","yellow"); return
            self._ae_term_chain.clear()
            self._ae_term_chain.log("⏳ Gemini analyzing exploit chains...","sys")
            def _go():
                summary = "\n".join([f"- [{f.get('severity')}] {f.get('title')} ({f.get('type')}) at {f.get('url','')}"
                                     for f in finds[:20]])
                prompt = (f"Analyze these security findings and identify exploit chains:\n\n{summary}\n\n"
                          f"For each chain: 1) Which vulns combine? 2) Step-by-step attack path "
                          f"3) Combined severity 4) Estimated bounty impact")
                result = _gemini(prompt, api_key=self._ae_key.get().strip(), max_tokens=3000)
                self.root.after(0, lambda: (self._ae_term_chain.clear(),
                                            self._ae_term_chain.log(result,"ok")))
            threading.Thread(target=_go, daemon=True).start()
        FilledButton(ca, text="🔗 Analyze Chains", command=_analyze_chains, color=C["purple"]).pack(
            side="left", padx=10, pady=(0,8), ipady=4)

        # Bounty Estimator
        be = nb.tab("💰 Bounty Estimator")
        self._ae_term_bounty = Terminal(be, height=20)
        self._ae_term_bounty.pack(fill="both", expand=True, padx=10, pady=8)
        r_be = ctk.CTkFrame(be); r_be.pack(fill="x", padx=10, pady=(0,4))
        ctk.CTkLabel(r_be, text="Platform:", font=F(10,mono=True)).pack(side="left")
        self._ae_platform = ctk.StringVar(value="HackerOne")
        ctk.CTkComboBox(r_be, variable=self._ae_platform,
                        values=["HackerOne","Bugcrowd","Intigriti","YesWeHack","Private Program"],
                        width=160, height=30, font=F(11,mono=True)).pack(side="left", padx=8)
        def _estimate_bounty():
            sel   = self._ae_finding.get() if hasattr(self,"_ae_finding") else ""
            if not sel or "No findings" in sel:
                finds = load_findings(project=self.project.get() if self.project.get() else None)
                f = finds[0] if finds else {}
            else:
                idx = choices.index(sel) if sel in choices else 0
                f   = findings[idx] if idx < len(findings) else {}
            self._ae_term_bounty.clear()
            self._ae_term_bounty.log("⏳ Estimating bounty...","sys")
            def _go():
                prompt = (f"Estimate the bug bounty payout for this vulnerability on {self._ae_platform.get()}:\n\n"
                          f"Title: {f.get('title','')}\nType: {f.get('type','')}\n"
                          f"Severity: {f.get('severity','')}\nURL: {f.get('url','')}\n"
                          f"Description: {f.get('description','')}\n\n"
                          f"Provide: 1) Estimated range $X-$Y 2) CVSS score justification "
                          f"3) What makes this more/less valuable 4) How to maximize payout")
                result = _gemini(prompt, api_key=self._ae_key.get().strip())
                self.root.after(0, lambda: (self._ae_term_bounty.clear(),
                                            self._ae_term_bounty.log(result,"ok")))
            threading.Thread(target=_go, daemon=True).start()
        FilledButton(be, text="💰 Estimate Bounty", command=_estimate_bounty, color=C["green"]).pack(
            side="left", padx=10, pady=(0,8), ipady=4)

        # Attack Suggester
        atk = nb.tab("🎯 Attack Suggester")
        r_atk = ctk.CTkFrame(atk); r_atk.pack(fill="x", padx=10, pady=(8,4))
        ctk.CTkLabel(r_atk, text="Target URL / Domain:",
                     font=F(10,mono=True), width=160, anchor="e").pack(side="left", padx=(0,8))
        self._ae_atk_target = ctk.StringVar(value=f"https://{self.project.get()}" if self.project.get() else "")
        GlowEntry(r_atk, textvariable=self._ae_atk_target, width=380, height=32).pack(side="left")
        self._ae_term_atk = Terminal(atk, height=18)
        self._ae_term_atk.pack(fill="both", expand=True, padx=10, pady=(4,8))
        def _suggest_attacks():
            target = self._ae_atk_target.get().strip()
            if not target: return
            self._ae_term_atk.clear()
            self._ae_term_atk.log("⏳ Generating attack plan...","sys")
            def _go():
                prompt = (f"As a bug bounty hunter testing {target}, suggest a comprehensive attack plan:\n"
                          f"1) Top 10 highest-value attack vectors to test\n"
                          f"2) What to look for in HTTP responses\n"
                          f"3) Specific payloads for this type of target\n"
                          f"4) Common misconfigs in this technology stack\n"
                          f"5) Tools and commands to use\n"
                          f"Be specific, technical, and prioritize by bounty value.")
                result = _gemini(prompt, api_key=self._ae_key.get().strip(), max_tokens=3000)
                self.root.after(0, lambda: (self._ae_term_atk.clear(),
                                            self._ae_term_atk.log(result,"ok")))
            threading.Thread(target=_go, daemon=True).start()
        FilledButton(atk, text="🎯 Generate Attack Plan", command=_suggest_attacks,
                     color=C["red"]).pack(side="left", padx=10, pady=(0,8), ipady=4)

    def _refresh_ae_findings(self):
        findings = load_findings(project=self.project.get() if self.project.get() else None)
        choices  = [f"[{f.get('severity','?')}] {f.get('title','?')[:60]}" for f in findings]
        if hasattr(self,"_ae_combo"):
            self._ae_combo.configure(values=choices or ["No findings"])
            if choices: self._ae_finding.set(choices[0])

    # ── SMART REPORTER ────────────────────────────────────────────
    def _tab_smart_reporter(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "SMART REPORT WRITER — AI Chains Vulns", "📊", C["green"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["green"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "AI analyzes ALL findings → finds exploit chains → writes professional bug bounty report\n"
            "Output formats: HackerOne · Bugcrowd · Intigriti · Executive Summary\n"
            "Auto-saves report to logs/<project>/report_<platform>.md"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        r1 = ctk.CTkFrame(pad); r1.pack(fill="x", pady=4)
        ctk.CTkLabel(r1, text="Gemini API Key:",
                     font=F(10,mono=True), width=130, anchor="e").pack(side="left", padx=(0,8))
        self._sr_key = ctk.StringVar(value=cfg.get_api_key("gemini_api_key"))
        GlowEntry(r1, textvariable=self._sr_key, show="●", width=340, height=32).pack(side="left")

        r2 = ctk.CTkFrame(pad); r2.pack(fill="x", pady=4)
        ctk.CTkLabel(r2, text="Platform:",
                     font=F(10,mono=True), width=130, anchor="e").pack(side="left", padx=(0,8))
        self._sr_platform = ctk.StringVar(value="HackerOne")
        ctk.CTkComboBox(r2, variable=self._sr_platform,
                        values=["HackerOne","Bugcrowd","Intigriti","YesWeHack","Executive Summary"],
                        width=200, height=32, font=F(11,mono=True)).pack(side="left")

        self._sr_output = ctk.CTkTextbox(pad, font=F(11))
        self._sr_output.pack(fill="both", expand=True, pady=(10,0))

        def _generate():
            api_key = self._sr_key.get().strip()
            if not api_key:
                self.set_status("Enter Gemini API key","red"); return
            proj   = self.project.get()
            finds  = load_findings(project=proj if proj else None)
            if not finds:
                self.set_status("No findings to report","yellow"); return
            self._sr_output.configure()
            self._sr_output.delete("0.0","end")
            self._sr_output.insert("0.0","⏳ AI generating professional report...")
            self._sr_output.configure()
            def _go():
                finds_summary = "\n".join([
                    f"## {i+1}. {f.get('title','')}\n"
                    f"- Severity: {f.get('severity','')}\n"
                    f"- Type: {f.get('type','')}\n"
                    f"- URL: {f.get('url','')}\n"
                    f"- Description: {f.get('description','')}\n"
                    f"- PoC: {f.get('poc','')}\n"
                    f"- Impact: {f.get('impact','')}\n"
                    for i, f in enumerate(finds[:10])
                ])
                platform = self._sr_platform.get()
                prompt = (f"Write a professional {platform}-style bug bounty report for these findings:\n\n"
                          f"Target: {proj or 'Unknown'}\n\n{finds_summary}\n\n"
                          f"Format requirements for {platform}:\n"
                          f"- Executive summary\n"
                          f"- For each finding: title, severity, CVSS, description, PoC steps, impact, remediation\n"
                          f"- Exploit chains if any\n"
                          f"- Professional, clear, persuasive writing\n"
                          f"- Markdown formatted")
                result = _gemini(prompt, api_key=api_key, max_tokens=4000)
                # Save to file
                from pathlib import Path as _P2
                from app.core.config import cfg as _cfg2
                out_dir = _P2(_cfg2.get("logs_dir","logs")) / (proj or "default") / "reports"
                out_dir.mkdir(parents=True, exist_ok=True)
                fname = f"report_{platform.lower().replace(' ','_')}.md"
                (out_dir / fname).write_text(result, encoding="utf-8")
                def _upd():
                    self._sr_output.configure(state="normal")
                    self._sr_output.delete("0.0","end")
                    self._sr_output.insert("0.0", result)
                    self._sr_output.configure(state="disabled")
                    self.set_status(f"Report saved: {fname}",C["green"])
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="📊 Generate Report", command=_generate, color=C["green"]).pack(
            side="left", ipady=4)
        NeonButton(btn_row, text="📋 Copy Report", small=True, color=C["accent"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(self._sr_output.get("0.0","end")),
                                    self.root.update())).pack(side="left", padx=8)

    # ── NUCLEI AI GENERATOR ───────────────────────────────────────
    def _tab_nuclei_ai(self, frame):
        frame.configure()
        pad = ctk.CTkScrollableFrame(frame,
                                      scrollbar_button_color=C["bg_hover"],
                                      scrollbar_button_hover_color=C["accent"])
        pad.pack(fill="both", expand=True, padx=20, pady=14)
        Section(pad, "NUCLEI TEMPLATE AI GENERATOR", "🔬", C["purple"]).pack(fill="x", pady=(0,10))

        info = Card(pad, accent=C["purple"]); info.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(info, text=(
            "Describe a vulnerability → Gemini generates complete Nuclei v3 YAML template\n"
            "Supports: HTTP · DNS · Network · Code matchers · Save to nuclei-templates/ folder"
        ), font=F(10), anchor="w").pack(anchor="w", padx=14, pady=8)

        r1 = ctk.CTkFrame(pad); r1.pack(fill="x", pady=4)
        ctk.CTkLabel(r1, text="Gemini API Key:",
                     font=F(10,mono=True), width=130, anchor="e").pack(side="left", padx=(0,8))
        self._nai_key = ctk.StringVar(value=cfg.get_api_key("gemini_api_key"))
        GlowEntry(r1, textvariable=self._nai_key, show="●", width=340, height=32).pack(side="left")

        ctk.CTkLabel(pad, text="Describe the vulnerability / template:", font=F(10, mono=True), anchor="w").pack(
            anchor="w", pady=(10,4))
        self._nai_desc = ctk.CTkTextbox(pad, height=80,
                                         font=F(11))
        self._nai_desc.pack(fill="x", pady=(0,8))
        self._nai_desc.insert("0.0","Example: Detect exposed .env files containing APP_KEY and DB_PASSWORD")

        self._nai_output = ctk.CTkTextbox(pad, font=F(10, mono=True))
        self._nai_output.pack(fill="both", expand=True)

        def _generate():
            desc = self._nai_desc.get("0.0","end").strip()
            api_key = self._nai_key.get().strip()
            if not desc or not api_key: return
            self._nai_output.configure()
            self._nai_output.delete("0.0","end")
            self._nai_output.insert("0.0","⏳ Generating Nuclei template with Gemini...")
            self._nai_output.configure()
            def _go():
                prompt = (f"Generate a complete, working Nuclei v3 YAML template for:\n\n{desc}\n\n"
                          f"Requirements:\n"
                          f"- Valid Nuclei v3 syntax\n"
                          f"- Include: id, info (name, author, severity, description, tags)\n"
                          f"- Include actual detection logic (matchers, extractors)\n"
                          f"- Use variables where appropriate\n"
                          f"- Output ONLY the YAML, no explanation or markdown fences")
                result = _gemini(prompt, system="You are a Nuclei template expert. Generate complete, accurate Nuclei v3 YAML templates only. No markdown, no explanation.",
                                  api_key=api_key, max_tokens=2000)
                def _upd():
                    self._nai_output.configure()
                    self._nai_output.delete("0.0","end")
                    self._nai_output.insert("0.0", result)
                    self._nai_output.configure()
                    self.set_status("Template generated!",C["green"])
                self.root.after(0, _upd)
            threading.Thread(target=_go, daemon=True).start()

        def _save_template():
            content = self._nai_output.get("0.0","end").strip()
            if not content: return
            import re
            m = re.search(r'^id:\s*(.+)$', content, re.MULTILINE)
            fname = (m.group(1).strip().replace(" ","-") + ".yaml") if m else "ai-template.yaml"
            templates_dir = Path(cfg.get("nuclei_templates_dir","nuclei-templates")) / "ai-generated"
            templates_dir.mkdir(parents=True, exist_ok=True)
            (templates_dir / fname).write_text(content, encoding="utf-8")
            self.set_status(f"Saved: {fname}",C["green"])

        btn_row = ctk.CTkFrame(pad); btn_row.pack(fill="x", pady=(8,0))
        FilledButton(btn_row, text="🔬 Generate Template", command=_generate, color=C["purple"]).pack(
            side="left", ipady=4)
        NeonButton(btn_row, text="💾 Save to Templates", command=_save_template,
                   color=C["green"], small=True).pack(side="left", padx=8)
        NeonButton(btn_row, text="📋 Copy YAML", small=True, color=C["accent"],
                   command=lambda v=None: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(self._nai_output.get("0.0","end")),
                                    self.root.update())).pack(side="left", padx=4)
