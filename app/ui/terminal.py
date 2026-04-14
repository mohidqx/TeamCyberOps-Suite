"""
TeamCyberOps V5 — Terminal Panel Module
Integrated terminal at bottom of main window for real-time command execution
"""
import customtkinter as ctk
import subprocess
import threading
import queue
from datetime import datetime
from pathlib import Path
from app.ui.theme import C, F, Terminal
from app.core.config import cfg


class TerminalPanel:
    """Manages integrated terminal panel with command history and live output."""
    
    def __init__(self, parent):
        """Initialize terminal panel with container."""
        self.parent = parent
        self.process = None
        self.output_queue = queue.Queue()
        self.is_running = False
        self.command_history = []
        self.history_index = -1
        
    def build(self, frame):
        """Build terminal UI panel."""
        # ── Container ────────────────────────────────────────────
        self.container = ctk.CTkFrame(frame, fg_color=C["bg_panel"])
        self.container.pack(fill="both", expand=False, padx=0, pady=0)
        
        # ── Header bar ───────────────────────────────────────────
        hdr = ctk.CTkFrame(self.container, height=32, fg_color=C["bg_panel"])
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)
        
        ctk.CTkFrame(hdr, height=1, fg_color=C["border_accent"]).pack(fill="x")
        
        inner_hdr = ctk.CTkFrame(hdr, fg_color="transparent")
        inner_hdr.pack(fill="x", padx=10, pady=6)
        
        ctk.CTkLabel(inner_hdr, text="  ◆ TERMINAL",
                     text_color=C["accent"],
                     font=F(10, bold=True, mono=True),
                     anchor="w").pack(side="left")
        
        self.status_lbl = ctk.CTkLabel(inner_hdr, text="● READY",
                                       text_color=C["green"],
                                       font=F(9, mono=True))
        self.status_lbl.pack(side="left", padx=12)
        
        # Buttons
        btn_frame = ctk.CTkFrame(inner_hdr, fg_color="transparent")
        btn_frame.pack(side="right")
        
        from app.ui.theme import NeonButton
        NeonButton(btn_frame, text="CLEAR", command=self.clear,
                   color=C["text_muted"], small=True).pack(side="left", padx=4)
        NeonButton(btn_frame, text="STOP", command=self.stop_process,
                   color=C["red"], small=True).pack(side="left", padx=2)
        
        # ── Main terminal area ───────────────────────────────────
        main = ctk.CTkFrame(self.container, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=8, pady=6)
        
        self.terminal = Terminal(main, height=160, corner_radius=4)
        self.terminal.pack(fill="both", expand=True)
        
        # ── Command input bar ────────────────────────────────────
        cmd_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        cmd_frame.pack(fill="x", padx=8, pady=(0, 8))
        
        ctk.CTkLabel(cmd_frame, text="$",
                     text_color=C["accent"],
                     font=F(11, bold=True, mono=True)).pack(side="left", padx=(0, 6))
        
        self.cmd_input = ctk.CTkEntry(
            cmd_frame,
            fg_color=C["bg_input"],
            border_color=C["border_mid"],
            border_width=1,
            text_color=C["text"],
            placeholder_text="Enter command or type 'help'...",
            placeholder_text_color=C["text_dim"],
            font=F(10, mono=True),
            height=28,
            corner_radius=3
        )
        self.cmd_input.pack(side="left", fill="x", expand=True)
        self.cmd_input.bind("<Return>", lambda e: self.execute_command())
        self.cmd_input.bind("<Up>", lambda e: self._prev_history())
        self.cmd_input.bind("<Down>", lambda e: self._next_history())
        
        from app.ui.theme import FilledButton
        FilledButton(cmd_frame, text="RUN",
                     command=self.execute_command,
                     color=C["green"],
                     height=28).pack(side="left", padx=4)
        
    def execute_command(self):
        """Execute command from input and show output."""
        cmd = self.cmd_input.get().strip()
        if not cmd:
            return
            
        # Store in history
        if not self.command_history or self.command_history[-1] != cmd:
            self.command_history.append(cmd)
        self.history_index = -1
        
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] $ {cmd}", "hdr")
        
        # Handle built-in commands
        if cmd.lower() == "help":
            self.show_help()
            return
        elif cmd.lower() == "clear":
            self.clear()
            return
        elif cmd.lower().startswith("cd "):
            self.log("[-] Use tabs to navigate projects", "warn")
            return
        
        # Execute system command
        self.run_command(cmd)
        self.cmd_input.delete(0, "end")
        
    def run_command(self, cmd: str):
        """Run command asynchronously."""
        if self.is_running:
            self.log("[-] Command already running", "err")
            return
            
        self.is_running = True
        self.status_lbl.configure(text="● RUNNING", text_color=C["yellow"])
        
        def _run():
            try:
                # Determine shell based on OS
                import sys
                shell = sys.platform.startswith("win")
                
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=cfg.get("work_dir", ".")
                )
                self.process = proc
                
                # Read stdout
                for line in proc.stdout:
                    self.output_queue.put(("stdout", line.rstrip()))
                
                # Wait and get stderr
                proc.wait()
                for line in proc.stderr:
                    self.output_queue.put(("stderr", line.rstrip()))
                    
                exit_code = proc.returncode
                self.output_queue.put(("exit", exit_code))
                
            except Exception as e:
                self.output_queue.put(("error", str(e)))
                self.output_queue.put(("exit", 1))
        
        # Start command thread
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        
        # Start output consumer
        self._consume_output()
        
    def _consume_output(self):
        """Consume output queue and display in terminal."""
        try:
            while self.is_running:
                try:
                    msg_type, msg = self.output_queue.get(timeout=0.1)
                    
                    if msg_type == "stdout":
                        self.log(msg, "ok")
                    elif msg_type == "stderr":
                        self.log(msg, "err")
                    elif msg_type == "error":
                        self.log(f"[ERROR] {msg}", "err")
                    elif msg_type == "exit":
                        code = msg
                        color = "ok" if code == 0 else "err"
                        self.log(f"\n[{datetime.now().strftime('%H:%M:%S')}] Process exited with code {code}", color)
                        self.is_running = False
                        self.status_lbl.configure(text="● READY", text_color=C["green"])
                        
                except queue.Empty:
                    pass
                    
                # Check if parent still exists
                try:
                    self.parent.update()
                except:
                    break
                    
        except Exception:
            pass
        
    def stop_process(self):
        """Stop running process."""
        if self.process and self.is_running:
            try:
                import signal
                import os
                if hasattr(signal, "CTRL_C_EVENT"):
                    os.kill(self.process.pid, signal.CTRL_C_EVENT)
                else:
                    self.process.terminate()
                self.log("[*] Process terminated", "warn")
            except Exception as e:
                self.log(f"[-] Failed to stop: {e}", "err")
        self.is_running = False
        self.status_lbl.configure(text="● READY", text_color=C["green"])
        
    def log(self, msg: str, tag: str = ""):
        """Log message to terminal."""
        try:
            self.terminal.log(msg, tag)
        except:
            pass
        
    def clear(self):
        """Clear terminal output."""
        self.terminal.clear()
        self.log("[*] Terminal cleared", "info")
        
    def show_help(self):
        """Show help text."""
        help_text = """
☆ TeamCyberOps Terminal — Built-in Commands ☆

RECON:
  subfinder -d <domain>          # Find subdomains
  amass enum -d <domain>         # Passive subdomain enum
  httpx -l urls.txt              # HTTP probes

SCANNING:
  nuclei -l urls.txt             # Run Nuclei templates
  dalfox url <url>               # XSS scanner
  sqlmap -u <url> -p <param>     # SQLi tester

EXPLOITATION:
  python main.py                 # Start GUI

INFO:
  help                           # This message
  clear                          # Clear terminal
  
Tip: Use ↑/↓ arrow keys for command history
"""
        for line in help_text.strip().split("\n"):
            self.log(line, "info")
        
    def _prev_history(self):
        """Go to previous command in history."""
        if not self.command_history:
            return
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            cmd = self.command_history[-(self.history_index + 1)]
            self.cmd_input.delete(0, "end")
            self.cmd_input.insert(0, cmd)
            
    def _next_history(self):
        """Go to next command in history."""
        if self.history_index > 0:
            self.history_index -= 1
            cmd = self.command_history[-(self.history_index + 1)]
            self.cmd_input.delete(0, "end")
            self.cmd_input.insert(0, cmd)
        elif self.history_index == 0:
            self.history_index = -1
            self.cmd_input.delete(0, "end")
