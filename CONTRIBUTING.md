# Contributing to TeamCyberOps Suite

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/mohidqx/TeamCyberOps_v5
cd TeamCyberOps_v5
pip install customtkinter pillow requests psutil
python main.py
```

## Project Structure

```
app/ui/tabs/          ← Add new tabs here (mixin pattern)
modules/              ← Add new security modules here
app/ui/theme.py       ← Design system (colors, widgets)
app/core/database.py  ← SQLite schema and queries
```

## Adding a New Tab

1. Add method to the appropriate mixin in `app/ui/tabs/`
2. Register it in `TABS` list in `app/ui/app_window.py`
3. Method signature: `def _tab_yourname(self, frame): ...`

```python
# Example tab method
def _tab_my_tool(self, frame):
    frame.configure(fg_color=C["bg_app"])
    pad = ctk.CTkScrollableFrame(frame, fg_color="transparent")
    pad.pack(fill="both", expand=True, padx=20, pady=14)
    Section(pad, "MY TOOL", ">>", C["accent"]).pack(fill="x", pady=(0,10))
    # ... your UI here
```

## Code Guidelines

- **Colors**: Always use `C["key"]` from theme — never raw hex with alpha (`#RRGGBBAA` breaks Tkinter)
- **Hover tints**: Use `get_tint(color)` for pre-blended hover colors
- **Threads**: Always wrap `_go()` in `try/except`, use `root.after(0, ...)` for GUI updates
- **StringVar**: Create `ctk.CTk()` root BEFORE any `ctk.StringVar()`
- **Override-friendly widgets**: Use `defaults = {...}; defaults.update(kw); super().__init__(..., **defaults)`

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Run validation: `python3 -c "from app.ui.app_window import App, TABS; print('OK')"`
4. Commit: `git commit -m "feat: description"`
5. Push and open PR against `main`

## Bug Reports

Open an issue with:
- Python version + OS
- Full traceback
- Steps to reproduce

## Security

Found a security issue in the framework itself? Email the maintainer privately before opening a public issue.
