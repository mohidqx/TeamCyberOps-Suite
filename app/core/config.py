"""
TeamCyberOps V5 — Config Manager
Single source of truth for all settings
"""
from pathlib import Path
from app.core.database import get_config, set_config, get_all_config

BASE_DIR = Path(__file__).parent.parent.parent

DEFAULTS = {
    "api_keys": {
        "gemini_api_key":    "",
        "claude_api_key":    "",
        "shodan":            "",
        "censys_id":         "",
        "censys_secret":     "",
        "github_token":      "",
        "hunter":            "",
        "virustotal":        "",
        "securitytrails":    "",
        "nvd_api_key":       "",
    },
    "proxy": {
        "enabled":  False,
        "host":     "127.0.0.1",
        "port":     "8080",
        "type":     "http",
    },
    "wordlists": {
        "directories":   str(BASE_DIR / "wordlists" / "directories.txt"),
        "subdomains":    str(BASE_DIR / "wordlists" / "subdomains.txt"),
        "passwords":     str(BASE_DIR / "wordlists" / "passwords.txt"),
        "parameters":    str(BASE_DIR / "wordlists" / "parameters.txt"),
        "api":           str(BASE_DIR / "wordlists" / "api_endpoints.txt"),
        "xss":           str(BASE_DIR / "wordlists" / "xss_payloads.txt"),
        "sqli":          str(BASE_DIR / "wordlists" / "sqli_payloads.txt"),
        "lfi":           str(BASE_DIR / "wordlists" / "lfi_paths.txt"),
    },
    "notifications": {
        "telegram_token":   "",
        "telegram_chat_id": "",
        "discord_webhook":  "",
        "notify_new_sub":   False,
        "notify_new_vuln":  True,
    },
    "ai": {
        "provider":      "gemini",
        "gemini_model":  "gemini-2.0-flash-exp",
        "claude_model":  "claude-sonnet-4-6",
        "auto_exploit":  True,
        "auto_report":   True,
    },
    "scan": {
        "threads":       50,
        "timeout":       10,
        "delay":         0,
        "user_agent":    "TeamCyberOps/5.0 Security Scanner",
        "follow_redirects": True,
        "verify_ssl":    False,
    },
    "ui": {
        "theme":         "dark",
        "accent":        "blue",
        "font_size":     12,
        "show_tooltips": True,
        "sidebar_width": 220,
    },
    "nuclei_templates_dir": str(BASE_DIR / "nuclei-templates"),
    "logs_dir":             str(BASE_DIR / "logs"),
    "reports_dir":          str(BASE_DIR / "reports"),
    "screenshots_dir":      str(BASE_DIR / "screenshots"),
}


class Config:
    """Single config instance — loads from DB with defaults fallback."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._cache = {}
            cls._instance._load()
        return cls._instance

    def _load(self):
        db_cfg = get_all_config()
        # Merge defaults with DB values
        self._cache = DEFAULTS.copy()
        for key, val in db_cfg.items():
            if "." in key:
                parts = key.split(".", 1)
                if parts[0] in self._cache and isinstance(self._cache[parts[0]], dict):
                    self._cache[parts[0]][parts[1]] = val
                else:
                    self._cache[key] = val
            else:
                self._cache[key] = val

    def get(self, key: str, default=None):
        """Get config value. Supports dot notation: 'api_keys.gemini_api_key'"""
        if "." in key:
            parts = key.split(".", 1)
            section = self._cache.get(parts[0], {})
            if isinstance(section, dict):
                return section.get(parts[1], default)
        return self._cache.get(key, default)

    def set(self, key: str, value):
        """Set config value and persist to DB + config.json."""
        if "." in key:
            parts = key.split(".", 1)
            if parts[0] not in self._cache:
                self._cache[parts[0]] = {}
            if isinstance(self._cache[parts[0]], dict):
                self._cache[parts[0]][parts[1]] = value
        else:
            self._cache[key] = value
        set_config(key, value)
        # Keep config.json in sync for legacy modules
        try:
            import json as _json
            cfg_path = BASE_DIR / "config.json"
            existing = _json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
            if "." in key:
                parts = key.split(".", 1)
                existing.setdefault(parts[0], {})[parts[1]] = value
            else:
                existing[key] = value
            cfg_path.write_text(_json.dumps(existing, indent=2))
        except Exception:
            pass

    def get_api_key(self, service: str) -> str:
        return self.get(f"api_keys.{service}", "")

    def set_api_key(self, service: str, key: str):
        self.set(f"api_keys.{service}", key)

    def get_wordlist(self, purpose: str) -> str:
        path = self.get(f"wordlists.{purpose}", "")
        if path and Path(path).exists():
            return path
        # Fallback to built-in
        builtin = BASE_DIR / "wordlists" / f"{purpose}.txt"
        return str(builtin) if builtin.exists() else ""

    @property
    def api_keys(self): return self._cache.get("api_keys", {})
    @property
    def proxy(self):    return self._cache.get("proxy", {})
    @property
    def ai(self):       return self._cache.get("ai", {})
    @property
    def scan(self):     return self._cache.get("scan", {})
    @property
    def ui(self):       return self._cache.get("ui", {})

    def reload(self):
        self._load()


# Singleton instance
cfg = Config()
