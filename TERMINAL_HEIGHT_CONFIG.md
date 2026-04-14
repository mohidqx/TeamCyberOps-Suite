# Terminal Height Configuration Guide

## Overview

TeamCyberOps v5 now features **auto-adjustable terminal heights** across all 40 terminals. You can customize terminal sizes by editing `config.json` without touching any code.

## Configuration

Edit the `terminal` section in `config.json`:

```json
{
  "terminal": {
    "default_height": 25,
    "vuln_scanner_height": 28,
    "auto_adjust": true,
    "max_height": 35,
    "min_height": 15
  }
}
```

### Configuration Options

| Key | Default | Description |
|-----|---------|-------------|
| `default_height` | `25` | Default terminal height for all tabs (in lines) |
| `vuln_scanner_height` | `28` | Specialized height for Vulnerability Scanner tab |
| `auto_adjust` | `true` | Enable/disable auto-adjustable feature |
| `max_height` | `35` | Maximum terminal height allowed (hard limit) |
| `min_height` | `15` | Minimum terminal height allowed (hard limit) |

## Examples

### Compact Layout (Small Screens)
```json
{
  "terminal": {
    "default_height": 15,
    "vuln_scanner_height": 18,
    "min_height": 10,
    "max_height": 20,
    "auto_adjust": true
  }
}
```

### Large Layout (Big Monitors)
```json
{
  "terminal": {
    "default_height": 35,
    "vuln_scanner_height": 40,
    "min_height": 20,
    "max_height": 50,
    "auto_adjust": true
  }
}
```

### Fixed Heights (No Auto-Adjust)
```json
{
  "terminal": {
    "default_height": 25,
    "vuln_scanner_height": 28,
    "auto_adjust": false
  }
}
```

## How It Works

1. When a tab loads, it calls `get_terminal_height()` function from `theme.py`
2. The function reads your `config.json` settings
3. Terminal height is adjusted dynamically based on your preferences
4. All bounds are automatically enforced (min/max constraints)

## Terminal Types

### Default Terminals (25 lines)
Used in most tabs: Exploitation, Power, AI Tabs, OSINT Recon, etc.

```
Exploit → SQLi, LFI, RCE, XSS, CVE
Scanner → Port/DNS Enumeration, NVD Search
Power → OAST, JWT, OAuth, HTTP Smuggling
Intel → Subdomain TKO, JWT Wordlist, SAST, API Tester
AI Tabs → PoC Generator, Chain Analyzer, Bounty Estimator
Recon → Passive/Active/Auto Recon, Dorks Search
Results → Live Monitor
Settings → Tools Installer
```

### Vuln Scanner Terminal (28 lines)  
Specialized for vulnerability scanning in Scanner tab:
```
Scanner → Vulnerability Scanner
```

## Quick Adjustments

**For very small terminals:**
```json
"default_height": 18
```

**For very large terminals:**
```json
"default_height": 32
```

**For custom specialized tab:**
Create new config entry following pattern:
```json
"custom_tab_height": 25
```
Then use: `get_terminal_height("custom_tab")` in code

## Testing Your Settings

1. Edit `config.json` with your preferred height
2. Restart TeamCyberOps
3. Open any tab with a terminal
4. Terminals will display at your configured height
5. Bounds are automatically enforced

## Auto-Adjust Behavior

When `auto_adjust: true`:
- Heights are dynamically validated on app startup
- Out-of-bounds values are clamped to min/max
- Fallback to default (25) if config is invalid
- No manual code edits required

When `auto_adjust: false`:
- Terminal heights remain as configured
- Min/max bounds are still enforced
- Good for consistent, predictable layouts

## Fallback Behavior

If `config.json` is missing or corrupted:
- All terminals default to 25 lines
- System continues working without errors
- No Exception thrown

## Terminal Sizing Tips

- **Small screens (< 1080p):** Use 18-22 lines
- **Standard screens (1080p):** Use 25-28 lines  
- **Large screens (1440p+):** Use 30-35 lines
- **Ultra-wide:** Use 35+ lines

## Files Modified

All terminal instantiations now use dynamic height:
- `app/ui/tabs/exploit.py` (8 terminals)
- `app/ui/tabs/scanner.py` (8 terminals)
- `app/ui/tabs/power.py` (7 terminals)
- `app/ui/tabs/intel.py` (7 terminals)
- `app/ui/tabs/ai_tabs.py` (4 terminals)
- `app/ui/tabs/recon.py` (4 terminals)
- `app/ui/tabs/results.py` (1 terminal)
- `app/ui/tabs/settings.py` (1 terminal)

**Total: 40 terminals configured dynamically**

## Version

- **Feature Available:** TeamCyberOps v5.0.5.1+
- **Last Updated:** April 14, 2026
