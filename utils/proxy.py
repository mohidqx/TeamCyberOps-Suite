"""
TeamCyberOps Suite v3 — Proxy & VPN Manager
Cross-platform: Windows + Linux + macOS
"""
import os, json, subprocess, platform, shutil
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"
CFG_PATH   = Path(__file__).parent.parent / "config.json"

def _cfg():
    with open(CFG_PATH) as f: return json.load(f)

def _save_cfg(data):
    with open(CFG_PATH, "w") as f: json.dump(data, f, indent=2)

def set_proxy(host, port, proxy_type="http"):
    cfg = _cfg(); cfg["proxy"].update({"host": host,"port": port,"type": proxy_type,"enabled": True}); _save_cfg(cfg)
    url = f"{proxy_type}://{host}:{port}"
    for var in ["http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY"]: os.environ[var] = url

def clear_proxy():
    cfg = _cfg(); cfg["proxy"]["enabled"] = False; _save_cfg(cfg)
    for var in ["http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY"]: os.environ.pop(var, None)

def set_burp(host="127.0.0.1", port=8080):
    cfg = _cfg(); cfg["proxy"].update({"burp_enabled": True,"burp_host": host,"burp_port": port}); _save_cfg(cfg)
    set_proxy(host, port, "http")

def disable_burp():
    cfg = _cfg(); cfg["proxy"]["burp_enabled"] = False; _save_cfg(cfg); clear_proxy()

def get_proxy_env():
    cfg = _cfg()["proxy"]
    if cfg.get("burp_enabled"): url = f"http://{cfg['burp_host']}:{cfg['burp_port']}"
    elif cfg.get("enabled"):    url = f"{cfg['type']}://{cfg['host']}:{cfg['port']}"
    else: return {}
    return {"http_proxy": url,"https_proxy": url,"HTTP_PROXY": url,"HTTPS_PROXY": url}

def start_vpn(config_path):
    if not os.path.isfile(config_path): raise FileNotFoundError(f"VPN config not found: {config_path}")
    cmd = ["openvpn", "--config", config_path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cfg = _cfg(); cfg["vpn"].update({"enabled": True,"config_path": config_path}); _save_cfg(cfg)
    return proc

def stop_vpn():
    if IS_WINDOWS:
        try: subprocess.run(["taskkill","/F","/IM","openvpn.exe"], capture_output=True, check=False)
        except Exception: pass
    else:
        try: subprocess.run(["pkill","-f","openvpn"], capture_output=True, check=False)
        except Exception: pass
    cfg = _cfg(); cfg["vpn"]["enabled"] = False; _save_cfg(cfg)

def get_current_ip():
    import urllib.request
    for url in ["https://api.ipify.org","https://checkip.amazonaws.com","https://icanhazip.com"]:
        try:
            with urllib.request.urlopen(url, timeout=5) as r: return r.read().decode().strip()
        except Exception: continue
    return "Unable to fetch"

def check_tun0():
    """Check VPN tunnel status — cross-platform safe."""
    if IS_WINDOWS:
        try:
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            out = r.stdout.lower()
            return "tap" in out or "tun" in out or "vpn" in out
        except Exception: return False
    else:
        for cmd in [["ip","addr","show","tun0"], ["ifconfig","tun0"]]:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if r.returncode == 0: return True
            except FileNotFoundError: continue
            except Exception: pass
        return False

def get_proxy_status():
    try:
        cfg = _cfg(); p = cfg.get("proxy",{}); v = cfg.get("vpn",{})
        return {"burp": p.get("burp_enabled",False),"proxy": p.get("enabled",False),
                "proxy_url": f"{p.get('type','http')}://{p.get('host','127.0.0.1')}:{p.get('port',8080)}",
                "vpn": v.get("enabled",False),"tun0": check_tun0(),"platform": platform.system()}
    except Exception:
        return {"burp":False,"proxy":False,"vpn":False,"tun0":False,"proxy_url":"","platform":platform.system()}

def open_folder(path):
    path = str(path)
    if IS_WINDOWS: os.startfile(path)
    elif IS_MAC: subprocess.Popen(["open", path])
    else:
        for fm in ["xdg-open","nautilus","thunar","nemo","dolphin"]:
            if shutil.which(fm): subprocess.Popen([fm, path]); return

def open_file(path):
    path = str(path)
    if IS_WINDOWS: os.startfile(path)
    elif IS_MAC: subprocess.Popen(["open", path])
    else:
        for opener in ["xdg-open"]:
            if shutil.which(opener): subprocess.Popen([opener, path]); return

def launch_terminal(cwd=None):
    cwd = cwd or str(Path.home())
    if IS_WINDOWS:
        for cmd in [["wt.exe"],["pwsh.exe","-NoExit"],["powershell.exe","-NoExit"],["cmd.exe"]]:
            try: subprocess.Popen(cmd, cwd=cwd, creationflags=subprocess.CREATE_NEW_CONSOLE); return True
            except Exception: continue
    elif IS_MAC: subprocess.Popen(["open","-a","Terminal",cwd]); return True
    else:
        for term in [["xterm","-bg","#010409","-fg","#00e676","-fa","Monospace","-fs","11"],["gnome-terminal","--"],["xfce4-terminal"],["konsole"],["xterm"]]:
            if shutil.which(term[0]):
                try: subprocess.Popen(term, cwd=cwd, start_new_session=True); return True
                except Exception: continue
    return False
