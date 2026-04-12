#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║   TeamCyberOps Suite v1 — Auto Tool Installer                  ║
# ║   Installs ALL recon & vuln tools into /tools/                  ║
# ╚══════════════════════════════════════════════════════════════════╝
# Usage: sudo bash install_tools.sh [--all | --go | --python | --apt]

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$TOOLS_DIR/install.log"
INSTALLED=0; FAILED=0; SKIPPED=0

log() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; log "OK: $1"; ((INSTALLED++)); }
fail() { echo -e "  ${RED}✗${NC} $1 — $2"; log "FAIL: $1 — $2"; ((FAILED++)); }
skip() { echo -e "  ${YELLOW}↷${NC} $1 already installed"; log "SKIP: $1"; ((SKIPPED++)); }
hdr()  { echo -e "\n${CYAN}${BOLD}[$1]${NC}"; }

check() { command -v "$1" &>/dev/null; }
check_go() { [ -f "$TOOLS_DIR/$1" ] || check "$1"; }

# ── Ensure Go is available ────────────────────────────────────────
ensure_go() {
    if ! check go; then
        echo -e "${YELLOW}[*] Go not found. Installing...${NC}"
        wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        ok "Go installed"
    fi
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    export GOPATH=$HOME/go
}

install_go_tool() {
    local name="$1" pkg="$2"
    if check_go "$name"; then skip "$name"; return; fi
    echo -n "  Installing $name... "
    if go install "$pkg@latest" >> "$LOG" 2>&1; then
        # Copy to tools dir for portability
        bin_path=$(which "$name" 2>/dev/null || echo "$HOME/go/bin/$name")
        [ -f "$bin_path" ] && cp "$bin_path" "$TOOLS_DIR/" 2>/dev/null
        ok "$name"
    else
        fail "$name" "go install failed"
    fi
}

install_apt() {
    local name="$1" pkg="${2:-$1}"
    if check "$name"; then skip "$name"; return; fi
    echo -n "  Installing $name... "
    if apt-get install -y -qq "$pkg" >> "$LOG" 2>&1; then ok "$name"
    else fail "$name" "apt install failed"; fi
}

install_pip() {
    local name="$1" pkg="${2:-$1}"
    if check "$name"; then skip "$name"; return; fi
    echo -n "  Installing $name... "
    if pip3 install "$pkg" --break-system-packages -q >> "$LOG" 2>&1; then ok "$name"
    else fail "$name" "pip install failed"; fi
}

install_binary() {
    local name="$1" url="$2" extract="${3:-}"
    if check_go "$name"; then skip "$name"; return; fi
    echo -n "  Installing $name from binary... "
    tmp=$(mktemp -d)
    if wget -q "$url" -O "$tmp/pkg" >> "$LOG" 2>&1; then
        if [[ "$url" == *.tar.gz ]]; then
            tar -xzf "$tmp/pkg" -C "$tmp" >> "$LOG" 2>&1
            bin=$(find "$tmp" -name "$name" -type f 2>/dev/null | head -1)
        elif [[ "$url" == *.zip ]]; then
            unzip -q "$tmp/pkg" -d "$tmp" >> "$LOG" 2>&1
            bin=$(find "$tmp" -name "$name" -type f 2>/dev/null | head -1)
        else
            bin="$tmp/pkg"
        fi
        if [ -f "$bin" ]; then
            chmod +x "$bin"
            cp "$bin" /usr/local/bin/"$name"
            cp "$bin" "$TOOLS_DIR/$name" 2>/dev/null
            ok "$name"
        else fail "$name" "binary not found in archive"; fi
    else fail "$name" "download failed"; fi
    rm -rf "$tmp"
}

# ═════════════════════════════════════════════════════════════════
echo -e "${CYAN}${BOLD}"
echo "  ████████╗███████╗ █████╗ ███╗   ███╗"
echo "     ██╔══╝██╔════╝██╔══██╗████╗ ████║"
echo "     ██║   █████╗  ███████║██╔████╔██║"
echo "     ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
echo "     ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
echo "     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}"
echo -e "${BOLD}TeamCyberOps Suite v1 — Auto Tool Installer${NC}"
echo -e "${YELLOW}All tools will be installed system-wide + copied to /tools/${NC}"
echo "Log: $LOG"; echo "" > "$LOG"
echo ""

# ── APT TOOLS ────────────────────────────────────────────────────
hdr "APT TOOLS"
apt-get update -qq 2>/dev/null
for tool_pkg in \
    "nmap:nmap" "masscan:masscan" "nikto:nikto" "sqlmap:sqlmap" \
    "gobuster:gobuster" "dirsearch:dirsearch" "curl:curl" \
    "dnsutils:dnsutils" "openssl:openssl" "wafw00f:wafw00f" \
    "openvpn:openvpn" "jq:jq" "git:git" "python3:python3" \
    "python3-pip:python3-pip" "wget:wget" "whois:whois"
do
    name="${tool_pkg%%:*}"; pkg="${tool_pkg##*:}"
    install_apt "$name" "$pkg"
done

# ── PYTHON TOOLS ─────────────────────────────────────────────────
hdr "PYTHON TOOLS"
for tool_pkg in "theHarvester:theHarvester" "spyhunt:spyhunt" "psutil:psutil" "requests:requests"; do
    name="${tool_pkg%%:*}"; pkg="${tool_pkg##*:}"
    install_pip "$name" "$pkg"
done

# ── GO TOOLS ─────────────────────────────────────────────────────
hdr "GO TOOLS"
ensure_go

# Subdomain Enumeration
install_go_tool "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "amass"        "github.com/owasp-amass/amass/v4/...@master"
install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder"
install_go_tool "dnsx"         "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "shuffledns"   "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
install_go_tool "puredns"      "github.com/d3mondev/puredns/v2"

# HTTP Probing
install_go_tool "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "httprobe"     "github.com/tomnomnom/httprobe"

# URL Discovery — NEW
install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau"
install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls"
install_go_tool "hakrawler"    "github.com/hakluke/hakrawler"
install_go_tool "gospider"     "github.com/jaeles-project/gospider"
install_go_tool "getallurls"   "github.com/bp0lr/gauplus"

# Subdomain Takeover — NEW
install_go_tool "subzy"        "github.com/LukaSikic/subzy"
install_go_tool "subjack"      "github.com/haccer/subjack"

# Parameter Discovery — NEW
install_go_tool "arjun"        "github.com/s0md3v/Arjun"
install_go_tool "x8"           "github.com/Sh1Yo/x8"
install_go_tool "paramspider"  "github.com/devanshbatham/paramspider"

# Fuzzing
install_go_tool "ffuf"         "github.com/ffuf/ffuf/v2"
install_go_tool "feroxbuster"  "github.com/epi052/feroxbuster" || true  # Rust, skip if no cargo

# Nuclei ecosystem
install_go_tool "nuclei"       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "notify"       "github.com/projectdiscovery/notify/cmd/notify"
install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client"
install_go_tool "cvemap"       "github.com/projectdiscovery/cvemap/cmd/cvemap"
install_go_tool "tlsx"         "github.com/projectdiscovery/tlsx/cmd/tlsx"
install_go_tool "naabu"        "github.com/projectdiscovery/naabu/cmd/naabu"

# XSS
install_go_tool "dalfox"       "github.com/hahwul/dalfox/v2"
install_go_tool "kxss"         "github.com/tomnomnom/hacks/kxss"

# SSRF
install_go_tool "ssrfmap"      "github.com/swisskyrepo/SSRFmap" || true

# Misc
install_go_tool "gowitness"    "github.com/sensepost/gowitness"
install_go_tool "rustscan"     "github.com/RustScan/RustScan" || true  # Rust
install_go_tool "anew"         "github.com/tomnomnom/anew"
install_go_tool "qsreplace"    "github.com/tomnomnom/qsreplace"
install_go_tool "gf"           "github.com/tomnomnom/gf"
install_go_tool "unfurl"       "github.com/tomnomnom/unfurl"

# Update Nuclei templates
hdr "NUCLEI TEMPLATES"
if check nuclei; then
    echo -n "  Updating Nuclei templates... "
    nuclei -update-templates >> "$LOG" 2>&1 && ok "nuclei-templates" || fail "nuclei-templates" "update failed"
fi

# Create tool symlinks in /tools/ for all installed Go tools
hdr "CREATING TOOL SYMLINKS"
for bin in "$HOME/go/bin"/*; do
    name=$(basename "$bin")
    if [ -f "$bin" ] && [ -x "$bin" ]; then
        ln -sf "$bin" "$TOOLS_DIR/$name" 2>/dev/null
    fi
done
ok "Symlinks created in $TOOLS_DIR"

# ── SUMMARY ──────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ Installed: $INSTALLED${NC}"
echo -e "  ${YELLOW}↷ Skipped:   $SKIPPED${NC}"
echo -e "  ${RED}✗ Failed:    $FAILED${NC}"
echo -e "${CYAN}════════════════════════════════════${NC}"
echo -e "  Log: ${BLUE}$LOG${NC}"
echo -e "  Tools dir: ${BLUE}$TOOLS_DIR${NC}"
echo ""
echo -e "${GREEN}${BOLD}Run: python3 main.py${NC}"
