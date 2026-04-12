#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║   TeamCyberOps Suite v1 — Complete Auto-Installer                  ║
# ║   Kali Linux | All Recon + Vuln + Exploit + Dork Tools             ║
# ║   Usage: sudo bash install.sh [--all|--go|--apt|--pip|--check]     ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/install.log"
TOOLS_DIR="$SCRIPT_DIR/tools"
GOBIN="$HOME/go/bin"
MODE="${1:---all}"
mkdir -p "$TOOLS_DIR"; echo "" > "$LOG_FILE"
INSTALLED=0; SKIPPED=0; FAILED=0
log()  { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"; }
ok()   { echo -e "  ${GREEN}✓${NC}  $1"; log "OK: $1"; ((INSTALLED++)); }
skip() { echo -e "  ${DIM}↷${NC}  $1 already installed"; log "SKIP: $1"; ((SKIPPED++)); }
fail() { echo -e "  ${RED}✗${NC}  $1  ${DIM}($2)${NC}"; log "FAIL: $1 — $2"; ((FAILED++)); }
hdr()  { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}"; }
info() { echo -e "  ${BLUE}→${NC}  $1"; }
exists() { command -v "$1" &>/dev/null || [ -f "$GOBIN/$1" ] || [ -f "$TOOLS_DIR/$1" ]; }
clear
echo -e "${CYAN}${BOLD}"
echo "  ████████╗███████╗ █████╗ ███╗   ███╗"
echo "     ██╔══╝██╔════╝██╔══██╗████╗ ████║"
echo "     ██║   █████╗  ███████║██╔████╔██║"
echo "     ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
echo "     ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
echo "     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}"
echo -e "${BOLD}  TeamCyberOps Suite v1 — Auto-Installer${NC}"
echo -e "${DIM}  Mode: $MODE | Log: $LOG_FILE | $(date)${NC}\n"

# ── Section 1: APT ───────────────────────────────────────────────────
install_apt() {
    local name="$1" pkg="${2:-$1}"
    if exists "$name"; then skip "$name"; return; fi
    echo -ne "  ${BLUE}→${NC}  apt: $name... "
    if apt-get install -y -qq "$pkg" >> "$LOG_FILE" 2>&1; then
        echo -e "${GREEN}done${NC}"; ok "$name"
    else echo -e "${RED}failed${NC}"; fail "$name" "apt $pkg"; fi
}

if [[ "$MODE" == "--all" || "$MODE" == "--apt" ]]; then
    hdr "APT PACKAGES"
    apt-get update -qq >> "$LOG_FILE" 2>&1 || true
    for entry in \
        "python3:python3" "python3-tk:python3-tk" "python3-pip:python3-pip" \
        "git:git" "curl:curl" "wget:wget" "jq:jq" "unzip:unzip" "zip:zip" \
        "whois:whois" "dnsutils:dnsutils" "openssl:openssl" "net-tools:net-tools" \
        "nmap:nmap" "masscan:masscan" "gobuster:gobuster" "dirsearch:dirsearch" \
        "nikto:nikto" "sqlmap:sqlmap" "wafw00f:wafw00f" "openvpn:openvpn" \
        "proxychains4:proxychains4" "subfinder:subfinder" "amass:amass" \
        "nuclei:nuclei" "httpx-toolkit:httpx-toolkit" "gowitness:gowitness"; do
        name="${entry%%:*}"; pkg="${entry##*:}"
        install_apt "$name" "$pkg"
    done
fi

# ── Section 2: Go tools ──────────────────────────────────────────────
ensure_go() {
    command -v go &>/dev/null && { info "Go $(go version | awk '{print $3}') found"; return; }
    info "Installing Go 1.22..."
    wget -q "https://go.dev/dl/go1.22.0.linux-amd64.tar.gz" -O /tmp/go.tar.gz >> "$LOG_FILE" 2>&1
    rm -rf /usr/local/go; tar -C /usr/local -xzf /tmp/go.tar.gz >> "$LOG_FILE" 2>&1; rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    for rc in ~/.bashrc ~/.zshrc; do
        [ -f "$rc" ] && grep -q "go/bin" "$rc" || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$rc"
    done
    ok "Go 1.22.0"
}

install_go_tool() {
    local name="$1" pkg="$2"
    if exists "$name"; then skip "$name"; return; fi
    echo -ne "  ${BLUE}→${NC}  go: $name... "
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin GOPATH=$HOME/go
    if go install "${pkg}@latest" >> "$LOG_FILE" 2>&1; then
        [ -f "$GOBIN/$name" ] && ln -sf "$GOBIN/$name" "$TOOLS_DIR/$name" 2>/dev/null || true
        echo -e "${GREEN}done${NC}"; ok "$name"
    else echo -e "${RED}failed${NC}"; fail "$name" "go install $pkg"; fi
}

if [[ "$MODE" == "--all" || "$MODE" == "--go" ]]; then
    hdr "GO TOOLS"
    ensure_go
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin GOPATH=$HOME/go

    info "[ Subdomain Enumeration ]"
    install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder"
    install_go_tool "dnsx"         "github.com/projectdiscovery/dnsx/cmd/dnsx"
    install_go_tool "shuffledns"   "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    install_go_tool "tlsx"         "github.com/projectdiscovery/tlsx/cmd/tlsx"
    install_go_tool "puredns"      "github.com/d3mondev/puredns/v2"
    install_go_tool "alterx"       "github.com/projectdiscovery/alterx/cmd/alterx"
    install_go_tool "asnmap"       "github.com/projectdiscovery/asnmap/cmd/asnmap"

    info "[ HTTP Probing ]"
    install_go_tool "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx"
    install_go_tool "httprobe"     "github.com/tomnomnom/httprobe"

    info "[ URL Discovery — Katana / GAU / Waybackurls ]"
    install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana"
    install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau"
    install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls"
    install_go_tool "hakrawler"    "github.com/hakluke/hakrawler"
    install_go_tool "gospider"     "github.com/jaeles-project/gospider"
    install_go_tool "getJS"        "github.com/003random/getJS"

    info "[ Subdomain Takeover — Subzy / Subjack ]"
    install_go_tool "subzy"        "github.com/LukaSikic/subzy"
    install_go_tool "subjack"      "github.com/haccer/subjack"

    info "[ Parameter Discovery ]"
    install_go_tool "gf"           "github.com/tomnomnom/gf"
    install_go_tool "qsreplace"    "github.com/tomnomnom/qsreplace"
    install_go_tool "anew"         "github.com/tomnomnom/anew"
    install_go_tool "unfurl"       "github.com/tomnomnom/unfurl"
    install_go_tool "kxss"         "github.com/Emoe/kxss"
    install_go_tool "tok"          "github.com/tomnomnom/tok"

    info "[ Fuzzing ]"
    install_go_tool "ffuf"         "github.com/ffuf/ffuf/v2"

    info "[ Port Scanning ]"
    install_go_tool "naabu"        "github.com/projectdiscovery/naabu/cmd/naabu"

    info "[ Nuclei Ecosystem ]"
    install_go_tool "nuclei"       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    install_go_tool "notify"       "github.com/projectdiscovery/notify/cmd/notify"
    install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client"
    install_go_tool "cvemap"       "github.com/projectdiscovery/cvemap/cmd/cvemap"
    install_go_tool "uncover"      "github.com/projectdiscovery/uncover/cmd/uncover"
    install_go_tool "mapcidr"      "github.com/projectdiscovery/mapcidr/cmd/mapcidr"

    info "[ Vulnerability Tools ]"
    install_go_tool "dalfox"       "github.com/hahwul/dalfox/v2"

    info "[ Screenshots ]"
    install_go_tool "gowitness"    "github.com/sensepost/gowitness"

    # GF patterns
    info "Setting up GF patterns..."
    if exists gf; then
        mkdir -p ~/.gf
        git clone -q https://github.com/tomnomnom/gf /tmp/gf-src >> "$LOG_FILE" 2>&1 || true
        [ -d /tmp/gf-src/examples ] && cp /tmp/gf-src/examples/*.json ~/.gf/ 2>/dev/null || true
        git clone -q https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-extra >> "$LOG_FILE" 2>&1 || true
        [ -d /tmp/gf-extra ] && cp /tmp/gf-extra/*.json ~/.gf/ 2>/dev/null || true
        ok "GF patterns (~/.gf/)"
    fi

    # Update Nuclei templates
    info "Updating Nuclei templates..."
    if exists nuclei; then
        nuclei -update-templates >> "$LOG_FILE" 2>&1 && ok "nuclei-templates" || fail "nuclei-templates" "update failed"
    fi
fi

# ── Section 3: Python ────────────────────────────────────────────────
install_pip() {
    local name="$1" pkg="${2:-$1}"
    if python3 -c "import ${name//-/_}" &>/dev/null 2>&1; then skip "$name (python lib)"; return; fi
    echo -ne "  ${BLUE}→${NC}  pip: $name... "
    if pip3 install "$pkg" --break-system-packages -q >> "$LOG_FILE" 2>&1; then
        echo -e "${GREEN}done${NC}"; ok "$name"
    else echo -e "${RED}failed${NC}"; fail "$name" "pip $pkg"; fi
}

if [[ "$MODE" == "--all" || "$MODE" == "--pip" ]]; then
    hdr "PYTHON DEPENDENCIES"
    # Core framework deps
    for entry in \
        "psutil:psutil" "requests:requests" "colorama:colorama" \
        "rich:rich" "shodan:shodan" "censys:censys" \
        "PyGithub:PyGithub" "google:google" "googlesearch:googlesearch-python" \
        "bs4:beautifulsoup4" "lxml:lxml" "dnspython:dnspython" \
        "python_dotenv:python-dotenv"; do
        name="${entry%%:*}"; pkg="${entry##*:}"
        install_pip "$name" "$pkg"
    done

    # theHarvester
    if ! exists theHarvester; then
        echo -ne "  ${BLUE}→${NC}  apt: theHarvester... "
        apt-get install -y -qq theharvester >> "$LOG_FILE" 2>&1 && \
        { echo -e "${GREEN}done${NC}"; ok "theHarvester"; } || \
        { pip3 install theHarvester --break-system-packages -q >> "$LOG_FILE" 2>&1 && ok "theHarvester" || fail "theHarvester" "both failed"; }
    else skip "theHarvester"; fi

    # SpyHunt
    exists spyhunt || pip3 install spyhunt --break-system-packages -q >> "$LOG_FILE" 2>&1 && ok "spyhunt" || fail "spyhunt" "pip failed"
fi

# ── Section 4: Binary installs ───────────────────────────────────────
if [[ "$MODE" == "--all" ]]; then
    hdr "BINARY INSTALLS"

    # RustScan
    if ! exists rustscan; then
        echo -ne "  ${BLUE}→${NC}  RustScan deb... "
        wget -q "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb" \
             -O /tmp/rustscan.deb >> "$LOG_FILE" 2>&1 && \
        dpkg -i /tmp/rustscan.deb >> "$LOG_FILE" 2>&1 && \
        { echo -e "${GREEN}done${NC}"; ok "rustscan"; rm -f /tmp/rustscan.deb; } || \
        { echo -e "${RED}failed${NC}"; fail "rustscan" "deb install"; }
    else skip "rustscan"; fi

    # Paramspider
    exists paramspider || pip3 install paramspider --break-system-packages -q >> "$LOG_FILE" 2>&1 && ok "paramspider" || true
fi

# ── Section 5: Project directories ──────────────────────────────────
hdr "PROJECT DIRECTORIES"
for dir in db logs reports screenshots wordlists payloads tools; do
    mkdir -p "$SCRIPT_DIR/$dir"
done
# Symlink all Go bins to tools/
for bin in "$GOBIN"/*; do
    [ -f "$bin" ] && [ -x "$bin" ] && ln -sf "$bin" "$TOOLS_DIR/$(basename "$bin")" 2>/dev/null || true
done
ok "Directories + symlinks ready"

# ── Section 6: Verification ──────────────────────────────────────────
if [[ "$MODE" == "--all" || "$MODE" == "--check" ]]; then
    hdr "VERIFICATION"
    TOOLS_CHECK=(
        subfinder amass assetfinder dnsx tlsx httpx
        katana gau waybackurls hakrawler gospider
        subzy subjack gf qsreplace kxss anew unfurl
        ffuf gobuster dirsearch naabu
        nuclei notify interactsh-client cvemap uncover
        nmap masscan wafw00f nikto
        dalfox sqlmap gowitness
        theHarvester jq curl git openssl whois
    )
    V=0; M=0
    for t in "${TOOLS_CHECK[@]}"; do
        if exists "$t"; then echo -e "  ${GREEN}●${NC} $t"; ((V++))
        else echo -e "  ${RED}○${NC} $t"; ((M++)); fi
    done
    echo -e "\n  ${GREEN}${V} ready${NC}  •  ${RED}${M} missing${NC}"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}✓${NC}  Installed : ${BOLD}$INSTALLED${NC}"
echo -e "  ${YELLOW}↷${NC}  Skipped   : ${BOLD}$SKIPPED${NC}"
echo -e "  ${RED}✗${NC}  Failed    : ${BOLD}$FAILED${NC}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Log  → ${BLUE}$LOG_FILE${NC}"
echo -e "  Bin  → ${BLUE}$TOOLS_DIR${NC}"
echo ""
echo -e "${GREEN}${BOLD}  Launch: python3 main.py${NC}"
echo -e "${YELLOW}  Default login: admin / admin${NC}\n"
