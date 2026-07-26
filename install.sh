#!/usr/bin/env bash
#
# install.sh — Setup script for Automated-Recon-Framework
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#

set -euo pipefail

GO_VERSION="1.23.4"
REPO_DEST="/usr/Recon"

info()  { echo -e "\033[1;34m[*]\033[0m $1"; }
ok()    { echo -e "\033[1;32m[+]\033[0m $1"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $1"; }
skip()  { echo -e "\033[1;36m[=]\033[0m $1"; }

echo "=============================================="
echo "  Automated-Recon-Framework — Installer"
echo "=============================================="


# 1. Update Ubuntu and check Python

info "Updating apt and upgrading packages..."
sudo apt update && sudo apt upgrade -y

info "Checking Python version..."
PY_VERSION="$(python3 --version 2>/dev/null | awk '{print $2}' || echo "0.0.0")"
PY_MAJOR="$(echo "$PY_VERSION" | cut -d. -f1)"
PY_MINOR="$(echo "$PY_VERSION" | cut -d. -f2)"

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    warn "Python $PY_VERSION detected — need 3.11+. Installing python3.11..."
    sudo apt install -y python3.11
    warn "Use 'python3.11' in place of 'python3' below, or set it as default with:"
    warn "  sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1"
else
    skip "Python $PY_VERSION already satisfies 3.11+ — skipping."
fi


# 2. Install Nmap and unzip

if command -v nmap >/dev/null 2>&1; then
    skip "nmap already installed ($(command -v nmap)) — skipping."
else
    info "Installing nmap..."
    sudo apt install -y nmap
fi

if command -v unzip >/dev/null 2>&1; then
    skip "unzip already installed ($(command -v unzip)) — skipping."
else
    info "Installing unzip..."
    sudo apt install -y unzip
fi


# 3. Install Go

if command -v go >/dev/null 2>&1; then
    skip "Go already installed ($(go version)) — skipping."
else
    info "Installing Go ${GO_VERSION}..."
    cd /tmp
    curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"

    if ! grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin
fi

# Make sure GOPATH/bin is on PATH for this session (needed for go install below)
export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin

go version || warn "Go not found on PATH yet — restart your shell or 'source ~/.bashrc' after this script finishes."

# 4. Install Go-based recon tools

info "Checking Go-based recon tools..."

if command -v subfinder >/dev/null 2>&1; then
    skip "subfinder already installed ($(command -v subfinder)) — skipping."
else
    info "Installing subfinder..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi

if command -v httpx >/dev/null 2>&1; then
    skip "httpx already installed ($(command -v httpx)) — skipping."
else
    info "Installing httpx..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
fi

if command -v assetfinder >/dev/null 2>&1; then
    skip "assetfinder already installed ($(command -v assetfinder)) — skipping."
else
    info "Installing assetfinder..."
    go install github.com/tomnomnom/assetfinder@latest
fi

if command -v gowitness >/dev/null 2>&1; then
    skip "gowitness already installed ($(command -v gowitness)) — skipping."
else
    info "Installing gowitness..."
    go install github.com/sensepost/gowitness@latest
fi

# 5. Install Amass

if command -v amass >/dev/null 2>&1; then
    skip "amass already installed ($(command -v amass)) — skipping."
else
    info "Installing Amass (via Go, latest master)..."
    go install -v github.com/owasp-amass/amass/v4/...@master
fi

# 6. Install Chromium for GoWitness

if command -v chromium-browser >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1; then
    skip "Chromium already installed ($(command -v chromium-browser || command -v chromium)) — skipping."
else
    info "Installing Chromium for GoWitness..."
    if sudo apt install -y chromium-browser 2>/dev/null; then
        ok "Installed chromium-browser via apt."
    elif command -v snap >/dev/null 2>&1; then
        warn "chromium-browser not found via apt — trying snap instead..."
        sudo snap install chromium
    else
        warn "Could not install Chromium automatically. Install it manually for GoWitness screenshots to work."
    fi
fi

# 7. Verify everything's on PATH

echo ""
info "Verifying installed tools..."
for tool in subfinder httpx assetfinder gowitness amass nmap; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool found: $(command -v "$tool")"
    else
        warn "$tool NOT found on PATH (that stage will just skip with a warning at runtime)"
    fi
done

# 8. Move the repo to /usr/Recon

echo ""
info "Setting up install location at ${REPO_DEST} ..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$SCRIPT_DIR" = "$REPO_DEST" ]; then
    skip "Already running from ${REPO_DEST} — skipping move."
else
    if [ -f "${REPO_DEST}/recon.py" ]; then
        skip "Automated-Recon-Framework already present at ${REPO_DEST} — skipping move."
    else
        sudo mkdir -p "$REPO_DEST"
        # Move regular files/folders, then dotfiles (excluding . and ..)
        shopt -s dotglob nullglob
        sudo mv "$SCRIPT_DIR"/* "$REPO_DEST"/
        shopt -u dotglob nullglob
        sudo chown -R "$(id -u):$(id -g)" "$REPO_DEST"
        ok "Moved Automated-Recon-Framework to ${REPO_DEST}"
    fi

    # Clean up the now-redundant downloaded directory
    cd "$(dirname "$SCRIPT_DIR")" 2>/dev/null || cd "$HOME"
    if [ -d "$SCRIPT_DIR" ]; then
        sudo rm -rf "$SCRIPT_DIR"
        ok "Deleted original directory: ${SCRIPT_DIR}"
    fi
fi


# 9. Create a 'recon' alias so you can run: recon url

info "Setting up 'recon' alias..."

ALIAS_LINE="alias recon='python3 ${REPO_DEST}/recon.py'"
SHELL_RC="$HOME/.bashrc"

# Support zsh users too, if that's their active shell
if [ -n "${ZSH_VERSION:-}" ] || [ "${SHELL##*/}" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

if grep -Fxq "$ALIAS_LINE" "$SHELL_RC" 2>/dev/null; then
    skip "'recon' alias already present in $SHELL_RC — skipping."
else
    echo "$ALIAS_LINE" >> "$SHELL_RC"
    ok "Added 'recon' alias to $SHELL_RC"
fi

echo ""
echo "=============================================="
ok           "Installation complete!"
echo "=============================================="
echo ""
echo "If any tools reported missing above, open a new shell (or run 'source ~/.bashrc') and re-run:"
echo "  which subfinder httpx assetfinder gowitness amass nmap"
echo ""
echo ">>> Automated-Recon-Framework is installed at: ${REPO_DEST} <<<"
echo ">>> The original downloaded directory has been removed. <<<"
echo ""
echo "Reload your shell config to activate the recon:"
echo "  source $SHELL_RC"
echo ""
