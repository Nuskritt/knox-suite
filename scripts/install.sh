#!/bin/bash
# Knox Suite installer script
# Usage: curl -sSL https://raw.githubusercontent.com/yourusername/knox-suite/main/scripts/install.sh | bash

set -e

REPO="yourusername/knox-suite"
BINARY="knox"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case $OS in
    linux|darwin) ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest release
echo "Fetching latest release..."
LATEST=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    echo "Failed to get latest release"
    exit 1
fi

echo "Latest version: $LATEST"

# Download URL
ARCHIVE="${BINARY}-${LATEST}-${OS}-${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST/$ARCHIVE"

echo "Downloading $DOWNLOAD_URL..."
curl -sSL "$DOWNLOAD_URL" -o "/tmp/$ARCHIVE"

echo "Extracting..."
tar -xzf "/tmp/$ARCHIVE" -C /tmp

echo "Installing to $INSTALL_DIR..."
sudo mv "/tmp/$BINARY" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/$BINARY"

# Cleanup
rm -f "/tmp/$ARCHIVE"

echo "✅ $BINARY installed successfully!"
echo "Run: $BINARY --help"

# Check for security tools
echo ""
echo "Checking for security tools..."
TOOLS=("nmap" "nuclei" "subfinder" "httpx" "dnsx" "sslscan" "whatweb" "nikto" "dirsearch" "ffuf" "katana" "gau" "waybackurls" "amass")
MISSING=()

for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "⚠️  Missing tools: ${MISSING[*]}"
    echo "Install them for full functionality:"
    echo "  Ubuntu/Debian: sudo apt install -y ${MISSING[*]}"
    echo "  macOS: brew install ${MISSING[*]}"
    echo "  Or use Go install for some tools"
else
    echo "✅ All security tools found!"
fi