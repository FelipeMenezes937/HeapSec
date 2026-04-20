#!/bin/bash
# HeapSec Installer
# Usage: ./install.sh [-- uninstall]

set -e

INSTALL_DIR="${HEAPSEC_DIR:-$HOME/.local/heapsec}"
BIN_DIR="$HOME/.local/bin"
DESKTOP_FILE="$HOME/.local/share/applications/heapsec.desktop"

install_mode() {
    echo "Installing HeapSec to $HOME/.local..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BIN_DIR"
    mkdir -p "$HOME/.local/share/applications"
    
    # Copy files
    cp -r out/classes "$INSTALL_DIR/"
    cp src/main/java/antivirus/*.java "$INSTALL_DIR/src/" 2>/dev/null || true
    cp src/main/java/antivirus/*/*.java "$INSTALL_DIR/src/" 2>/dev/null || true
    cp -r resources "$INSTALL_DIR/" 2>/dev/null || true
    
    # Compile if needed
    if [ ! -d "$INSTALL_DIR/classes" ]; then
        mkdir -p "$INSTALL_DIR/classes"
        javac -d "$INSTALL_DIR/classes" --source-path src/main/java src/main/java/antivirus/*.java src/main/java/antivirus/*/*.java 2>/dev/null || true
    fi
    
    # Create launcher script
    cat > "$BIN_DIR/heapsec" << 'EOF'
#!/bin/bash
HEAPSEC_DIR="$HOME/.local/heapsec"
exec java -cp "$HEAPSEC_DIR/classes" antivirus.AntivirusScanner "$@"
EOF
    chmod +x "$BIN_DIR/heapsec"
    
    # Create desktop entry
    cat > "$DESKTOP_FILE" << 'EOF'
[Desktop Entry]
Type=Application
Name=HeapSec Antivirus
Comment=HeapSec - Static Malware Analyzer
Exec=heapsec
Icon=antivirus
Terminal=true
Categories=Security;Utility;
EOF
    
    # Add to PATH if needed
    if ! grep -q "$HOME/.local/bin" "$HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    fi
    
    echo "HeapSec installed!"
    echo "Run 'heapsec' to start"
    echo ""
    echo "Note: Add 'source ~/.bashrc' or restart terminal to use 'heapsec' command"
}

uninstall_mode() {
    echo "Uninstalling HeapSec..."
    rm -rf "$INSTALL_DIR"
    rm -f "$BIN_DIR/heapsec"
    rm -f "$DESKTOP_FILE"
    echo "HeapSec uninstalled!"
}

case "${1:-install}" in
    --uninstall|-u|uninstall)
        uninstall_mode
        ;;
    *)
        install_mode
        ;;
esac