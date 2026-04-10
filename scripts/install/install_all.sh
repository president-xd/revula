#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Revula Master Installer
# Installs all system and Python dependencies for the Revula server.
# Supports Linux (apt, dnf, pacman) and macOS (brew).
#
# Usage:
#   ./install_all.sh [OPTIONS]
#
# Options:
#   --minimal       Only install core deps (mcp, jsonschema, capstone, lief, pefile, pyelftools, yara)
#   --no-android    Skip Android-related tools (jadx, apktool, frida, androguard, semgrep, quark)
#   --no-ghidra     Skip Ghidra headless download
#   --help          Show this help message
# =============================================================================

readonly REMCP_DIR="${HOME}/.revula"
readonly LOG_FILE="${REMCP_DIR}/install.log"
readonly GHIDRA_VERSION="11.2.1"
readonly GHIDRA_DATE="20241105"
readonly GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
readonly APKTOOL_VERSION="2.10.0"
readonly APKTOOL_JAR_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
readonly APKTOOL_SCRIPT_URL="https://raw.githubusercontent.com/iBotPeaches/Apktool/v${APKTOOL_VERSION}/scripts/linux/apktool"
readonly YARA_RULES_REPO="https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"

# Flags (defaults)
FLAG_MINIMAL=false
FLAG_NO_ANDROID=false
FLAG_NO_GHIDRA=false

# ---------------------------------------------------------------------------
# Colored output helpers
# ---------------------------------------------------------------------------

_supports_color() {
    [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]
}

if _supports_color; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info()    { echo -e "${BLUE}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[  OK]${NC}  $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERR!]${NC}  $*" | tee -a "$LOG_FILE" >&2; }

die() { error "$@"; exit 1; }

sha256_file() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        return 1
    fi
}

sync_legacy_yara_dir() {
    local canonical_dir="$1"
    local legacy_dir="$2"

    if [[ ! -d "$canonical_dir" ]]; then
        return
    fi

    if [[ -L "$legacy_dir" ]]; then
        ln -sfn "$canonical_dir" "$legacy_dir" 2>/dev/null || true
        return
    fi

    if [[ -d "$legacy_dir" ]]; then
        cp -rn "${canonical_dir}/." "$legacy_dir/" 2>/dev/null || true
        return
    fi

    ln -s "$canonical_dir" "$legacy_dir" 2>/dev/null || cp -r "$canonical_dir" "$legacy_dir" 2>/dev/null || true
}

banner() {
    echo -e "${BOLD}"
    cat <<'EOF'
  ╔══════════════════════════════════════════════╗
  ║       Revula  —  Master Installer            ║
  ║   Universal Reverse Engineering MCP Server    ║
  ╚══════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --minimal)     FLAG_MINIMAL=true ;;
            --no-android)  FLAG_NO_ANDROID=true ;;
            --no-ghidra)   FLAG_NO_GHIDRA=true ;;
            --help|-h)
                echo "Usage: $0 [--minimal] [--no-android] [--no-ghidra] [--help]"
                echo ""
                echo "Options:"
                echo "  --minimal       Only core Python deps (mcp, jsonschema, capstone, lief, pefile, pyelftools, yara-python)"
                echo "  --no-android    Skip jadx, apktool, androguard, frida, semgrep, quark"
                echo "  --no-ghidra     Skip Ghidra headless download"
                echo "  --help          Show this message"
                exit 0
                ;;
            *)
                die "Unknown option: $1 (use --help for usage)"
                ;;
        esac
        shift
    done
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    PKG_MGR=""

    case "$OS" in
        Linux)
            if command -v apt-get &>/dev/null; then
                PKG_MGR="apt"
            elif command -v dnf &>/dev/null; then
                PKG_MGR="dnf"
            elif command -v pacman &>/dev/null; then
                PKG_MGR="pacman"
            else
                warn "Unsupported Linux package manager. Install system deps manually."
            fi
            ;;
        Darwin)
            if command -v brew &>/dev/null; then
                PKG_MGR="brew"
            else
                die "Homebrew not found. Install it first: https://brew.sh"
            fi
            ;;
        *)
            die "Unsupported operating system: $OS"
            ;;
    esac

    info "Platform: ${OS} / ${ARCH} / pkg-manager=${PKG_MGR:-none}"
}

# ---------------------------------------------------------------------------
# Python 3.11+ check
# ---------------------------------------------------------------------------

check_python() {
    local py_cmd=""
    for candidate in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" 2>/dev/null || continue
            local major minor
            major="${ver%%.*}"
            minor="${ver##*.}"
            if [[ "$major" -ge 3 ]] && [[ "$minor" -ge 11 ]]; then
                py_cmd="$candidate"
                break
            fi
        fi
    done

    if [[ -z "$py_cmd" ]]; then
        die "Python 3.11+ is required but not found. Please install it first."
    fi

    PYTHON="$py_cmd"
    PIP="$PYTHON -m pip"
    success "Python found: $PYTHON ($($PYTHON --version 2>&1))"
}

# ---------------------------------------------------------------------------
# System dependency installation
# ---------------------------------------------------------------------------

pkg_install() {
    local pkg="$1"
    info "Installing system package: $pkg"
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        dnf)    sudo dnf install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        pacman) sudo pacman -S --noconfirm "$pkg" >> "$LOG_FILE" 2>&1 ;;
        brew)   brew install "$pkg" >> "$LOG_FILE" 2>&1 ;;
        *)      warn "No package manager — skipping $pkg" ; return 1 ;;
    esac
}

install_system_deps() {
    info "Installing system dependencies..."

    # Map package names per manager
    # Each key is a logical tool name; value is the package that provides it.
    declare -A apt_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx-ucl [qemu_user]=qemu-user [qemu_system]=qemu-system [qemu_utils]=qemu-utils
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=tshark
        [wabt]=wabt [libfuzzy]=libfuzzy-dev [llvm]=llvm
        [checksec]=checksec [monodis]=mono-utils [msfvenom]=metasploit-framework
        [drrun]=dynamorio [adb]=adb
    )
    declare -A dnf_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx [qemu_user]=qemu-user-static [qemu_system]=qemu-system-x86 [qemu_utils]=qemu-img
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=wireshark-cli
        [wabt]=wabt [libfuzzy]=ssdeep-devel [llvm]=llvm
        [checksec]=checksec [monodis]=mono-core [msfvenom]=metasploit
        [drrun]=dynamorio [adb]=android-tools
    )
    declare -A pacman_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx [qemu_user]=qemu-user [qemu_system]=qemu-full [qemu_utils]=qemu-full
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=wireshark-cli
        [wabt]=wabt [libfuzzy]=ssdeep [llvm]=llvm
        [checksec]=checksec [monodis]=mono [msfvenom]=metasploit
        [drrun]=dynamorio [adb]=android-tools
    )
    declare -A brew_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx [qemu_user]=qemu [qemu_system]=qemu [qemu_utils]=qemu
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=wireshark
        [wabt]=wabt [libfuzzy]=ssdeep [llvm]=llvm
        [checksec]=checksec [monodis]=mono [msfvenom]=metasploit
        [drrun]=dynamorio [adb]=android-platform-tools
    )

    local tools_to_install=(
        gdb binutils binwalk upx
        qemu_user qemu_system qemu_utils
        radare2 lldb rizin tshark wabt
        libfuzzy llvm
        checksec monodis msfvenom drrun adb
    )

    for tool_key in "${tools_to_install[@]}"; do
        local pkg=""
        case "$PKG_MGR" in
            apt)    pkg="${apt_pkgs[$tool_key]:-}" ;;
            dnf)    pkg="${dnf_pkgs[$tool_key]:-}" ;;
            pacman) pkg="${pacman_pkgs[$tool_key]:-}" ;;
            brew)   pkg="${brew_pkgs[$tool_key]:-}" ;;
        esac
        if [[ -n "$pkg" ]]; then
            pkg_install "$pkg" || warn "Failed to install $pkg — you may need to install it manually"
        fi
    done

    # Java (needed for Ghidra, jadx, apktool)
    if ! command -v java &>/dev/null; then
        info "Java not found — installing JDK..."
        case "$PKG_MGR" in
            apt)    pkg_install "default-jdk" || warn "Java install failed" ;;
            dnf)    pkg_install "java-17-openjdk-devel" || warn "Java install failed" ;;
            pacman) pkg_install "jdk-openjdk" || warn "Java install failed" ;;
            brew)   pkg_install "openjdk" || warn "Java install failed" ;;
        esac
    else
        success "Java already available: $(java -version 2>&1 | head -1)"
    fi

    # Android tools (jadx, apktool)
    if [[ "$FLAG_NO_ANDROID" == false ]] && [[ "$FLAG_MINIMAL" == false ]]; then
        info "Installing Android RE tools..."
        case "$PKG_MGR" in
            brew)
                pkg_install "jadx" || warn "jadx install failed"
                pkg_install "apktool" || warn "apktool install failed"
                ;;
            *)
                # jadx — download binary release for Linux
                if ! command -v jadx &>/dev/null; then
                    info "Downloading jadx..."
                    local jadx_ver="1.5.1"
                    local jadx_url="https://github.com/skylot/jadx/releases/download/v${jadx_ver}/jadx-${jadx_ver}.zip"
                    local jadx_dir="${REMCP_DIR}/jadx"
                    local jadx_zip
                    jadx_zip="$(mktemp /tmp/jadx_XXXXXX.zip)"
                    if curl -fSL --progress-bar -o "$jadx_zip" "$jadx_url" 2>>"$LOG_FILE"; then
                        mkdir -p "$jadx_dir"
                        unzip -qo "$jadx_zip" -d "$jadx_dir" >> "$LOG_FILE" 2>&1
                        chmod +x "$jadx_dir/bin/jadx" "$jadx_dir/bin/jadx-gui" 2>/dev/null || true
                        success "jadx installed to $jadx_dir/bin/jadx"
                        info "Add to PATH: export PATH=\"${jadx_dir}/bin:\$PATH\""
                    else
                        warn "jadx download failed — install manually: https://github.com/skylot/jadx/releases"
                    fi
                    rm -f "$jadx_zip"
                else
                    success "jadx already available: $(command -v jadx)"
                fi

                # apktool — download wrapper + jar for Linux
                if ! command -v apktool &>/dev/null; then
                    info "Downloading apktool..."
                    local apktool_dir="${REMCP_DIR}/apktool"
                    mkdir -p "$apktool_dir"
                    if curl -fSL -o "${apktool_dir}/apktool.jar" \
                        "$APKTOOL_JAR_URL" 2>>"$LOG_FILE" && \
                       curl -fSL -o "${apktool_dir}/apktool" \
                        "$APKTOOL_SCRIPT_URL" 2>>"$LOG_FILE"; then
                        chmod +x "${apktool_dir}/apktool"
                        success "apktool installed to ${apktool_dir}/apktool"
                        info "Add to PATH: export PATH=\"${apktool_dir}:\$PATH\""
                    else
                        warn "apktool download failed — install manually: https://ibotpeaches.github.io/Apktool/install/"
                    fi
                else
                    success "apktool already available: $(command -v apktool)"
                fi
                ;;
        esac
    fi

    # Pip-installable CLI tools (floss, capa) — these are Python packages that provide CLI commands
    if [[ "$FLAG_MINIMAL" == false ]]; then
        info "Installing pip-based CLI tools (floss, capa, ROPgadget, ropper)..."
        $PIP install --upgrade "flare-floss>=3.0.0" >> "$LOG_FILE" 2>&1 \
            && success "floss (FLARE) installed." \
            || warn "floss install failed — install manually: pip install flare-floss"
        $PIP install --upgrade "flare-capa>=7.0.0" >> "$LOG_FILE" 2>&1 \
            && success "capa (FLARE) installed." \
            || warn "capa install failed — install manually: pip install flare-capa"
        $PIP install --upgrade "ROPGadget" "ropper" >> "$LOG_FILE" 2>&1 \
            && success "ROPgadget/ropper installed." \
            || warn "ROPgadget/ropper install failed — install manually: pip install ROPGadget ropper"

        if ! command -v one_gadget &>/dev/null; then
            if command -v gem &>/dev/null; then
                info "Installing one_gadget via RubyGems..."
                gem install --no-document one_gadget >> "$LOG_FILE" 2>&1 \
                    && success "one_gadget installed." \
                    || warn "one_gadget install failed — install manually: gem install one_gadget"
            else
                warn "one_gadget not installed (Ruby gem 'gem' not found). Install manually: gem install one_gadget"
            fi
        else
            success "one_gadget already available: $(command -v one_gadget)"
        fi
    fi

    # Fail hard if core runtime tools are still unavailable after install.
    local missing_core_tools=()
    for core_tool in gdb objdump strings; do
        if ! command -v "$core_tool" &>/dev/null; then
            missing_core_tools+=("$core_tool")
        fi
    done
    if [[ "${#missing_core_tools[@]}" -gt 0 ]]; then
        die "Missing required system tools after install: ${missing_core_tools[*]}"
    fi

    success "System dependencies installed."
}

# ---------------------------------------------------------------------------
# Python dependency installation
# ---------------------------------------------------------------------------

install_python_deps() {
    info "Installing Python dependencies..."

    # Core deps (always)
    local core_pkgs=(
        "capstone>=5.0.0"
        "lief>=0.14.0"
        "pefile>=2023.2.7"
        "pyelftools>=0.30"
        "yara-python>=4.3.0"
        "mcp>=1.0.0"
        "jsonschema>=4.20.0"
    )

    info "Installing core Python packages..."
    $PIP install --upgrade "${core_pkgs[@]}" >> "$LOG_FILE" 2>&1 \
        && success "Core Python packages installed." \
        || die "Core Python package installation failed — check $LOG_FILE"

    if [[ "$FLAG_MINIMAL" == true ]]; then
        info "--minimal mode: skipping optional Python packages."
        return
    fi

    # Extended deps
    local extended_pkgs=(
        "r2pipe>=1.8.0"
        "scapy>=2.5.0"
        "python-tlsh>=4.5.0"
        "ppdeep>=1.1"
        "uncompyle6>=3.9.0"
    )

    # Frida + androguard (unless --no-android)
    if [[ "$FLAG_NO_ANDROID" == false ]]; then
        extended_pkgs+=(
            "frida>=16.0.0"
            "frida-tools>=12.0.0"
            "androguard>=3.4.0a1"
            "semgrep"
            "quark-engine"
        )
    fi

    info "Installing extended Python packages..."
    # Install one-by-one so a single failure doesn't block everything
    for pkg in "${extended_pkgs[@]}"; do
        info "  Installing $pkg ..."
        $PIP install --upgrade "$pkg" >> "$LOG_FILE" 2>&1 \
            && success "  $pkg" \
            || warn "  $pkg failed — check $LOG_FILE (may need system build deps)"
    done

    # angr (large, separate — ~2 GB)
    info "Installing angr (this may take several minutes, ~2 GB)..."
    $PIP install --upgrade "angr>=9.2.0" >> "$LOG_FILE" 2>&1 \
        && success "angr installed." \
        || warn "angr installation failed — it may not support your platform"

    # triton — note: the PyPI 'triton' is OpenAI's Triton GPU compiler, NOT
    # Jonathan Salwan's Triton for binary analysis. The RE Triton must be built
    # from source: https://github.com/JonathanSalwan/Triton
    warn "Triton (symbolic execution): NOT available via pip."
    warn "  Build from source: https://github.com/JonathanSalwan/Triton"
    warn "  This is optional — most users don't need it."
}

# ---------------------------------------------------------------------------
# Ghidra headless download
# ---------------------------------------------------------------------------

install_ghidra() {
    if [[ "$FLAG_NO_GHIDRA" == true ]] || [[ "$FLAG_MINIMAL" == true ]]; then
        info "Skipping Ghidra download (--no-ghidra or --minimal)."
        return
    fi

    local ghidra_dir="${REMCP_DIR}/ghidra"

    if [[ -d "$ghidra_dir" ]] && [[ -f "$ghidra_dir/support/analyzeHeadless" ]]; then
        success "Ghidra already installed at $ghidra_dir"
        return
    fi

    info "Downloading Ghidra ${GHIDRA_VERSION}..."
    local tmp_zip
    tmp_zip="$(mktemp /tmp/ghidra_XXXXXX.zip)"

    if ! curl -fSL --progress-bar -o "$tmp_zip" "$GHIDRA_URL"; then
        warn "Ghidra download failed. You can download manually from:"
        warn "  https://ghidra-sre.org/"
        rm -f "$tmp_zip"
        return
    fi

    local checksum_url="${GHIDRA_URL}.sha256"
    local checksum_file
    checksum_file="$(mktemp /tmp/ghidra_sha_XXXXXX.txt)"
    if ! curl -fSL --progress-bar -o "$checksum_file" "$checksum_url"; then
        warn "Could not download Ghidra checksum (${checksum_url}); skipping auto-install for integrity."
        rm -f "$tmp_zip" "$checksum_file"
        return
    fi
    local expected_sha actual_sha
    expected_sha="$(awk '{print $1}' "$checksum_file" | head -1 | tr -d '\r')"
    actual_sha="$(sha256_file "$tmp_zip" || true)"
    rm -f "$checksum_file"
    if [[ -z "$expected_sha" ]] || [[ -z "$actual_sha" ]] || [[ "$expected_sha" != "$actual_sha" ]]; then
        warn "Ghidra checksum verification failed (expected=${expected_sha:-missing}, actual=${actual_sha:-missing})."
        warn "Skipping automatic Ghidra install."
        rm -f "$tmp_zip"
        return
    fi

    info "Extracting Ghidra..."
    mkdir -p "${REMCP_DIR}"
    local extract_dir
    extract_dir="$(mktemp -d /tmp/ghidra_extract_XXXXXX)"
    unzip -q "$tmp_zip" -d "$extract_dir" >> "$LOG_FILE" 2>&1

    # The zip contains a top-level folder like ghidra_11.2.1_PUBLIC
    local inner_dir
    inner_dir="$(find "$extract_dir" -maxdepth 1 -type d -name 'ghidra_*' | head -1)"
    if [[ -z "$inner_dir" ]]; then
        warn "Unexpected Ghidra zip structure. Check $extract_dir"
        rm -f "$tmp_zip"
        return
    fi

    rm -rf "$ghidra_dir"
    mv "$inner_dir" "$ghidra_dir"
    rm -f "$tmp_zip"
    rm -rf "$extract_dir"

    chmod +x "$ghidra_dir/support/analyzeHeadless" 2>/dev/null || true

    success "Ghidra installed to $ghidra_dir"
    info "Add to PATH: export PATH=\"${ghidra_dir}/support:\$PATH\""
}

# ---------------------------------------------------------------------------
# YARA rules download
# ---------------------------------------------------------------------------

download_yara_rules() {
    if [[ "$FLAG_MINIMAL" == true ]]; then
        info "Skipping YARA rules download (--minimal)."
        return
    fi

    local rules_dir="${REMCP_DIR}/yara_rules"
    local legacy_rules_dir="${REMCP_DIR}/yara-rules"

    if [[ -d "$legacy_rules_dir" ]] && [[ ! -d "$rules_dir" ]]; then
        info "Migrating legacy YARA rules directory (${legacy_rules_dir}) to ${rules_dir}"
        mkdir -p "$rules_dir"
        cp -rn "${legacy_rules_dir}/." "$rules_dir/" 2>/dev/null || true
    fi

    if [[ -d "$rules_dir" ]] && [[ "$(find "$rules_dir" -name '*.yar' 2>/dev/null | head -1)" ]]; then
        success "YARA rules already present at $rules_dir"
        sync_legacy_yara_dir "$rules_dir" "$legacy_rules_dir"
        return
    fi

    info "Downloading community YARA rules..."
    local tmp_zip
    tmp_zip="$(mktemp /tmp/yara_rules_XXXXXX.zip)"

    if ! curl -fSL --progress-bar -o "$tmp_zip" "$YARA_RULES_REPO"; then
        warn "YARA rules download failed. Download manually:"
        warn "  https://github.com/Yara-Rules/rules"
        rm -f "$tmp_zip"
        return
    fi

    mkdir -p "$rules_dir"
    local extract_dir
    extract_dir="$(mktemp -d /tmp/yara_extract_XXXXXX)"
    unzip -q "$tmp_zip" -d "$extract_dir" >> "$LOG_FILE" 2>&1

    # Move the inner rules-master/ content
    local inner
    inner="$(find "$extract_dir" -maxdepth 1 -type d -name 'rules-*' | head -1)"
    if [[ -n "$inner" ]]; then
        cp -r "$inner"/* "$rules_dir"/ 2>/dev/null || true
    fi

    rm -f "$tmp_zip"
    rm -rf "$extract_dir"

    local count
    count="$(find "$rules_dir" -name '*.yar' -o -name '*.yara' 2>/dev/null | wc -l)"
    success "YARA rules installed: ${count} rule files in $rules_dir"
    sync_legacy_yara_dir "$rules_dir" "$legacy_rules_dir"
}

# ---------------------------------------------------------------------------
# Install revula itself
# ---------------------------------------------------------------------------

install_remcp() {
    info "Installing revula..."

    # Detect if we are inside the source tree
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_root="${script_dir}/../.."

    if [[ -f "${project_root}/pyproject.toml" ]]; then
        info "Installing revula from local source in editable mode (core package)..."
        $PIP install -e "${project_root}" >> "$LOG_FILE" 2>&1 \
            && success "revula installed (editable mode)." \
            || die "revula installation failed — check $LOG_FILE"
    else
        info "Installing revula core package from PyPI..."
        $PIP install "revula" >> "$LOG_FILE" 2>&1 \
            && success "revula installed from PyPI." \
            || die "revula installation failed — check $LOG_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir -p "$REMCP_DIR"
    : > "$LOG_FILE"

    banner
    info "Install log: $LOG_FILE"
    info "Flags: minimal=$FLAG_MINIMAL no-android=$FLAG_NO_ANDROID no-ghidra=$FLAG_NO_GHIDRA"
    echo ""

    detect_platform
    check_python
    echo ""

    install_system_deps
    echo ""

    install_python_deps
    echo ""

    install_ghidra
    echo ""

    download_yara_rules
    echo ""

    install_remcp
    echo ""

    echo -e "${GREEN}${BOLD}"
    echo "══════════════════════════════════════════════════════"
    echo "  Revula installation complete!"
    echo "══════════════════════════════════════════════════════"
    echo -e "${NC}"
    info "Next steps:"
    info "  1. Verify: scripts/install/install_verify.sh"
    info "  2. Configure Claude Desktop: python scripts/setup/setup_claude_desktop.py"
    info "  3. Start the server: revula"
    info ""
    info "Full log: $LOG_FILE"
}

main "$@"
