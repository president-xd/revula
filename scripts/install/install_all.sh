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
#   --no-android    Skip Android-related tools (jadx, apktool, aapt, smali, frida, androguard, semgrep, quark)
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
readonly SMALI_VERSION="2.5.2"
readonly SMALI_JAR_URL="https://repo.maven.apache.org/maven2/org/smali/smali/${SMALI_VERSION}/smali-${SMALI_VERSION}.jar"
readonly BAKSMALI_JAR_URL="https://repo.maven.apache.org/maven2/org/smali/baksmali/${SMALI_VERSION}/baksmali-${SMALI_VERSION}.jar"
readonly CFR_VERSION="0.152"
readonly CFR_JAR_URL="https://www.benf.org/other/cfr/cfr-${CFR_VERSION}.jar"
readonly RADARE2_VERSION="6.1.2"
readonly RADARE2_DEB_URL="https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb"
readonly RIZIN_VERSION="0.8.2"
readonly RIZIN_TAR_URL="https://github.com/rizinorg/rizin/releases/download/v${RIZIN_VERSION}/rizin-v${RIZIN_VERSION}-static-x86_64.tar.xz"
readonly DYNAMORIO_VERSION="11.91.20545"
readonly DYNAMORIO_TAR_URL="https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-${DYNAMORIO_VERSION}/DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz"
readonly DIE_VERSION="3.10"
readonly DIE_DEB_URL="https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_12_amd64.deb"
readonly UPX_VERSION="5.1.1"
readonly UPX_TAR_URL="https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz"
readonly RETDEC_VERSION="5.0"
readonly RETDEC_TAR_URL="https://github.com/avast/retdec/releases/download/v${RETDEC_VERSION}/RetDec-v${RETDEC_VERSION}-Linux-Release.tar.xz"
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
                echo "  --no-android    Skip jadx, apktool, aapt, smali, androguard, frida, semgrep, quark"
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
        [wabt]=wabt [libfuzzy]=libfuzzy-dev [llvm]=llvm [ruby]=ruby-full
        [apksigner]=apksigner
        [checksec]=checksec [monodis]=mono-utils [msfvenom]=metasploit-framework
        [drrun]=dynamorio [adb]=adb
    )
    declare -A dnf_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx [qemu_user]=qemu-user-static [qemu_system]=qemu-system-x86 [qemu_utils]=qemu-img
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=wireshark-cli
        [wabt]=wabt [libfuzzy]=ssdeep-devel [llvm]=llvm [ruby]=ruby
        [apksigner]=android-tools
        [checksec]=checksec [monodis]=mono-core [msfvenom]=metasploit
        [drrun]=dynamorio [adb]=android-tools
    )
    declare -A pacman_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx [qemu_user]=qemu-user [qemu_system]=qemu-full [qemu_utils]=qemu-full
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=wireshark-cli
        [wabt]=wabt [libfuzzy]=ssdeep [llvm]=llvm [ruby]=ruby
        [apksigner]=android-sdk-build-tools
        [checksec]=checksec [monodis]=mono [msfvenom]=metasploit
        [drrun]=dynamorio [adb]=android-tools
    )
    declare -A brew_pkgs=(
        [gdb]=gdb [binutils]=binutils [binwalk]=binwalk
        [upx]=upx [qemu_user]=qemu [qemu_system]=qemu [qemu_utils]=qemu
        [radare2]=radare2
        [lldb]=lldb [rizin]=rizin [tshark]=wireshark
        [wabt]=wabt [libfuzzy]=ssdeep [llvm]=llvm [ruby]=ruby
        [apksigner]=android-platform-tools
        [checksec]=checksec [monodis]=mono [msfvenom]=metasploit
        [drrun]=dynamorio [adb]=android-platform-tools
    )

    local tools_to_install=(
        gdb binutils binwalk
        qemu_user qemu_system qemu_utils
        lldb tshark wabt
        libfuzzy llvm ruby
        checksec monodis adb apksigner
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

    # Android tools (jadx, apktool, aapt, smali/baksmali)
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

        # aapt is required by APK analyzers
        if ! command -v aapt &>/dev/null; then
            info "aapt not found; attempting installation..."
            case "$PKG_MGR" in
                apt)
                    pkg_install "android-sdk-build-tools" \
                        || warn "aapt install failed — install manually: sudo apt install android-sdk-build-tools"
                    ;;
                *)
                    warn "aapt not auto-installed on ${PKG_MGR:-unknown}. Install Android build tools manually."
                    ;;
            esac
        else
            success "aapt already available: $(command -v aapt)"
        fi

        # smali/baksmali are required for DEX disassembly/assembly handlers
        if ! command -v smali &>/dev/null || ! command -v baksmali &>/dev/null; then
            info "Installing smali/baksmali wrappers..."
            local smali_dir="${REMCP_DIR}/smali"
            mkdir -p "$smali_dir"
            if curl -fSL -o "${smali_dir}/smali.jar" "$SMALI_JAR_URL" 2>>"$LOG_FILE" && \
               curl -fSL -o "${smali_dir}/baksmali.jar" "$BAKSMALI_JAR_URL" 2>>"$LOG_FILE"; then
                cat > "${smali_dir}/smali" <<'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec java -jar "${DIR}/smali.jar" "$@"
EOF
                cat > "${smali_dir}/baksmali" <<'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec java -jar "${DIR}/baksmali.jar" "$@"
EOF
                chmod +x "${smali_dir}/smali" "${smali_dir}/baksmali"
                success "smali/baksmali installed to ${smali_dir}"
                info "Add to PATH: export PATH=\"${smali_dir}:\$PATH\""
            else
                warn "smali/baksmali download failed — install manually: https://github.com/JesusFreke/smali"
            fi
        else
            success "smali already available: $(command -v smali)"
            success "baksmali already available: $(command -v baksmali)"
        fi
    fi

    # Fill optional tool gaps that are commonly missing from default distro repos.
    if [[ "$FLAG_MINIMAL" == false ]]; then
        local user_tools_dir="${REMCP_DIR}/tools"
        local user_bin_dir="${HOME}/.local/bin"
        local added_user_bin=false
        mkdir -p "$user_tools_dir" "$user_bin_dir"

        # CFR decompiler (jar + wrapper)
        if ! command -v cfr &>/dev/null; then
            info "Installing CFR decompiler wrapper..."
            local cfr_dir="${user_tools_dir}/cfr"
            mkdir -p "$cfr_dir"
            if curl -fSL -o "${cfr_dir}/cfr.jar" "$CFR_JAR_URL" 2>>"$LOG_FILE"; then
                cat > "${cfr_dir}/cfr" <<'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec java -jar "${DIR}/cfr.jar" "$@"
EOF
                chmod +x "${cfr_dir}/cfr"
                ln -sfn "${cfr_dir}/cfr" "${user_bin_dir}/cfr"
                added_user_bin=true
                success "cfr installed to ${cfr_dir}/cfr"
            else
                warn "cfr download failed — install manually from https://www.benf.org/other/cfr/"
            fi
        else
            success "cfr already available: $(command -v cfr)"
        fi

        if [[ "$PKG_MGR" == "apt" ]]; then
            # apksigner
            if ! command -v apksigner &>/dev/null; then
                pkg_install "apksigner" \
                    && success "apksigner installed." \
                    || warn "apksigner install failed — install manually: sudo apt install apksigner"
            fi

            # ikdasm is usually provided by mono-devel, monodis by mono-utils
            if ! command -v ikdasm &>/dev/null; then
                pkg_install "mono-devel" \
                    && success "mono-devel installed (ikdasm)." \
                    || warn "ikdasm unavailable — install manually: sudo apt install mono-devel"
            fi

            # pdbutil via LLVM (versioned binary is acceptable)
            if ! command -v llvm-pdbutil &>/dev/null && ! command -v llvm-pdbutil-19 &>/dev/null; then
                pkg_install "llvm-19" || pkg_install "llvm" \
                    || warn "pdbutil unavailable — install manually: sudo apt install llvm-19"
            fi

            # msfvenom via Rapid7 apt repository
            if ! command -v msfvenom &>/dev/null; then
                info "Installing metasploit-framework (msfvenom) from apt.metasploit.com..."
                local msf_key_tmp msf_keyring msf_repo
                msf_key_tmp="$(mktemp /tmp/metasploit_key_XXXXXX.asc)"
                msf_keyring="/usr/share/keyrings/metasploit-framework.gpg"
                msf_repo="/etc/apt/sources.list.d/metasploit-framework.list"
                if pkg_install "gnupg" && \
                   curl -fSL -o "$msf_key_tmp" "https://apt.metasploit.com/metasploit-framework.gpg.key" 2>>"$LOG_FILE" && \
                   sudo gpg --dearmor -o "$msf_keyring" "$msf_key_tmp" >>"$LOG_FILE" 2>&1; then
                    echo "deb [signed-by=${msf_keyring}] https://apt.metasploit.com/ lucid main" | sudo tee "$msf_repo" >/dev/null
                    if sudo apt-get update >>"$LOG_FILE" 2>&1 && \
                       sudo apt-get install -y metasploit-framework >>"$LOG_FILE" 2>&1; then
                        success "metasploit-framework installed (msfvenom)."
                    else
                        warn "metasploit-framework install failed — see $LOG_FILE"
                    fi
                    sudo rm -f "$msf_repo" "$msf_keyring" >>"$LOG_FILE" 2>&1 || true
                    sudo apt-get update >>"$LOG_FILE" 2>&1 || true
                else
                    warn "Failed to configure metasploit apt repository."
                fi
                rm -f "$msf_key_tmp"
            fi

            # radare2 from upstream Debian package
            if ! command -v r2 &>/dev/null; then
                info "Installing radare2 from upstream release package..."
                local radare2_deb
                radare2_deb="$(mktemp /tmp/radare2_XXXXXX.deb)"
                if curl -fSL -o "$radare2_deb" "$RADARE2_DEB_URL" 2>>"$LOG_FILE" && \
                   sudo apt-get install -y "$radare2_deb" >>"$LOG_FILE" 2>&1; then
                    success "radare2 installed."
                else
                    warn "radare2 install failed — install manually from https://github.com/radareorg/radare2/releases"
                fi
                rm -f "$radare2_deb"
            fi

            # Detect It Easy CLI (diec)
            if ! command -v diec &>/dev/null; then
                info "Installing Detect It Easy (diec)..."
                local die_deb
                die_deb="$(mktemp /tmp/die_XXXXXX.deb)"
                if curl -fSL -o "$die_deb" "$DIE_DEB_URL" 2>>"$LOG_FILE" && \
                   sudo apt-get install -y "$die_deb" >>"$LOG_FILE" 2>&1; then
                    success "diec installed."
                else
                    warn "diec install failed — install manually from https://github.com/horsicq/DIE-engine/releases"
                fi
                rm -f "$die_deb"
            fi
        fi

        # rizin + rz-diff (static bundle)
        if ! command -v rizin &>/dev/null || ! command -v rz-diff &>/dev/null; then
            info "Installing rizin static bundle..."
            local rizin_dir="${user_tools_dir}/rizin"
            local rizin_tar
            rizin_tar="$(mktemp /tmp/rizin_XXXXXX.tar.xz)"
            if curl -fSL -o "$rizin_tar" "$RIZIN_TAR_URL" 2>>"$LOG_FILE"; then
                rm -rf "$rizin_dir"
                mkdir -p "$rizin_dir"
                tar -xf "$rizin_tar" -C "$rizin_dir" >>"$LOG_FILE" 2>&1
                ln -sfn "${rizin_dir}/bin/rizin" "${user_bin_dir}/rizin"
                ln -sfn "${rizin_dir}/bin/rz" "${user_bin_dir}/rz"
                ln -sfn "${rizin_dir}/bin/rz-diff" "${user_bin_dir}/rz-diff"
                added_user_bin=true
                success "rizin/rz-diff installed to ${rizin_dir}"
            else
                warn "rizin download failed — install manually from https://github.com/rizinorg/rizin/releases"
            fi
            rm -f "$rizin_tar"
        fi

        # drrun (DynamoRIO)
        if ! command -v drrun &>/dev/null; then
            info "Installing DynamoRIO (drrun)..."
            local dr_dir="${user_tools_dir}/dynamorio"
            local dr_tar
            dr_tar="$(mktemp /tmp/dynamorio_XXXXXX.tar.gz)"
            if curl -fSL -o "$dr_tar" "$DYNAMORIO_TAR_URL" 2>>"$LOG_FILE"; then
                rm -rf "$dr_dir"
                mkdir -p "$dr_dir"
                tar -xzf "$dr_tar" -C "$dr_dir" --strip-components=1 >>"$LOG_FILE" 2>&1
                printf '#!/usr/bin/env bash\nexec "%s/bin64/drrun" "$@"\n' "$dr_dir" > "${user_bin_dir}/drrun"
                chmod +x "${user_bin_dir}/drrun"
                added_user_bin=true
                success "drrun installed with wrapper at ${user_bin_dir}/drrun"
            else
                warn "DynamoRIO download failed — install manually from https://dynamorio.org/"
            fi
            rm -f "$dr_tar"
        fi

        # UPX
        if ! command -v upx &>/dev/null; then
            info "Installing UPX..."
            local upx_dir="${user_tools_dir}/upx"
            local upx_tar
            upx_tar="$(mktemp /tmp/upx_XXXXXX.tar.xz)"
            if curl -fSL -o "$upx_tar" "$UPX_TAR_URL" 2>>"$LOG_FILE"; then
                rm -rf "$upx_dir"
                mkdir -p "$upx_dir"
                tar -xf "$upx_tar" -C "$upx_dir" >>"$LOG_FILE" 2>&1
                ln -sfn "${upx_dir}/upx-${UPX_VERSION}-amd64_linux/upx" "${user_bin_dir}/upx"
                added_user_bin=true
                success "upx installed."
            else
                warn "UPX download failed — install manually from https://github.com/upx/upx/releases"
            fi
            rm -f "$upx_tar"
        fi

        # RetDec
        if ! command -v retdec-decompiler &>/dev/null; then
            info "Installing RetDec decompiler..."
            local retdec_dir="${user_tools_dir}/retdec"
            local retdec_tar
            retdec_tar="$(mktemp /tmp/retdec_XXXXXX.tar.xz)"
            if curl -fSL -o "$retdec_tar" "$RETDEC_TAR_URL" 2>>"$LOG_FILE"; then
                rm -rf "$retdec_dir"
                mkdir -p "$retdec_dir"
                tar -xf "$retdec_tar" -C "$retdec_dir" >>"$LOG_FILE" 2>&1
                ln -sfn "${retdec_dir}/bin/retdec-decompiler" "${user_bin_dir}/retdec-decompiler"
                added_user_bin=true
                success "retdec-decompiler installed."
            else
                warn "RetDec download failed — install manually from https://github.com/avast/retdec/releases"
            fi
            rm -f "$retdec_tar"
        fi

        if [[ "$added_user_bin" == true ]]; then
            info "Ensure ~/.local/bin is on PATH: export PATH=\"${user_bin_dir}:\$PATH\""
        fi
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
                if gem install --no-document --user-install one_gadget >> "$LOG_FILE" 2>&1; then
                    local gem_user_bin
                    gem_user_bin="$(ruby -e 'print Gem.user_dir' 2>/dev/null)/bin"
                    if [[ -x "${gem_user_bin}/one_gadget" ]]; then
                        mkdir -p "${HOME}/.local/bin"
                        ln -sfn "${gem_user_bin}/one_gadget" "${HOME}/.local/bin/one_gadget"
                        success "one_gadget installed to ${gem_user_bin}/one_gadget"
                        info "Ensure ~/.local/bin is on PATH: export PATH=\"${HOME}/.local/bin:\$PATH\""
                    else
                        success "one_gadget installed."
                    fi
                else
                    warn "one_gadget install failed — install manually: gem install --user-install one_gadget"
                fi
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
        "unicorn>=2.0.0"
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
