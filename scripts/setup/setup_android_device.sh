#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Revula — Android Device Preparation Script
#
# Prepares a connected Android device for dynamic analysis with Frida:
#   1. Verify ADB connection
#   2. Detect device ABI
#   3. Download matching frida-server
#   4. Push frida-server to device
#   5. Start frida-server
#   6. Verify with frida-python
#   7. Setup port forwarding
#
# Usage:
#   ./setup_android_device.sh [--no-start] [--frida-version VERSION]
# =============================================================================

FLAG_NO_START=false
FRIDA_VERSION=""

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[  OK]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR!]${NC}  $*" >&2; }
die()     { error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-start)        FLAG_NO_START=true ;;
        --frida-version)   shift; FRIDA_VERSION="$1" ;;
        --help|-h)
            echo "Usage: $0 [--no-start] [--frida-version VERSION]"
            echo "  --no-start         Push frida-server but don't start it"
            echo "  --frida-version V  Use specific frida version (default: match pip frida)"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Prereq checks
# ---------------------------------------------------------------------------

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║    Revula — Android Device Setup                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ADB check
if ! command -v adb &>/dev/null; then
    die "adb not found. Install Android SDK platform-tools first."
fi
success "ADB found: $(command -v adb)"

# Check device connected
info "Checking for connected device..."
device_count="$(adb devices 2>/dev/null | grep -cE '\tdevice$' || true)"
if [[ "$device_count" -eq 0 ]]; then
    die "No Android device connected. Connect via USB and enable USB debugging."
elif [[ "$device_count" -gt 1 ]]; then
    warn "Multiple devices connected. Using first device."
    warn "Set ANDROID_SERIAL env var to target a specific device."
fi

DEVICE_SERIAL="$(adb devices 2>/dev/null | grep -E '\tdevice$' | head -1 | awk '{print $1}')"
success "Device connected: ${DEVICE_SERIAL}"

# Device info
DEVICE_MODEL="$(adb -s "$DEVICE_SERIAL" shell getprop ro.product.model 2>/dev/null | tr -d '\r' || echo 'unknown')"
ANDROID_VERSION="$(adb -s "$DEVICE_SERIAL" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r' || echo 'unknown')"
info "Device: ${DEVICE_MODEL} (Android ${ANDROID_VERSION})"

# ---------------------------------------------------------------------------
# Detect ABI
# ---------------------------------------------------------------------------

info "Detecting device ABI..."
DEVICE_ABI="$(adb -s "$DEVICE_SERIAL" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"

case "$DEVICE_ABI" in
    arm64-v8a)    FRIDA_ARCH="arm64"  ;;
    armeabi-v7a)  FRIDA_ARCH="arm"    ;;
    x86_64)       FRIDA_ARCH="x86_64" ;;
    x86)          FRIDA_ARCH="x86"    ;;
    *)            die "Unsupported ABI: ${DEVICE_ABI}" ;;
esac

success "Device ABI: ${DEVICE_ABI} → Frida arch: ${FRIDA_ARCH}"

# ---------------------------------------------------------------------------
# Determine frida version
# ---------------------------------------------------------------------------

if [[ -z "$FRIDA_VERSION" ]]; then
    info "Detecting installed frida-python version..."
    FRIDA_VERSION="$(python3 -c 'import frida; print(frida.__version__)' 2>/dev/null || true)"
    if [[ -z "$FRIDA_VERSION" ]]; then
        die "frida-python not installed. Install with: pip install frida frida-tools"
    fi
fi

success "Frida version: ${FRIDA_VERSION}"

# ---------------------------------------------------------------------------
# Download frida-server
# ---------------------------------------------------------------------------

FRIDA_SERVER_NAME="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
DOWNLOAD_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER_NAME}.xz"
CACHE_DIR="${HOME}/.revula/cache/frida"
FRIDA_BINARY="${CACHE_DIR}/${FRIDA_SERVER_NAME}"

mkdir -p "$CACHE_DIR"

if [[ -f "$FRIDA_BINARY" ]]; then
    success "frida-server already cached: ${FRIDA_BINARY}"
else
    info "Downloading ${FRIDA_SERVER_NAME}.xz ..."
    tmp_xz="${CACHE_DIR}/${FRIDA_SERVER_NAME}.xz"

    if ! curl -fSL --progress-bar -o "$tmp_xz" "$DOWNLOAD_URL"; then
        rm -f "$tmp_xz"
        die "Download failed. URL: ${DOWNLOAD_URL}"
    fi

    info "Decompressing..."
    if command -v xz &>/dev/null; then
        xz -d -f "$tmp_xz"
    elif command -v unxz &>/dev/null; then
        unxz -f "$tmp_xz"
    else
        die "xz/unxz not found. Install xz-utils."
    fi

    if [[ ! -f "$FRIDA_BINARY" ]]; then
        die "Decompression failed — expected file not found: ${FRIDA_BINARY}"
    fi

    chmod +x "$FRIDA_BINARY"
    success "Downloaded: ${FRIDA_BINARY}"
fi

# ---------------------------------------------------------------------------
# Check if frida-server already running
# ---------------------------------------------------------------------------

REMOTE_PATH="/data/local/tmp/frida-server"

running_pid="$(adb -s "$DEVICE_SERIAL" shell "pidof frida-server" 2>/dev/null | tr -d '\r' || true)"
if [[ -n "$running_pid" ]]; then
    warn "frida-server already running on device (PID: ${running_pid})"
    info "Killing existing frida-server..."
    adb -s "$DEVICE_SERIAL" shell "su -c 'kill -9 ${running_pid}'" 2>/dev/null || \
        adb -s "$DEVICE_SERIAL" shell "kill -9 ${running_pid}" 2>/dev/null || true
    sleep 1
fi

# ---------------------------------------------------------------------------
# Push to device
# ---------------------------------------------------------------------------

info "Pushing frida-server to device..."
adb -s "$DEVICE_SERIAL" push "$FRIDA_BINARY" "$REMOTE_PATH" 2>/dev/null
adb -s "$DEVICE_SERIAL" shell "chmod 755 ${REMOTE_PATH}" 2>/dev/null
success "frida-server pushed to ${REMOTE_PATH}"

# ---------------------------------------------------------------------------
# Start frida-server
# ---------------------------------------------------------------------------

if [[ "$FLAG_NO_START" == true ]]; then
    info "Skipping frida-server start (--no-start)"
else
    info "Starting frida-server on device (as root)..."

    # Try su first (rooted device)
    adb -s "$DEVICE_SERIAL" shell "su -c '${REMOTE_PATH} -D &'" 2>/dev/null &
    FRIDA_START_PID=$!

    # Wait a moment for it to start
    sleep 3

    # Verify
    running_pid="$(adb -s "$DEVICE_SERIAL" shell "pidof frida-server" 2>/dev/null | tr -d '\r' || true)"
    if [[ -n "$running_pid" ]]; then
        success "frida-server running on device (PID: ${running_pid})"
    else
        warn "frida-server may not have started. The device might need root."
        warn "Try manually: adb shell 'su -c /data/local/tmp/frida-server -D &'"
    fi

    # Cleanup background process
    wait "$FRIDA_START_PID" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Verify with frida-python
# ---------------------------------------------------------------------------

info "Verifying frida connection from host..."
if python3 -c "
import frida
import sys
try:
    device = frida.get_usb_device(timeout=5)
    print(f'Connected to: {device.name} (id={device.id})')
    processes = device.enumerate_processes()
    print(f'Processes visible: {len(processes)}')
    sys.exit(0)
except Exception as e:
    print(f'Frida connection failed: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
    success "Frida connection verified!"
else
    warn "Frida connection check failed. frida-server may not be running as root."
fi

# ---------------------------------------------------------------------------
# Port forwarding
# ---------------------------------------------------------------------------

info "Setting up port forwarding..."

# Default frida port
adb -s "$DEVICE_SERIAL" forward tcp:27042 tcp:27042 2>/dev/null && \
    success "Port forward: tcp:27042 → tcp:27042" || \
    warn "Port forwarding for 27042 failed"

adb -s "$DEVICE_SERIAL" forward tcp:27043 tcp:27043 2>/dev/null && \
    success "Port forward: tcp:27043 → tcp:27043" || \
    warn "Port forwarding for 27043 failed"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Android device ready for Revula dynamic analysis!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
info "Device:        ${DEVICE_MODEL} (${DEVICE_SERIAL})"
info "Android:       ${ANDROID_VERSION}"
info "ABI:           ${DEVICE_ABI}"
info "Frida version: ${FRIDA_VERSION}"
info "Frida server:  ${REMOTE_PATH}"
echo ""
info "Quick test:  frida-ps -U"
echo ""
