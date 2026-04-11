#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Revula Post-Install Verification
# Checks that every required and optional tool is available and functional.
# =============================================================================

# ---------------------------------------------------------------------------
# Colored output
# ---------------------------------------------------------------------------

if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

PASS=0
FAIL=0
WARN=0

pass() { ((PASS++)) || true; echo -e "  ${GREEN}✓${NC} $*"; }
fail() { ((FAIL++)) || true; echo -e "  ${RED}✗${NC} $*"; }
skip() { ((WARN++)) || true; echo -e "  ${YELLOW}–${NC} $* ${YELLOW}(optional)${NC}"; }

# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

check_command() {
    local name="$1"
    local required="${2:-true}"
    if command -v "$name" &>/dev/null; then
        local loc
        loc="$(command -v "$name")"
        pass "$name  →  $loc"
    else
        if [[ "$required" == "true" ]]; then
            fail "$name  →  NOT FOUND"
        else
            skip "$name  →  not found"
        fi
    fi
}

check_python_module() {
    local module="$1"
    local import_name="${2:-$1}"
    local required="${3:-true}"
    local found_import=""
    local ver=""

    IFS='|' read -r -a imports <<< "$import_name"
    for mod in "${imports[@]}"; do
        if python3 -c "import ${mod}" 2>/dev/null; then
            found_import="$mod"
            break
        fi
    done

    if [[ -n "$found_import" ]]; then
        ver="$(python3 -c "
import ${found_import}
v = getattr(${found_import}, '__version__', getattr(${found_import}, 'VERSION', '?'))
print(v)
" 2>/dev/null || echo '?')"
        pass "Python: ${module}  →  ${found_import} v${ver}"
    else
        if [[ "$required" == "true" ]]; then
            fail "Python: ${module}  →  NOT IMPORTABLE"
        else
            skip "Python: ${module}  →  not installed"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Main checks
# ---------------------------------------------------------------------------

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       Revula Installation Verification               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}Python Runtime${NC}"
echo "──────────────────────────────────────────────────────"
if command -v python3 &>/dev/null; then
    py_ver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
    py_major="$(python3 -c 'import sys; print(sys.version_info.major)')"
    py_minor="$(python3 -c 'import sys; print(sys.version_info.minor)')"
    if [[ "$py_major" -ge 3 ]] && [[ "$py_minor" -ge 11 ]]; then
        pass "Python ${py_ver}  (>=3.11 ✓)"
    else
        fail "Python ${py_ver}  (need >=3.11)"
    fi
else
    fail "python3 not found"
fi
echo ""

echo -e "${BOLD}Revula Package${NC}"
echo "──────────────────────────────────────────────────────"
if python3 -c "import revula" 2>/dev/null; then
    remcp_ver="$(python3 -c 'import revula; print(revula.__version__)')"
    pass "revula  →  v${remcp_ver}"
else
    fail "revula  →  NOT INSTALLED"
fi

if command -v revula &>/dev/null; then
    pass "revula CLI  →  $(command -v revula)"
else
    skip "revula CLI  →  not in PATH (use: python -m revula.server)"
fi
echo ""

echo -e "${BOLD}Core Python Modules${NC}"
echo "──────────────────────────────────────────────────────"
check_python_module "capstone"    "capstone"   "true"
check_python_module "lief"        "lief"       "true"
check_python_module "pefile"      "pefile"     "true"
check_python_module "pyelftools"  "elftools"   "true"
check_python_module "yara-python" "yara"       "true"
check_python_module "mcp"         "mcp"        "true"
check_python_module "jsonschema"  "jsonschema" "true"
echo ""

echo -e "${BOLD}Optional Python Modules${NC}"
echo "──────────────────────────────────────────────────────"
check_python_module "frida"       "frida"      "false"
check_python_module "angr"        "angr"       "false"
check_python_module "unicorn"     "unicorn"    "false"
check_python_module "lldb"        "lldb"       "false"
check_python_module "r2pipe"      "r2pipe"     "false"
check_python_module "scapy"       "scapy"      "false"
check_python_module "androguard"  "androguard" "false"
check_python_module "tlsh"        "tlsh"       "false"
check_python_module "ssdeep"      "ssdeep|ppdeep" "false"
check_python_module "uncompyle6"  "uncompyle6" "false"
check_python_module "quark-engine" "quark"     "false"
check_python_module "semgrep"     "semgrep"    "false"
echo ""

echo -e "${BOLD}System Tools — Core${NC}"
echo "──────────────────────────────────────────────────────"
check_command "gdb"        "true"
check_command "objdump"    "true"
check_command "strings"    "true"
if command -v r2 &>/dev/null; then
    pass "r2  →  $(command -v r2)"
elif command -v radare2 &>/dev/null; then
    pass "r2  →  $(command -v radare2)"
else
    skip "r2  →  not found"
fi
check_command "rizin"      "false"
check_command "lldb"       "false"
check_command "checksec"   "false"
echo ""

echo -e "${BOLD}System Tools — Optional${NC}"
echo "──────────────────────────────────────────────────────"
check_command "binwalk"         "false"
check_command "upx"             "false"
check_command "qemu-x86_64"    "false"
check_command "qemu-arm"       "false"
check_command "qemu-system-x86_64" "false"
check_command "qemu-img"       "false"
check_command "tshark"          "false"
check_command "capinfos"        "false"
check_command "wasm2wat"        "false"
check_command "capa"            "false"
check_command "floss"           "false"
check_command "drrun"           "false"
check_command "msfvenom"        "false"
check_command "one_gadget"      "false"
check_command "monodis"         "false"
check_command "ikdasm"          "false"
check_command "cfr"             "false"
check_command "diec"            "false"
check_command "rz-diff"         "false"
check_command "retdec-decompiler" "false"
_pdbutil_cmd=""
for _pdb_candidate in llvm-pdbutil llvm-pdbutil-20 llvm-pdbutil-19 llvm-pdbutil-18 llvm-pdbutil-17 llvm-pdbutil-16 llvm-pdbutil-15 llvm-pdbutil-14; do
    if command -v "$_pdb_candidate" &>/dev/null; then
        _pdbutil_cmd="$(command -v "$_pdb_candidate")"
        break
    fi
done
if [[ -n "${_pdbutil_cmd}" ]]; then
    pass "llvm-pdbutil  →  ${_pdbutil_cmd}"
else
    skip "llvm-pdbutil  →  not found"
fi
check_command "semgrep"         "false"
check_command "quark"           "false"
echo ""

echo -e "${BOLD}Android RE Tools${NC}"
echo "──────────────────────────────────────────────────────"
check_command "jadx"      "false"
check_command "apktool"   "false"
check_command "aapt"      "false"
check_command "apksigner" "false"
check_command "baksmali"  "false"
check_command "smali"     "false"
check_command "adb"       "false"
echo ""

echo -e "${BOLD}Ghidra${NC}"
echo "──────────────────────────────────────────────────────"
if command -v analyzeHeadless &>/dev/null; then
    pass "Ghidra analyzeHeadless  →  $(command -v analyzeHeadless)"
elif [[ -f "${HOME}/.revula/ghidra/support/analyzeHeadless" ]]; then
    pass "Ghidra analyzeHeadless  →  ${HOME}/.revula/ghidra/support/analyzeHeadless"
    echo -e "  ${YELLOW}  Hint: add to PATH: export PATH=\"${HOME}/.revula/ghidra/support:\$PATH\"${NC}"
else
    skip "Ghidra analyzeHeadless  →  not found"
fi
echo ""

echo -e "${BOLD}YARA Rules${NC}"
echo "──────────────────────────────────────────────────────"
yara_dir="${HOME}/.revula/yara_rules"
legacy_yara_dir="${HOME}/.revula/yara-rules"
if [[ ! -d "$yara_dir" ]] && [[ -d "$legacy_yara_dir" ]]; then
    yara_dir="$legacy_yara_dir"
fi
if [[ -d "$yara_dir" ]]; then
    count="$(find "$yara_dir" -name '*.yar' -o -name '*.yara' 2>/dev/null | wc -l)"
    if [[ "$count" -gt 0 ]]; then
        pass "YARA rules: ${count} rule files in ${yara_dir}"
    else
        skip "YARA rules directory exists but no .yar files found"
    fi
else
    skip "YARA rules directory not found (${HOME}/.revula/yara_rules or ${HOME}/.revula/yara-rules)"
fi
echo ""

echo -e "${BOLD}Configuration${NC}"
echo "──────────────────────────────────────────────────────"
config_file="${HOME}/.revula/config.toml"
if [[ -f "$config_file" ]]; then
    pass "Config file: ${config_file}"
else
    skip "Config file not found (${config_file}) — defaults will be used"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "══════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed: ${PASS}${NC}  |  ${RED}Failed: ${FAIL}${NC}  |  ${YELLOW}Optional/Skipped: ${WARN}${NC}"
echo "══════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}${BOLD}Some required components are missing. See failures above.${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}All required components are available!${NC}"
    exit 0
fi
