#!/bin/bash
# Docker Build and Test Script for Revula (stdio-only runtime)

set -euo pipefail

echo "=========================================="
echo "Revula Docker Build & Test Script"
echo "=========================================="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: Docker is not installed or not in PATH${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}ERROR: Docker daemon is not running${NC}"
    echo "Please start Docker Desktop or the Docker daemon"
    exit 1
fi

echo -e "${GREEN}Docker is available${NC}"
echo ""

echo "=========================================="
echo "Building Docker image..."
echo "=========================================="
docker build -t revula:latest .
echo -e "${GREEN}Docker image built successfully${NC}"
echo ""

echo "=========================================="
echo "Test 1: Package import and version"
echo "=========================================="
docker run --rm --entrypoint python revula:latest -c "import revula; print(revula.__version__)"
echo -e "${GREEN}Test 1 passed${NC}"
echo ""

echo "=========================================="
echo "Test 2: Tool registry loads"
echo "=========================================="
docker run --rm --entrypoint python revula:latest -c "from revula.server import _register_all_tools; from revula.tools import TOOL_REGISTRY; _register_all_tools(); print(TOOL_REGISTRY.count())"
echo -e "${GREEN}Test 2 passed${NC}"
echo ""

echo "=========================================="
echo "Test 3: Availability report command"
echo "=========================================="
docker run --rm --entrypoint python revula:latest -c "from revula.config import get_config, format_availability_report; print(format_availability_report(get_config()))" | head -40
echo -e "${GREEN}Test 3 passed${NC}"
echo ""

echo "=========================================="
echo "Test 4: Core Python dependencies"
echo "=========================================="
docker run --rm --entrypoint python revula:latest -c "
import capstone
import lief
import pefile
import yara
import mcp
import jsonschema
print('Core dependencies imported successfully')
"
echo -e "${GREEN}Test 4 passed${NC}"
echo ""

echo "=========================================="
echo "Test 5: External tool coverage"
echo "=========================================="
docker run --rm --entrypoint python revula:latest - <<'PY'
import shutil
import sys

checks = {
    "gdb": ["gdb"],
    "radare2": ["r2", "radare2"],
    "rizin": ["rizin"],
    "rz_diff": ["rz-diff"],
    "ghidra_headless": ["analyzeHeadless"],
    "upx": ["upx"],
    "retdec_decompiler": ["retdec-decompiler"],
    "drrun": ["drrun"],
    "msfvenom": ["msfvenom"],
    "one_gadget": ["one_gadget"],
    "checksec": ["checksec"],
    "diec": ["diec"],
    "apksigner": ["apksigner"],
    "monodis": ["monodis"],
    "ikdasm": ["ikdasm", "ildasm"],
    "pdbutil": [
        "llvm-pdbutil",
        "llvm-pdbutil-20",
        "llvm-pdbutil-19",
        "llvm-pdbutil-18",
        "llvm-pdbutil-17",
        "llvm-pdbutil-16",
        "llvm-pdbutil-15",
        "llvm-pdbutil-14",
    ],
    "cfr": ["cfr"],
    "qemu-img": ["qemu-img"],
}

missing = {}
for label, candidates in checks.items():
    resolved = None
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            resolved = path
            break
    if not resolved:
        missing[label] = candidates
    else:
        print(f"{label}: {resolved}")

if missing:
    print("Missing tools detected:")
    for label, candidates in missing.items():
        print(f"  - {label}: tried {', '.join(candidates)}")
    sys.exit(1)
PY
echo -e "${GREEN}Test 5 passed${NC}"
echo ""

echo "=========================================="
echo -e "${GREEN}All Docker checks passed${NC}"
echo "=========================================="
echo ""
echo "Docker image: revula:latest"
echo "Image size: $(docker images revula:latest --format '{{.Size}}')"
echo ""
echo "Usage examples:"
echo "  1. stdio mode (for MCP clients):"
echo "     docker run -i --rm -v \$(pwd)/workspace:/workspace -v revula-data:/root/.revula revula:latest"
echo ""
echo "  2. docker compose stdio profile:"
echo "     docker compose --profile stdio run --rm revula-stdio"
echo ""
echo "  3. Interactive shell:"
echo "     docker run -it --rm --entrypoint /bin/bash revula:latest"
echo ""
