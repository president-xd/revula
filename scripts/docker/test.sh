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
docker run --rm revula:latest python -c "import revula; print(revula.__version__)"
echo -e "${GREEN}Test 1 passed${NC}"
echo ""

echo "=========================================="
echo "Test 2: Tool registry loads"
echo "=========================================="
docker run --rm revula:latest python -c "from revula.server import _register_all_tools; from revula.tools import TOOL_REGISTRY; _register_all_tools(); print(TOOL_REGISTRY.count())"
echo -e "${GREEN}Test 2 passed${NC}"
echo ""

echo "=========================================="
echo "Test 3: Availability report command"
echo "=========================================="
docker run --rm revula:latest python -c "from revula.config import get_config, format_availability_report; print(format_availability_report(get_config()))" | head -40
echo -e "${GREEN}Test 3 passed${NC}"
echo ""

echo "=========================================="
echo "Test 4: Core Python dependencies"
echo "=========================================="
docker run --rm revula:latest python -c "
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
echo "Test 5: Core external binaries"
echo "=========================================="
docker run --rm revula:latest gdb --version | head -1
docker run --rm revula:latest r2 -v 2>&1 | head -1
docker run --rm revula:latest analyzeHeadless -help | head -3
docker run --rm revula:latest qemu-img --version | head -1
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
echo "     docker run -it --rm revula:latest /bin/bash"
echo ""
