#!/bin/bash
# Docker Build and Test Script for Revula
# Complete testing of Docker image with all RE tools

set -e

echo "=========================================="
echo "Revula Docker Build & Test Script"
echo "=========================================="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: Docker is not installed or not in PATH${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}ERROR: Docker daemon is not running${NC}"
    echo "Please start Docker Desktop or the Docker daemon"
    exit 1
fi

echo -e "${GREEN}Docker is available${NC}"
echo ""

# Build the Docker image
echo "=========================================="
echo "Building Docker image..."
echo "=========================================="
docker build -t revula:latest .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Docker image built successfully${NC}"
else
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi
echo ""

# Test 1: Check revula command
echo "=========================================="
echo "Test 1: Checking revula command"
echo "=========================================="
docker run --rm revula:latest --version

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 1 passed${NC}"
else
    echo -e "${RED}Test 1 failed${NC}"
    exit 1
fi
echo ""

# Test 2: List available tools
echo "=========================================="
echo "Test 2: Listing available tools"
echo "=========================================="
docker run --rm revula:latest --list-tools | head -30

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 2 passed${NC}"
else
    echo -e "${RED}Test 2 failed${NC}"
    exit 1
fi
echo ""

# Test 3: Check Python dependencies
echo "=========================================="
echo "Test 3: Checking Python dependencies"
echo "=========================================="
docker run --rm revula:latest python -c "
import capstone
import lief
import pefile
import yara
import angr
import frida
import androguard
print('All core dependencies imported successfully')
"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 3 passed${NC}"
else
    echo -e "${RED}Test 3 failed${NC}"
    exit 1
fi
echo ""

# Test 4: Check GDB
echo "=========================================="
echo "Test 4: Checking GDB availability"
echo "=========================================="
docker run --rm revula:latest gdb --version | head -1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 4 passed${NC}"
else
    echo -e "${YELLOW}Test 4 warning (GDB not available)${NC}"
fi
echo ""

# Test 5: Check radare2
echo "=========================================="
echo "Test 5: Checking radare2 availability"
echo "=========================================="
docker run --rm revula:latest r2 -v 2>&1 | head -1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 5 passed${NC}"
else
    echo -e "${YELLOW}Test 5 warning (radare2 not available)${NC}"
fi
echo ""

# Test 6: Check Ghidra
echo "=========================================="
echo "Test 6: Checking Ghidra availability"
echo "=========================================="
docker run --rm revula:latest analyzeHeadless -help | head -5

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 6 passed (Ghidra available)${NC}"
else
    echo -e "${RED}Test 6 failed (Ghidra not available)${NC}"
    exit 1
fi
echo ""

# Test 7: Check Frida
echo "=========================================="
echo "Test 7: Checking Frida availability"
echo "=========================================="
docker run --rm revula:latest frida --version

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 7 passed (Frida available)${NC}"
else
    echo -e "${RED}Test 7 failed (Frida not available)${NC}"
    exit 1
fi
echo ""

# Test 8: Check Android tools
echo "=========================================="
echo "Test 8: Checking Android tools"
echo "=========================================="
docker run --rm revula:latest apktool --version
docker run --rm revula:latest jadx --version

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Test 8 passed (Android tools available)${NC}"
else
    echo -e "${YELLOW}Test 8 warning (Some Android tools not available)${NC}"
fi
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}All critical tests passed successfully${NC}"
echo "=========================================="
echo ""
echo "Docker image: revula:latest"
echo "Image size: $(docker images revula:latest --format '{{.Size}}')"
echo ""
echo "Usage examples:"
echo "  1. stdio mode (for MCP clients):"
echo "     docker run -i --rm -v \$(pwd)/workspace:/workspace revula:latest"
echo ""
echo "  2. SSE mode (for remote access):"
echo "     docker run -p 8000:8000 revula:latest --sse --host 0.0.0.0"
echo ""
echo "  3. Using docker-compose:"
echo "     docker-compose --profile sse up"
echo ""
echo "  4. Interactive shell:"
echo "     docker run -it --rm revula:latest /bin/bash"
echo ""
