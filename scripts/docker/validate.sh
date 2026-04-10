#!/bin/bash
# Validation script for Docker configuration
# Checks that all necessary files are present and properly configured

set -e

echo "=========================================="
echo "Revula Docker Configuration Validator"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check file existence
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}[PASS]${NC} Found: $1"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} Missing: $1"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

# Check directory existence
check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}[PASS]${NC} Found: $1/"
        return 0
    else
        echo -e "${YELLOW}[WARN]${NC} Missing: $1/ (will be created)"
        WARNINGS=$((WARNINGS + 1))
        return 1
    fi
}

echo "Checking Docker configuration files..."
echo ""

# Required files
check_file "Dockerfile"
check_file "docker-compose.yml"
check_file ".dockerignore"
check_file "requirements.txt"
check_file "pyproject.toml"
check_file "README.md"
check_file "LICENSE"

echo ""
echo "Checking Docker documentation..."
echo ""

check_file "DOCKER.md"
check_file "DOCKER-QUICKREF.md"
check_file "scripts/docker/test.sh"
check_file "scripts/docker/validate.sh"

# Check if scripts are executable
if [ -f "scripts/docker/test.sh" ]; then
    if [ -x "scripts/docker/test.sh" ]; then
        echo -e "${GREEN}[PASS]${NC} scripts/docker/test.sh is executable"
    else
        echo -e "${YELLOW}[WARN]${NC} scripts/docker/test.sh is not executable (run: chmod +x scripts/docker/test.sh)"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

if [ -f "scripts/docker/validate.sh" ]; then
    if [ -x "scripts/docker/validate.sh" ]; then
        echo -e "${GREEN}[PASS]${NC} scripts/docker/validate.sh is executable"
    else
        echo -e "${YELLOW}[WARN]${NC} scripts/docker/validate.sh is not executable (run: chmod +x scripts/docker/validate.sh)"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

echo ""
echo "Checking source code structure..."
echo ""

check_dir "src"
check_dir "src/revula"
check_file "src/revula/server.py"
check_file "src/revula/config.py"

echo ""
echo "Checking workspace directory..."
echo ""

check_dir "workspace"

echo ""
echo "Validating Dockerfile syntax..."
echo ""

# Check for common Dockerfile issues
if grep -q "FROM python:3.12-slim-bookworm" Dockerfile; then
    echo -e "${GREEN}[PASS]${NC} Base image specified correctly"
else
    echo -e "${RED}[FAIL]${NC} Base image not found or incorrect"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "ENTRYPOINT.*revula" Dockerfile; then
    echo -e "${GREEN}[PASS]${NC} Entrypoint configured"
else
    echo -e "${YELLOW}[WARN]${NC} Entrypoint not found in Dockerfile"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "WORKDIR /workspace" Dockerfile; then
    echo -e "${GREEN}[PASS]${NC} Working directory set to /workspace"
else
    echo -e "${YELLOW}[WARN]${NC} Working directory not set"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "VOLUME" Dockerfile; then
    echo -e "${GREEN}[PASS]${NC} Volumes configured"
else
    echo -e "${YELLOW}[WARN]${NC} No volumes configured"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo "Validating docker-compose.yml..."
echo ""

if grep -q "version:" docker-compose.yml; then
    echo -e "${GREEN}[PASS]${NC} docker-compose.yml has version specified"
else
    echo -e "${YELLOW}[WARN]${NC} docker-compose.yml version not specified"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "revula-stdio:" docker-compose.yml; then
    echo -e "${GREEN}[PASS]${NC} stdio service defined"
else
    echo -e "${RED}[FAIL]${NC} stdio service not found"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "revula-dev:" docker-compose.yml; then
    echo -e "${GREEN}[PASS]${NC} dev service defined"
else
    echo -e "${YELLOW}[WARN]${NC} dev service not defined"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "revula-data:" docker-compose.yml; then
    echo -e "${GREEN}[PASS]${NC} Persistent volume defined"
else
    echo -e "${RED}[FAIL]${NC} Persistent volume not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking .dockerignore patterns..."
echo ""

if grep -q "__pycache__" .dockerignore; then
    echo -e "${GREEN}[PASS]${NC} Python cache excluded"
else
    echo -e "${YELLOW}[WARN]${NC} Python cache not excluded"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q ".git" .dockerignore; then
    echo -e "${GREEN}[PASS]${NC} .git excluded"
else
    echo -e "${YELLOW}[WARN]${NC} .git not excluded"
    WARNINGS=$((WARNINGS + 1))
fi

if grep -q "venv" .dockerignore; then
    echo -e "${GREEN}[PASS]${NC} Virtual environments excluded"
else
    echo -e "${YELLOW}[WARN]${NC} Virtual environments not excluded"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo "Checking Python requirements..."
echo ""

if grep -q "mcp" requirements.txt; then
    echo -e "${GREEN}[PASS]${NC} MCP library in requirements"
else
    echo -e "${RED}[FAIL]${NC} MCP library not found in requirements.txt"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "capstone" requirements.txt; then
    echo -e "${GREEN}[PASS]${NC} Capstone in requirements"
else
    echo -e "${RED}[FAIL]${NC} Capstone not found in requirements.txt"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "lief" requirements.txt; then
    echo -e "${GREEN}[PASS]${NC} LIEF in requirements"
else
    echo -e "${RED}[FAIL]${NC} LIEF not found in requirements.txt"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "Checking documentation..."
echo ""

if grep -q "Docker" README.md; then
    echo -e "${GREEN}[PASS]${NC} Docker section in README.md"
else
    echo -e "${YELLOW}[WARN]${NC} Docker not mentioned in README.md"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -f "DOCKER.md" ]; then
    DOCKER_MD_LINES=$(wc -l < DOCKER.md)
    if [ "$DOCKER_MD_LINES" -gt 100 ]; then
        echo -e "${GREEN}[PASS]${NC} DOCKER.md has comprehensive documentation ($DOCKER_MD_LINES lines)"
    else
        echo -e "${YELLOW}[WARN]${NC} DOCKER.md seems incomplete ($DOCKER_MD_LINES lines)"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

echo ""
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}[PASS] All checks passed!${NC}"
    echo ""
    echo "Docker configuration is complete and ready to use."
    echo ""
    echo "Next steps:"
    echo "  1. Build the image: docker build -t revula:latest ."
    echo "  2. Run tests: ./scripts/docker/test.sh"
    echo "  3. Start using: docker compose --profile stdio run --rm revula-stdio"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}[WARN] Validation passed with $WARNINGS warning(s)${NC}"
    echo ""
    echo "Configuration is functional but could be improved."
    exit 0
else
    echo -e "${RED}[FAIL] Validation failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo ""
    echo "Please fix the errors before building the Docker image."
    exit 1
fi
