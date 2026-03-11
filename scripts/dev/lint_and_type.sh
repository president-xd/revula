#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Revula — Lint & Type Check
#
# Runs ruff (lint + format check) and mypy in one command.
# Exits non-zero if any check fails.
#
# Usage:
#   ./lint_and_type.sh           # check only
#   ./lint_and_type.sh --fix     # auto-fix ruff issues
# =============================================================================

FLAG_FIX=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix)  FLAG_FIX=true ;;
        --help|-h)
            echo "Usage: $0 [--fix] [--help]"
            echo "  --fix    Auto-fix ruff lint and format issues"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' BLUE='' BOLD='' NC=''
fi

step() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
pass() { echo -e "${GREEN}  ✓ $*${NC}"; }
fail() { echo -e "${RED}  ✗ $*${NC}"; }

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BOLD}Revula — Lint & Type Check${NC}"
echo "  Root: ${PROJECT_ROOT}"
echo ""

EXIT_CODE=0

# ---------------------------------------------------------------------------
# 1. Ruff lint
# ---------------------------------------------------------------------------

if [[ "$FLAG_FIX" == true ]]; then
    step "ruff check --fix"
    python3 -m ruff check --fix src/ tests/ && pass "ruff lint (fixed)" || { fail "ruff lint"; EXIT_CODE=1; }
else
    step "ruff check"
    python3 -m ruff check src/ tests/ && pass "ruff lint" || { fail "ruff lint"; EXIT_CODE=1; }
fi

# ---------------------------------------------------------------------------
# 2. Ruff format
# ---------------------------------------------------------------------------

if [[ "$FLAG_FIX" == true ]]; then
    step "ruff format"
    python3 -m ruff format src/ tests/ && pass "ruff format (applied)" || { fail "ruff format"; EXIT_CODE=1; }
else
    step "ruff format --check"
    python3 -m ruff format --check src/ tests/ && pass "ruff format" || { fail "ruff format"; EXIT_CODE=1; }
fi

# ---------------------------------------------------------------------------
# 3. mypy
# ---------------------------------------------------------------------------

step "mypy (strict)"
python3 -m mypy src/revula/ --ignore-missing-imports && pass "mypy" || { fail "mypy"; EXIT_CODE=1; }

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
if [[ "$EXIT_CODE" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All checks passed!${NC}"
else
    echo -e "${RED}${BOLD}Some checks failed!${NC}"
fi

exit $EXIT_CODE
