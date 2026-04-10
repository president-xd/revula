#!/usr/bin/env bash
set -euo pipefail

COAUTHOR="Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"

commit_file() {
    local file="$1"
    local message="$2"
    git add "$file"
    git commit -m "$message" -m "$COAUTHOR"
}

commit_file "pyproject.toml" \
    "Add semgrep and quark-engine to Android optional dependencies"

commit_file "requirements.txt" \
    "Add semgrep and quark-engine to optional requirements"

commit_file "scripts/install/install_verify.sh" \
    "Use canonical YARA rules path with legacy fallback in install verifier"

commit_file "src/revula/tools/dynamic/coverage.py" \
    "Validate coverage input and output paths against security allowlist"

commit_file "src/revula/tools/static/capa_scan.py" \
    "Validate custom CAPA rules directory path before execution"

commit_file "src/revula/tools/static/yara_scan.py" \
    "Harden YARA rules path handling and support legacy community dir"

commit_file "src/revula/tools/unpacking/unpack.py" \
    "Validate unpack and rebuild output paths against allowed directories"

commit_file "tests/test_core.py" \
    "Add core tests for security env parsing and argument redaction"

commit_file "did.sh" \
    "Refresh per-file commit script and messages for current changes"
