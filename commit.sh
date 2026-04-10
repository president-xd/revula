#!/usr/bin/env bash
set -euo pipefail

# Run these commands one block at a time to create separate commits per file.
TRAILER="Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"

git add Dockerfile
git commit -m "docker: install missing toolchain components and fix retdec binary path" -m "$TRAILER"

git add scripts/install/install_all.sh
git commit -m "install: add missing optional tool installers and align with docker coverage" -m "$TRAILER"

git add scripts/install/install_verify.sh
git commit -m "install-verify: check newly added external tool binaries" -m "$TRAILER"

git add scripts/test/validate_install.py
git commit -m "validate-install: include added tool availability checks" -m "$TRAILER"

git add src/revula/config.py
git commit -m "config: extend tool env overrides and install hints for added tools" -m "$TRAILER"

git add requirements.txt
git commit -m "deps: add exploit helper python dependencies" -m "$TRAILER"

git add pyproject.toml
git commit -m "deps: expose exploit extras and include them in full install set" -m "$TRAILER"

git add README.md
git commit -m "docs: sync docker/install guidance with actual tool provisioning" -m "$TRAILER"

git add commit.sh
git commit -m "chore: add per-file commit helper script" -m "$TRAILER"
