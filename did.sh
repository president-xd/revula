#!/usr/bin/env bash
set -euo pipefail

git add scripts/docker/full_audit.sh
git commit -m "Harden full Docker audit flow with entrypoint overrides, smoke env wiring, and stable summary generation"

git add Dockerfile
git commit -m "Fix Docker build sources and integrity pins for Ghidra and smali dependencies"

git add did.sh
git commit -m "Refresh per-file commit helper entries for current Docker audit and Dockerfile changes"
