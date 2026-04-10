#!/usr/bin/env bash
set -euo pipefail

git add scripts/install/install_all.sh
git commit -m "Install aapt and smali/baksmali in Android tooling setup"

git add scripts/install/install_verify.sh
git commit -m "Verify aapt, smali, and baksmali in install verification"

git add Dockerfile
git commit -m "Add wabt and smali/baksmali tooling to Docker build/runtime image"

git add did.sh
git commit -m "Update did.sh with per-file commit commands for current changes"
