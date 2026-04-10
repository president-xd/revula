#!/usr/bin/env bash
set -euo pipefail

git add Dockerfile
git commit -m "Add missing RE toolchains and pip tooling to Docker image"

git add README.md
git commit -m "Remove stale overclaims and align docs with current behavior"

git add scripts/install/install_all.sh
git commit -m "Harden installer dependency flow and add ROP tooling install"

git add scripts/setup/setup_claude_desktop.py
git commit -m "Log setup probe failures in Claude Desktop integration script"

git add scripts/setup/setup_ide.py
git commit -m "Log setup probe failures in IDE integration script"

git add scripts/test/validate_install.py
git commit -m "Improve install validation diagnostics and avoid silent cleanup errors"

git add scripts/utils/download_frida_server.py
git commit -m "Improve Frida downloader fallback diagnostics and error visibility"

git add src/revula/config.py
git commit -m "Expand config probes and improve module detection diagnostics"

git add src/revula/sandbox.py
git commit -m "Enforce fail-closed allowlist loading and security limit resolution"

git add src/revula/scripts/DecompileFunction.py
git commit -m "Replace silent exception swallowing in Ghidra decompile script"

git add src/revula/server.py
git commit -m "Keep error-result cache parsing explicit without silent fallback"

git add src/revula/tools/android/apk_parse.py
git commit -m "Improve APK parser exception handling and logging"

git add src/revula/tools/android/binary_analysis.py
git commit -m "Avoid silent decode failures in Android binary analysis"

git add src/revula/tools/android/decompile.py
git commit -m "Log decompile source read failures instead of swallowing errors"

git add src/revula/tools/android/dex_analyze.py
git commit -m "Handle dex string decode failures with explicit continue behavior"

git add src/revula/tools/android/repack.py
git commit -m "Add dependency metadata and path handling hardening for Android repack"

git add src/revula/tools/android/scanners.py
git commit -m "Add scanner dependency metadata and explicit import fallback logging"

git add src/revula/tools/binary_formats/formats.py
git commit -m "Add binary-format tool dependency metadata for preflight checks"

git add src/revula/tools/deobfuscation/deobfuscate.py
git commit -m "Replace broad exception swallowing in deobfuscation paths"

git add src/revula/tools/exploit/libc_database.py
git commit -m "Declare libc toolchain dependencies for exploit lookup handlers"

git add src/revula/tools/exploit/rop_builder.py
git commit -m "Declare ROP tool dependencies for builder handlers"

git add src/revula/tools/exploit/shellcode.py
git commit -m "Declare shellcode helper dependencies for exploit handlers"

git add src/revula/tools/firmware/firmware.py
git commit -m "Fix firmware string offset parsing and directory validation metadata"

git add src/revula/tools/malware/triage.py
git commit -m "Add malware triage dependency metadata and import diagnostics"

git add src/revula/tools/platform/gdb_enhanced.py
git commit -m "Declare GDB-enhanced helper dependencies for early preflight checks"

git add src/revula/tools/platform/qemu.py
git commit -m "Declare QEMU dependencies and validate sysroot as directory"

git add src/revula/tools/static/decompile.py
git commit -m "Log Ghidra autodetect failures instead of silent pass"

git add src/revula/tools/static/disasm.py
git commit -m "Log missing instruction group metadata instead of silent pass"

git add src/revula/tools/static/pe_elf.py
git commit -m "Declare PE/ELF tooling dependencies for static analysis handlers"

git add src/revula/tools/symbolic/symbolic.py
git commit -m "Declare symbolic execution backend dependencies for handlers"

git add tests/test_security.py
git commit -m "Add security regression coverage for fail-closed path validation"

git add tests/test_registry_coverage.py
git commit -m "Add registry coverage tests for metadata and dependency declarations"

git add tests/test_scripts_invariants.py
git commit -m "Add script and documentation invariants to prevent drift"

git add did.sh
git commit -m "Add per-file git add/commit command script for all touched files"
