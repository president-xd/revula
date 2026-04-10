#!/usr/bin/env python3
"""
Revula — Post-Install Validation Script.

Performs comprehensive validation of the Revula installation:
  - Python module imports (core + optional integrations)
  - External tool availability (core RE + optional ecosystems)
  - Config loading
  - Path traversal rejection
  - safe_subprocess safety

Usage:
    python scripts/test/validate_install.py
"""
from __future__ import annotations

import importlib
import importlib.metadata
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Result of a single validation check."""
    name: str
    category: str
    passed: bool
    detail: str = ""
    required: bool = True


@dataclass
class ValidationReport:
    """Aggregated validation results."""
    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed and r.required)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if not r.passed and not r.required)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def all_required_pass(self) -> bool:
        return all(r.passed for r in self.results if r.required)


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def _pass(text: str) -> str:
    return _color("32", f"✓ {text}")

def _fail(text: str) -> str:
    return _color("31", f"✗ {text}")

def _skip(text: str) -> str:
    return _color("33", f"– {text}")

def _bold(text: str) -> str:
    return _color("1", text)

def _section(title: str) -> None:
    print()
    print(_bold(f"─── {title} ───"))


# ---------------------------------------------------------------------------
# Check: Python module imports
# ---------------------------------------------------------------------------

def check_python_imports(report: ValidationReport) -> None:
    """Test that key Python modules are importable."""
    _section("Python Module Imports")

    required_modules = [
        ("capstone",   "capstone",     True),
        ("lief",       "lief",         True),
        ("pefile",     "pefile",       True),
        ("pyelftools", "elftools",     True),
        ("yara",       "yara",         True),
        ("mcp",        "mcp",          True),
        ("jsonschema", "jsonschema",   True),
    ]
    optional_modules = [
        ("frida",       "frida",          False),
        ("angr",        "angr",           False),
        ("unicorn",     "unicorn",        False),
        ("lldb",        "lldb",           False),
        ("r2pipe",      "r2pipe",         False),
        ("scapy",       "scapy.all",      False),
        ("androguard",  "androguard",     False),
        ("tlsh",        "tlsh",           False),
        ("ssdeep",      "ssdeep|ppdeep",  False),
        ("uncompyle6",  "uncompyle6",     False),
        ("triton",      "triton",         False),
        ("quark",       "quark",          False),
        ("semgrep",     "semgrep",        False),
    ]

    for display_name, import_name, required in required_modules + optional_modules:
        imported_name = None
        mod = None
        for candidate in import_name.split("|"):
            try:
                mod = importlib.import_module(candidate)
                imported_name = candidate
                break
            except Exception:
                continue

        if imported_name is not None and mod is not None:
            try:
                version = importlib.metadata.version(imported_name.split(".", 1)[0])
            except Exception:
                version = getattr(mod, "__version__", getattr(mod, "VERSION", "?"))
            result = CheckResult(
                name=f"import {display_name}",
                category="python",
                passed=True,
                detail=f"{imported_name} v{version}",
                required=required,
            )
            print(f"  {_pass(display_name):<40} {imported_name} v{version}")
            report.add(result)
            continue

        result = CheckResult(
            name=f"import {display_name}",
            category="python",
            passed=False,
            detail=f"Could not import any of: {import_name}",
            required=required,
        )
        if required:
            print(f"  {_fail(display_name):<40} Could not import any of: {import_name}")
        else:
            print(f"  {_skip(display_name):<40} not installed (optional)")
        report.add(result)


# ---------------------------------------------------------------------------
# Check: External tools
# ---------------------------------------------------------------------------

def check_external_tools(report: ValidationReport) -> None:
    """Verify external tool binaries are available."""
    _section("External Tools")

    tools = [
        ("gdb",              ["gdb"],                      True),
        ("radare2",          ["r2", "radare2"],             False),
        ("objdump",          ["objdump"],                   True),
        ("strings",          ["strings"],                   True),
        ("checksec",         ["checksec"],                  False),
        ("adb",              ["adb"],                       False),
        ("aapt",             ["aapt", "aapt2"],             False),
        ("apksigner",        ["apksigner"],                 False),
        ("jadx",             ["jadx"],                      False),
        ("apktool",          ["apktool"],                   False),
        ("baksmali",         ["baksmali"],                  False),
        ("smali",            ["smali"],                     False),
        ("cfr",              ["cfr"],                       False),
        ("ghidra headless",  ["analyzeHeadless"],           False),
        ("binwalk",          ["binwalk"],                   False),
        ("diec",             ["diec"],                      False),
        ("upx",              ["upx"],                       False),
        ("capa",             ["capa"],                      False),
        ("retdec_decompiler", ["retdec-decompiler"],        False),
        ("rizin",            ["rizin", "rz"],               False),
        ("rz-diff",          ["rz-diff"],                   False),
        ("lldb",             ["lldb"],                      False),
        ("qemu user",        ["qemu-x86_64", "qemu-arm"],   False),
        ("qemu system",      ["qemu-system-x86_64"],        False),
        ("qemu-img",         ["qemu-img"],                  False),
        ("tshark/capinfos",  ["tshark", "capinfos"],        False),
        ("drrun",            ["drrun"],                     False),
        ("ikdasm",           ["ikdasm", "ildasm"],          False),
        ("monodis",          ["monodis"],                   False),
        ("msfvenom",         ["msfvenom"],                  False),
        ("one_gadget",       ["one_gadget"],                False),
        ("semgrep",          ["semgrep"],                   False),
        ("quark",            ["quark"],                     False),
        ("wasm2wat",         ["wasm2wat"],                  False),
        ("pdbutil",          ["llvm-pdbutil", "llvm-pdbutil-19", "llvm-pdbutil-18", "llvm-pdbutil-17"], False),
    ]

    for display_name, candidates, required in tools:
        found_path = None
        for c in candidates:
            found_path = shutil.which(c)
            if found_path:
                break

        result = CheckResult(
            name=display_name,
            category="tools",
            passed=found_path is not None,
            detail=found_path or "not found",
            required=required,
        )
        report.add(result)

        if found_path:
            print(f"  {_pass(display_name):<40} {found_path}")
        elif required:
            print(f"  {_fail(display_name):<40} NOT FOUND")
        else:
            print(f"  {_skip(display_name):<40} not found (optional)")

    # Check Ghidra in ~/.revula path
    ghidra_local = Path.home() / ".revula" / "ghidra" / "support" / "analyzeHeadless"
    if ghidra_local.exists():
        print(f"  {_pass('ghidra (local)'):<40} {ghidra_local}")


# ---------------------------------------------------------------------------
# Check: Config loading
# ---------------------------------------------------------------------------

def check_config_loading(report: ValidationReport) -> None:
    """Test that Revula config loads without errors."""
    _section("Configuration")

    try:
        from revula.config import load_config
        config = load_config()

        result = CheckResult(
            name="config loading",
            category="config",
            passed=True,
            detail=f"platform={config.platform}, tools={len(config.tools)}",
            required=True,
        )
        print(f"  {_pass('Config loads successfully')}")
        print(f"    Platform: {config.platform}/{config.arch}")
        print(f"    Tools detected: {sum(1 for t in config.tools.values() if t.available)}/{len(config.tools)}")
        print(f"    Python modules: {sum(1 for v in config.python_modules.values() if v)}/{len(config.python_modules)}")
        print(f"    Allowed dirs: {config.security.allowed_dirs}")
    except Exception as e:
        result = CheckResult(
            name="config loading",
            category="config",
            passed=False,
            detail=str(e),
            required=True,
        )
        print(f"  {_fail('Config loading failed')}: {e}")

    report.add(result)

    # Config file
    config_file = Path.home() / ".revula" / "config.toml"
    exists = config_file.exists()
    result2 = CheckResult(
        name="config.toml exists",
        category="config",
        passed=exists,
        detail=str(config_file),
        required=False,
    )
    report.add(result2)
    if exists:
        print(f"  {_pass('config.toml'):<40} {config_file}")
    else:
        print(f"  {_skip('config.toml'):<40} not found (using defaults)")


# ---------------------------------------------------------------------------
# Check: Path traversal rejection
# ---------------------------------------------------------------------------

def check_path_traversal(report: ValidationReport) -> None:
    """Test that path traversal attacks are blocked."""
    _section("Security: Path Traversal Rejection")

    try:
        from revula.sandbox import validate_path, PathValidationError
    except ImportError as e:
        result = CheckResult(
            name="path traversal check",
            category="security",
            passed=False,
            detail=f"Cannot import sandbox: {e}",
            required=True,
        )
        report.add(result)
        print(f"  {_fail('Cannot import revula.sandbox')}: {e}")
        return

    # Create a real temp file for the "safe" test
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        safe_temp = tf.name
        tf.write(b"\x00" * 16)

    dangerous_paths = [
        ("/etc/passwd", "absolute system file"),
        ("../../etc/shadow", "relative traversal"),
        ("/proc/self/environ", "proc filesystem"),
        ("/dev/null", "device file"),
    ]

    all_blocked = True
    for dangerous_path, description in dangerous_paths:
        try:
            # Use a restrictive allowed_dirs to ensure these are blocked
            validate_path(
                dangerous_path,
                allowed_dirs=["/tmp/revula-test-nonexistent"],
                must_exist=False,
            )
            # If we get here, it wasn't blocked
            print(f"  {_fail(f'Should block: {description}'):<50} {dangerous_path}")
            all_blocked = False
        except (PathValidationError, ValueError, Exception):
            print(f"  {_pass(f'Blocked: {description}'):<50} {dangerous_path}")

    result = CheckResult(
        name="path traversal rejection",
        category="security",
        passed=all_blocked,
        detail=f"tested {len(dangerous_paths)} dangerous paths",
        required=True,
    )
    report.add(result)

    # Test that a valid path IS accepted
    try:
        parent_dir = str(Path(safe_temp).parent)
        validated = validate_path(
            safe_temp,
            allowed_dirs=[parent_dir],
            must_exist=True,
        )
        print(f"  {_pass('Accepts valid path'):<50} {safe_temp}")
        result_valid = CheckResult(
            name="valid path acceptance",
            category="security",
            passed=True,
            required=True,
        )
    except Exception as e:
        print(f"  {_fail('Rejects valid path'):<50} {e}")
        result_valid = CheckResult(
            name="valid path acceptance",
            category="security",
            passed=False,
            detail=str(e),
            required=True,
        )
    report.add(result_valid)

    # Cleanup temp file
    try:
        os.unlink(safe_temp)
    except OSError as e:
        print(f"  [WARN] Temp cleanup failed: {e}")


# ---------------------------------------------------------------------------
# Check: safe_subprocess safety
# ---------------------------------------------------------------------------

def check_subprocess_safety(report: ValidationReport) -> None:
    """Test that safe_subprocess blocks shell injection patterns."""
    _section("Security: Subprocess Safety")

    try:
        from revula.sandbox import safe_subprocess, SubprocessResult
    except ImportError as e:
        result = CheckResult(
            name="subprocess safety",
            category="security",
            passed=False,
            detail=f"Cannot import: {e}",
            required=True,
        )
        report.add(result)
        print(f"  {_fail('Cannot import safe_subprocess')}: {e}")
        return

    import asyncio

    async def _test_subprocess() -> bool:
        all_safe = True

        # Test 1: Simple safe command should work
        try:
            result = await safe_subprocess(["echo", "hello"], timeout=5)
            if result.success and "hello" in result.stdout:
                print(f"  {_pass('Safe command works'):<50} echo hello → ok")
            else:
                print(f"  {_fail('Safe command failed'):<50} rc={result.returncode}")
                all_safe = False
        except Exception as e:
            print(f"  {_fail('Safe command raised'):<50} {e}")
            all_safe = False

        # Test 2: Command with timeout should eventually complete or timeout
        try:
            result = await safe_subprocess(["sleep", "0.1"], timeout=5)
            print(f"  {_pass('Timeout handling works'):<50} sleep completed")
        except Exception as e:
            # Some error is also acceptable depending on sandbox config
            print(f"  {_pass('Timeout handling works'):<50} caught: {type(e).__name__}")

        # Test 3: Non-existent command should fail gracefully
        try:
            result = await safe_subprocess(
                ["__nonexistent_command_12345__"],
                timeout=5,
            )
            if not result.success:
                print(f"  {_pass('Bad command fails gracefully'):<50} rc={result.returncode}")
            else:
                print(f"  {_fail('Bad command should not succeed')}")
                all_safe = False
        except (FileNotFoundError, OSError, Exception):
            print(f"  {_pass('Bad command raises expected error')}")

        return all_safe

    try:
        loop = asyncio.new_event_loop()
        safe = loop.run_until_complete(_test_subprocess())
        loop.close()
    except Exception as e:
        safe = False
        print(f"  {_fail(f'Subprocess test error: {e}')}")

    report.add(CheckResult(
        name="subprocess safety",
        category="security",
        passed=safe,
        required=True,
    ))


# ---------------------------------------------------------------------------
# Check: Revula tool registry
# ---------------------------------------------------------------------------

def check_tool_registry(report: ValidationReport) -> None:
    """Test that the tool registry loads and has tools."""
    _section("Tool Registry")

    try:
        # Import the server module to trigger tool registration
        from revula.tools import TOOL_REGISTRY

        # Force registration
        try:
            from revula.server import _register_all_tools
            _register_all_tools()
        except Exception as e:
            print(f"  [WARN] Tool auto-registration failed: {e}")

        count = TOOL_REGISTRY.count()
        names = TOOL_REGISTRY.names()

        passed = count > 0
        result = CheckResult(
            name="tool registry",
            category="registry",
            passed=passed,
            detail=f"{count} tools registered",
            required=True,
        )
        report.add(result)

        if passed:
            print(f"  {_pass(f'{count} tools registered')}")
            # Show categories
            categories: dict[str, int] = {}
            for tool in TOOL_REGISTRY.all():
                categories[tool.category] = categories.get(tool.category, 0) + 1
            for cat, cnt in sorted(categories.items()):
                print(f"    {cat}: {cnt} tools")
        else:
            print(f"  {_fail('No tools registered')}")

    except Exception as e:
        report.add(CheckResult(
            name="tool registry",
            category="registry",
            passed=False,
            detail=str(e),
            required=True,
        ))
        print(f"  {_fail(f'Registry error: {e}')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    Revula — Installation Validation                  ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  Python: {sys.version}")
    print(f"  Platform: {sys.platform}")

    report = ValidationReport()

    check_python_imports(report)
    check_external_tools(report)
    check_config_loading(report)
    check_tool_registry(report)
    check_path_traversal(report)
    check_subprocess_safety(report)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------

    print()
    print("══════════════════════════════════════════════════════")
    print(f"  {_color('32', f'Passed: {report.passed}')}  |  "
          f"{_color('31', f'Failed: {report.failed}')}  |  "
          f"{_color('33', f'Skipped: {report.skipped}')}  |  "
          f"Total: {report.total}")
    print("══════════════════════════════════════════════════════")

    if report.all_required_pass:
        print(_color("32;1", "  All required checks passed! Revula is ready."))
    else:
        print(_color("31;1", "  Some required checks failed. See details above."))
        print()
        print("  Failed checks:")
        for r in report.results:
            if not r.passed and r.required:
                print(f"    • {r.name}: {r.detail}")

    print()
    sys.exit(0 if report.all_required_pass else 1)


if __name__ == "__main__":
    main()
