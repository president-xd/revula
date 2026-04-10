#!/usr/bin/env python3
"""
Revula — Interactive config.toml Generator.

Walks the user through an interactive setup to create ~/.revula/config.toml
with analysis directories, tool paths, and security settings.

Usage:
    python scripts/setup/setup_config_toml.py
"""
from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def bold(text: str) -> str:
    return _color("1", text)

def green(text: str) -> str:
    return _color("32", text)

def yellow(text: str) -> str:
    return _color("33", text)

def cyan(text: str) -> str:
    return _color("36", text)


CONFIG_DIR = Path.home() / ".revula"
CONFIG_FILE = CONFIG_DIR / "config.toml"

# Known tools to offer path configuration
TOOL_ENTRIES: list[tuple[str, str, list[str]]] = [
    # (config_key, display_name, binary_candidates)
    ("ghidra_headless.path", "Ghidra analyzeHeadless", ["analyzeHeadless"]),
    ("radare2.path",         "Radare2 (r2)",           ["r2", "radare2"]),
    ("rizin.path",           "Rizin",                   ["rizin", "rz"]),
    ("gdb.path",             "GDB",                     ["gdb"]),
    ("lldb.path",            "LLDB",                    ["lldb"]),
    ("adb.path",             "ADB",                     ["adb"]),
    ("java.path",            "Java/JDK",                ["java", "javap"]),
    ("jadx.path",            "JADX",                    ["jadx"]),
    ("apktool.path",         "Apktool",                 ["apktool"]),
    ("semgrep.path",         "Semgrep",                 ["semgrep"]),
    ("quark.path",           "Quark",                   ["quark"]),
    ("capa.path",            "capa",                    ["capa"]),
    ("floss.path",           "FLOSS",                   ["floss"]),
    ("upx.path",             "UPX",                     ["upx"]),
]


def prompt(question: str, default: str = "") -> str:
    """Prompt the user with an optional default value."""
    suffix = f" [{default}]" if default else ""
    answer = input(f"  {cyan('?')} {question}{suffix}: ").strip()
    return answer if answer else default


def prompt_yn(question: str, default: bool = True) -> bool:
    """Prompt for yes/no."""
    hint = "Y/n" if default else "y/N"
    answer = input(f"  {cyan('?')} {question} [{hint}]: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def auto_detect_path(candidates: list[str]) -> str:
    """Try to find a binary in PATH."""
    for c in candidates:
        found = shutil.which(c)
        if found:
            return found
    return ""


# ---------------------------------------------------------------------------
# Interactive sections
# ---------------------------------------------------------------------------

def section_allowed_dirs() -> list[str]:
    """Ask for allowed analysis directories."""
    print()
    print(bold("─── Allowed Analysis Directories ───"))
    print("  Revula restricts file access to specific directories for security.")
    print("  Enter directories where your samples / binaries are stored.")
    print("  Press Enter on an empty line when done.")
    print()

    dirs: list[str] = []
    # Offer sensible defaults
    home = str(Path.home())
    defaults = [
        os.path.join(home, "samples"),
        os.path.join(home, "malware"),
        os.path.join(home, "ctf"),
        "/tmp",
    ]

    for d in defaults:
        if prompt_yn(f"Allow {d}?", default=Path(d).is_dir()):
            dirs.append(d)

    while True:
        extra = prompt("Additional directory (empty to finish)")
        if not extra:
            break
        resolved = str(Path(extra).expanduser().resolve())
        dirs.append(resolved)
        print(f"    Added: {resolved}")

    if not dirs:
        fallback = str(Path.home())
        print(f"  {yellow('No directories specified — defaulting to')} {fallback}")
        dirs = [fallback]

    return dirs


def section_tool_paths() -> dict[str, str]:
    """Auto-detect and optionally override tool paths."""
    print()
    print(bold("─── Tool Paths ───"))
    print("  Revula will auto-detect tools in PATH. Override specific paths here.")
    print()

    paths: dict[str, str] = {}

    for config_key, display_name, candidates in TOOL_ENTRIES:
        detected = auto_detect_path(candidates)
        if detected:
            print(f"  {green('✓')} {display_name}: {detected}")
            override = prompt(f"  Override path for {display_name}? (Enter to keep)")
            if override:
                paths[config_key] = override
            else:
                paths[config_key] = detected
        else:
            print(f"  {yellow('–')} {display_name}: not found")
            manual = prompt(f"  Path to {display_name}? (Enter to skip)")
            if manual:
                paths[config_key] = manual

    return paths


def section_security() -> dict[str, int]:
    """Configure security limits."""
    print()
    print(bold("─── Security Settings ───"))
    print()

    settings: dict[str, int] = {}

    val = prompt("Max memory per subprocess (MB)", "512")
    try:
        settings["max_memory_mb"] = int(val)
    except ValueError:
        settings["max_memory_mb"] = 512

    val = prompt("Default command timeout (seconds)", "60")
    try:
        settings["default_timeout"] = int(val)
    except ValueError:
        settings["default_timeout"] = 60

    val = prompt("Max command timeout (seconds)", "600")
    try:
        settings["max_timeout"] = int(val)
    except ValueError:
        settings["max_timeout"] = 600

    return settings


# ---------------------------------------------------------------------------
# TOML generation (manual — no external deps needed)
# ---------------------------------------------------------------------------

def generate_toml(
    allowed_dirs: list[str],
    tool_paths: dict[str, str],
    security: dict[str, int],
) -> str:
    """Generate config.toml content."""
    lines: list[str] = [
        "# Revula Configuration",
        f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "#",
        "# Docs: https://github.com/president-xd/revula#configuration",
        "",
        "[security]",
    ]

    # Allowed dirs
    dirs_str = ", ".join(f'"{d}"' for d in allowed_dirs)
    lines.append(f"allowed_dirs = [{dirs_str}]")

    for key, val in security.items():
        lines.append(f"{key} = {val}")

    lines.append("")

    # Group tool paths by top-level section
    sections: dict[str, list[tuple[str, str]]] = {}
    for dotpath, value in tool_paths.items():
        parts = dotpath.split(".")
        if len(parts) == 2:
            section, key = parts
        else:
            section = parts[0]
            key = ".".join(parts[1:])
        sections.setdefault(section, []).append((key, value))

    for section, entries in sorted(sections.items()):
        lines.append(f"[tools.{section}]")
        for key, value in entries:
            lines.append(f'{key} = "{value}"')
        lines.append("")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    Revula — Interactive Configuration Setup          ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  Config will be saved to: {cyan(str(CONFIG_FILE))}")

    # Check for existing config
    if CONFIG_FILE.exists():
        print()
        print(f"  {yellow('An existing config.toml was found.')}")
        if not prompt_yn("Overwrite it?", default=False):
            print("  Aborted.")
            sys.exit(0)
        # Backup
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = CONFIG_FILE.with_name(f"config.{ts}.bak.toml")
        shutil.copy2(CONFIG_FILE, backup)
        print(f"  Backed up to: {backup}")

    # Interactive sections
    allowed_dirs = section_allowed_dirs()
    tool_paths = section_tool_paths()
    security = section_security()

    # Generate
    toml_content = generate_toml(allowed_dirs, tool_paths, security)

    print()
    print(bold("─── Preview ───"))
    print()
    for line in toml_content.splitlines():
        print(f"  {line}")
    print()

    if prompt_yn("Write this configuration?", default=True):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(toml_content, encoding="utf-8")
        print()
        print(f"  {green('✓')} Configuration saved to {CONFIG_FILE}")
    else:
        print("  Aborted.")
        sys.exit(0)

    print()
    print("  Next steps:")
    print(f"    • Edit manually: {cyan(str(CONFIG_FILE))}")
    print("    • Test: revula  (server will load the new config)")
    print()


if __name__ == "__main__":
    main()
