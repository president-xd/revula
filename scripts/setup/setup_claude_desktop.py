#!/usr/bin/env python3
"""
Revula — Claude Desktop Configuration Generator.

Auto-generates or updates the claude_desktop_config.json with the
correct MCP server entry for revula. Detects OS, finds the revula
command, merges into existing config, and backs up before overwriting.

Usage:
    python scripts/setup/setup_claude_desktop.py
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def info(msg: str) -> None:
    print(_color("34", "[INFO]") + f"  {msg}")

def success(msg: str) -> None:
    print(_color("32", "[  OK]") + f"  {msg}")

def warn(msg: str) -> None:
    print(_color("33", "[WARN]") + f"  {msg}")

def error(msg: str) -> None:
    print(_color("31", "[ERR!]") + f"  {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Detect Claude Desktop config path
# ---------------------------------------------------------------------------

def get_config_path() -> Path:
    """Return the platform-specific Claude Desktop config.json path."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Linux":
        # XDG_CONFIG_HOME or fallback
        xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        return Path(xdg) / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    else:
        warn(f"Unknown OS '{system}', assuming Linux-like path.")
        return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


# ---------------------------------------------------------------------------
# Detect the best way to run revula
# ---------------------------------------------------------------------------

def find_remcp_command() -> dict:
    """
    Detect the best available command to run revula.

    Returns the MCP server config dict with 'command' and 'args'.
    Checks in order:
      1. uvx (if uv is installed)
      2. revula command in PATH
      3. python -m revula.server
    """
    # 1. Check for uvx
    if shutil.which("uvx"):
        info("Found uvx — will use 'uvx revula' for zero-install startup.")
        return {
            "command": "uvx",
            "args": ["revula"],
        }

    # 2. Check for revula in PATH
    remcp_path = shutil.which("revula")
    if remcp_path:
        info(f"Found revula in PATH: {remcp_path}")
        return {
            "command": remcp_path,
            "args": [],
        }

    # 3. Fallback: python -m revula.server
    python_path = sys.executable
    # Verify the module is importable
    try:
        result = subprocess.run(
            [python_path, "-c", "import revula"],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            info(f"Using Python module mode: {python_path} -m revula.server")
            return {
                "command": python_path,
                "args": ["-m", "revula.server"],
            }
    except Exception as e:
        warn(f"Python module probe failed: {e}")

    warn("Could not auto-detect revula. Using default 'revula' command.")
    return {
        "command": "revula",
        "args": [],
    }


# ---------------------------------------------------------------------------
# Build MCP server entry
# ---------------------------------------------------------------------------

def build_server_entry() -> dict:
    """Build the revula server entry for Claude Desktop config."""
    cmd_config = find_remcp_command()
    entry: dict = {
        "command": cmd_config["command"],
    }
    if cmd_config["args"]:
        entry["args"] = cmd_config["args"]

    # Optional: add env overrides if config.toml exists
    config_toml = Path.home() / ".revula" / "config.toml"
    if config_toml.exists():
        entry.setdefault("env", {})
        # No extra env needed — revula reads config.toml natively
        info(f"Config file detected: {config_toml}")

    return entry


# ---------------------------------------------------------------------------
# Merge into existing config
# ---------------------------------------------------------------------------

def merge_config(config_path: Path, server_entry: dict) -> dict:
    """Load existing config, merge revula server entry, return new config."""
    existing: dict = {}
    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
            info(f"Loaded existing config from {config_path}")
        except (json.JSONDecodeError, OSError) as e:
            warn(f"Could not parse existing config: {e}")
            existing = {}

    if not isinstance(existing, dict):
        warn("Existing config is not a JSON object, starting fresh.")
        existing = {}

    # Ensure mcpServers key exists
    if "mcpServers" not in existing:
        existing["mcpServers"] = {}

    # Check if revula is already configured
    if "revula" in existing["mcpServers"]:
        warn("revula entry already exists in config. It will be updated.")

    existing["mcpServers"]["revula"] = server_entry
    return existing


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

def backup_config(config_path: Path) -> Path | None:
    """Create a timestamped backup of the config file if it exists."""
    if not config_path.exists():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_name(f"claude_desktop_config.{timestamp}.bak.json")
    shutil.copy2(config_path, backup_path)
    success(f"Backed up existing config to {backup_path}")
    return backup_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   Revula — Claude Desktop Configuration Setup        ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    config_path = get_config_path()
    info(f"Config path: {config_path}")
    print()

    # Detect command
    server_entry = build_server_entry()
    print()

    # Backup existing
    backup_config(config_path)

    # Merge
    merged = merge_config(config_path, server_entry)
    print()

    # Write
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    success(f"Config written to {config_path}")
    print()

    # Show result
    info("Claude Desktop MCP configuration:")
    print(json.dumps({"mcpServers": {"revula": server_entry}}, indent=2))
    print()

    info("Restart Claude Desktop to pick up the new configuration.")
    print()


if __name__ == "__main__":
    main()
