#!/usr/bin/env python3
"""
Revula — Universal IDE / MCP Client Configuration Generator.

Generates or updates MCP server configuration for every supported client:
  - Claude Desktop
  - Claude Code (CLI)
  - VS Code (GitHub Copilot)
  - Cursor
  - Windsurf (Codeium)
  - Continue.dev
  - Zed
  - JetBrains (AI Assistant plugin)

Usage:
    python scripts/setup/setup_ide.py              # Interactive — pick a client
    python scripts/setup/setup_ide.py --all         # Configure all detected clients
    python scripts/setup/setup_ide.py --client vscode
    python scripts/setup/setup_ide.py --client cursor
    python scripts/setup/setup_ide.py --client claude-desktop
    python scripts/setup/setup_ide.py --print-only  # Print configs without writing
"""
from __future__ import annotations

import argparse
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

def header(msg: str) -> None:
    print(_color("1;36", f"\n{'─' * 60}"))
    print(_color("1;36", f"  {msg}"))
    print(_color("1;36", f"{'─' * 60}\n"))


# ---------------------------------------------------------------------------
# Detect the best way to run revula
# ---------------------------------------------------------------------------

def detect_revula_command() -> dict:
    """
    Detect the best available command to run revula.

    Returns a dict with 'command' and 'args'.
    Checks in order:
      1. revula command in PATH (pip install -e . / pipx)
      2. uvx (zero-install via uv)
      3. python -m revula.server (fallback)
    """
    # 1. Check for revula in PATH
    revula_path = shutil.which("revula")
    if revula_path:
        info(f"Found revula in PATH: {revula_path}")
        return {"command": revula_path, "args": []}

    # 2. Check for uvx
    if shutil.which("uvx"):
        info("Found uvx — will use 'uvx revula' for zero-install startup.")
        return {"command": "uvx", "args": ["revula"]}

    # 3. Fallback: python -m revula.server
    python_path = sys.executable
    try:
        result = subprocess.run(
            [python_path, "-c", "import revula"],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            info(f"Using Python module mode: {python_path} -m revula.server")
            return {"command": python_path, "args": ["-m", "revula.server"]}
    except Exception as e:
        warn(f"Python module probe failed: {e}")

    warn("Could not auto-detect revula. Using default 'revula' command.")
    warn("Make sure revula is installed: pip install -e .")
    return {"command": "revula", "args": []}


# ---------------------------------------------------------------------------
# Client definitions
# ---------------------------------------------------------------------------

SYSTEM = platform.system()

CLIENT_REGISTRY: dict[str, dict] = {}


def _register_client(name: str, display: str, *, config_paths: list[Path],
                     config_format: str, merge_key: str | None = None,
                     notes: str = "") -> None:
    """Register a client into CLIENT_REGISTRY."""
    CLIENT_REGISTRY[name] = {
        "display": display,
        "config_paths": config_paths,
        "config_format": config_format,
        "merge_key": merge_key,
        "notes": notes,
    }


def _home() -> Path:
    return Path.home()


def _xdg_config() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))


# --- Claude Desktop ---
def _claude_desktop_paths() -> list[Path]:
    if SYSTEM == "Darwin":
        return [_home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"]
    elif SYSTEM == "Windows":
        appdata = os.environ.get("APPDATA", str(_home() / "AppData" / "Roaming"))
        return [Path(appdata) / "Claude" / "claude_desktop_config.json"]
    else:
        return [_xdg_config() / "Claude" / "claude_desktop_config.json"]


_register_client(
    "claude-desktop", "Claude Desktop",
    config_paths=_claude_desktop_paths(),
    config_format="json",
    merge_key="mcpServers",
    notes="Restart Claude Desktop after editing.",
)

# --- Claude Code (CLI) ---
_register_client(
    "claude-code", "Claude Code (CLI)",
    config_paths=[_home() / ".claude" / "claude_code_config.json"],
    config_format="json",
    merge_key="mcpServers",
    notes="Run: claude mcp add revula -- revula  (or edit the config file manually).",
)

# --- VS Code (Copilot) ---
_register_client(
    "vscode", "VS Code (GitHub Copilot)",
    config_paths=[
        # User-level settings (global)
        _home() / ".vscode" / "mcp.json" if SYSTEM != "Darwin"
        else _home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",
    ],
    config_format="json",
    merge_key="mcp.servers" if SYSTEM == "Darwin" else "servers",
    notes=(
        "VS Code reads MCP config from .vscode/mcp.json (workspace) or User settings.json.\n"
        "    A workspace-level .vscode/mcp.json is already included in this repo.\n"
        "    For global config, add to User settings.json under \"mcp.servers\"."
    ),
)

# --- Cursor ---
def _cursor_paths() -> list[Path]:
    paths = [_home() / ".cursor" / "mcp.json"]
    return paths


_register_client(
    "cursor", "Cursor",
    config_paths=_cursor_paths(),
    config_format="json",
    merge_key="mcpServers",
    notes="Restart Cursor after editing.",
)

# --- Windsurf (Codeium) ---
def _windsurf_paths() -> list[Path]:
    return [_home() / ".codeium" / "windsurf" / "mcp_config.json"]


_register_client(
    "windsurf", "Windsurf (Codeium)",
    config_paths=_windsurf_paths(),
    config_format="json",
    merge_key="mcpServers",
    notes="Restart Windsurf after editing.",
)

# --- Zed ---
def _zed_paths() -> list[Path]:
    if SYSTEM == "Darwin":
        return [_home() / ".config" / "zed" / "settings.json"]
    return [_xdg_config() / "zed" / "settings.json"]


_register_client(
    "zed", "Zed",
    config_paths=_zed_paths(),
    config_format="json",
    merge_key="context_servers",
    notes="Zed uses 'context_servers' in settings.json.",
)


# ---------------------------------------------------------------------------
# Config generation per client
# ---------------------------------------------------------------------------

def build_entry_for_client(client_name: str, cmd: dict) -> dict:
    """Build the MCP server entry in the format expected by a specific client."""
    command = cmd["command"]
    args = cmd["args"]

    if client_name == "zed":
        # Zed uses a different schema
        return {
            "revula": {
                "command": command,
                "args": args,
            }
        }

    if client_name == "vscode":
        # VS Code .vscode/mcp.json format
        entry: dict = {"command": command}
        if args:
            entry["args"] = args
        entry["env"] = {}
        return {"revula": entry}

    # Standard mcpServers format (Claude Desktop, Cursor, Windsurf, Continue, Claude Code)
    entry = {"command": command}
    if args:
        entry["args"] = args
    return {"revula": entry}


def generate_config_snippet(client_name: str, cmd: dict) -> str:
    """Return a formatted JSON snippet for display."""
    client = CLIENT_REGISTRY[client_name]
    entry = build_entry_for_client(client_name, cmd)
    merge_key = client["merge_key"]

    if merge_key:
        wrapped = {merge_key: entry}
    else:
        wrapped = entry

    return json.dumps(wrapped, indent=2)


# ---------------------------------------------------------------------------
# Write config
# ---------------------------------------------------------------------------

def write_config(client_name: str, cmd: dict, *, dry_run: bool = False) -> bool:
    """Write or merge revula config into the client's config file."""
    client = CLIENT_REGISTRY[client_name]
    entry = build_entry_for_client(client_name, cmd)
    merge_key = client["merge_key"]

    config_path = client["config_paths"][0]

    if dry_run:
        info(f"[DRY RUN] Would write to: {config_path}")
        print(generate_config_snippet(client_name, cmd))
        return True

    # Load existing config
    existing: dict = {}
    if config_path.exists():
        try:
            raw = config_path.read_text(encoding="utf-8")
            existing = json.loads(raw)
            info(f"Loaded existing config: {config_path}")
        except (json.JSONDecodeError, OSError) as e:
            warn(f"Could not parse existing config ({e}), starting fresh.")
            existing = {}

    # Backup
    if config_path.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = config_path.with_name(f"{config_path.stem}.{timestamp}.bak.json")
        shutil.copy2(config_path, backup)
        success(f"Backed up to {backup}")

    # Merge
    if merge_key:
        # Handle nested keys like "mcp.servers"
        keys = merge_key.split(".")
        target = existing
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
        final_key = keys[-1]
        if final_key not in target or not isinstance(target[final_key], dict):
            target[final_key] = {}
        target[final_key].update(entry)
    else:
        existing.update(entry)

    # Write
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    success(f"Config written to {config_path}")

    if client["notes"]:
        info(client["notes"])

    return True


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def interactive_menu(cmd: dict) -> None:
    """Present a menu to pick which client(s) to configure."""
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║     Revula — IDE / MCP Client Configuration         ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    info(f"Detected command: {cmd['command']} {' '.join(cmd['args'])}")
    print()

    clients = list(CLIENT_REGISTRY.keys())
    print("  Available clients:")
    print()
    for i, name in enumerate(clients, 1):
        client = CLIENT_REGISTRY[name]
        path = client["config_paths"][0]
        exists = "✓ config exists" if path.exists() else "✗ not configured"
        print(f"    {i}. {client['display']:30s}  [{exists}]")

    print(f"    {len(clients) + 1}. Configure ALL")
    print(f"    {len(clients) + 2}. Print all configs (no write)")
    print(f"     0. Exit")
    print()

    try:
        choice = input("  Select (number): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if choice == "0":
        return

    if choice == str(len(clients) + 2):
        # Print only
        for name in clients:
            header(CLIENT_REGISTRY[name]["display"])
            print(generate_config_snippet(name, cmd))
            if CLIENT_REGISTRY[name]["notes"]:
                print()
                info(CLIENT_REGISTRY[name]["notes"])
        return

    if choice == str(len(clients) + 1):
        # All
        for name in clients:
            header(CLIENT_REGISTRY[name]["display"])
            write_config(name, cmd)
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(clients):
            name = clients[idx]
            header(CLIENT_REGISTRY[name]["display"])
            write_config(name, cmd)
        else:
            error("Invalid selection.")
    except ValueError:
        error("Invalid input. Enter a number.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Revula — Configure MCP server for IDEs and AI clients",
    )
    p.add_argument(
        "--client", "-c",
        choices=list(CLIENT_REGISTRY.keys()),
        help="Configure a specific client",
    )
    p.add_argument(
        "--all", "-a",
        action="store_true",
        help="Configure all clients",
    )
    p.add_argument(
        "--print-only", "-p",
        action="store_true",
        help="Print config snippets without writing files",
    )
    p.add_argument(
        "--command",
        help="Override the revula command (default: auto-detect)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Detect command
    if args.command:
        parts = args.command.split()
        cmd = {"command": parts[0], "args": parts[1:]}
    else:
        cmd = detect_revula_command()

    if args.print_only:
        for name in CLIENT_REGISTRY:
            header(CLIENT_REGISTRY[name]["display"])
            print(generate_config_snippet(name, cmd))
            info(f"Config path: {CLIENT_REGISTRY[name]['config_paths'][0]}")
            if CLIENT_REGISTRY[name]["notes"]:
                info(CLIENT_REGISTRY[name]["notes"])
        return

    if args.client:
        header(CLIENT_REGISTRY[args.client]["display"])
        write_config(args.client, cmd)
        return

    if args.all:
        for name in CLIENT_REGISTRY:
            header(CLIENT_REGISTRY[name]["display"])
            write_config(name, cmd)
        return

    # Interactive
    interactive_menu(cmd)


if __name__ == "__main__":
    main()
