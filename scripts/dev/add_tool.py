#!/usr/bin/env python3
"""
Revula — New Tool Scaffold Generator.

Creates a new tool module from a template with the correct decorator pattern,
input schema, and async handler function.

Usage:
    python scripts/dev/add_tool.py --name scan_headers --category static --description "Scan PE/ELF headers for anomalies"
    python scripts/dev/add_tool.py --name frida_hook --category dynamic --description "Set Frida hooks on functions"
"""
from __future__ import annotations

import argparse
import keyword
import re
import sys
from pathlib import Path
from textwrap import dedent


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = PROJECT_ROOT / "src" / "revula" / "tools"

VALID_CATEGORIES = [
    "static",
    "dynamic",
    "android",
    "binary_formats",
    "deobfuscation",
    "exploit",
    "firmware",
    "malware",
    "platform",
    "protocol",
    "symbolic",
    "unpacking",
    "utils",
    "antianalysis",
    "admin",
]


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

def error(msg: str) -> None:
    print(_color("31", "[ERR!]") + f"  {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_name(name: str) -> str:
    """Validate and normalize the tool name."""
    # Strip common prefixes
    name = name.removeprefix("re_")

    # Must be a valid Python identifier
    normalized = re.sub(r"[^a-z0-9_]", "_", name.lower())
    normalized = re.sub(r"_+", "_", normalized).strip("_")

    if not normalized:
        raise ValueError(f"Invalid tool name: '{name}'")
    if keyword.iskeyword(normalized):
        raise ValueError(f"Tool name '{normalized}' is a Python keyword")

    return normalized


def validate_category(category: str) -> str:
    """Validate the tool category."""
    if category not in VALID_CATEGORIES:
        raise ValueError(
            f"Invalid category '{category}'. "
            f"Valid: {', '.join(VALID_CATEGORIES)}"
        )
    return category


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

def generate_tool_module(
    tool_name: str,
    category: str,
    description: str,
) -> str:
    """Generate the complete tool module source code."""
    # Full MCP tool name with re_ prefix
    mcp_name = f"re_{tool_name}"
    # Python function name
    func_name = f"handle_{tool_name}"
    # Module docstring first line
    module_doc = f"Revula Tool — {description}"

    return dedent(f'''\
        """
        {module_doc}
        """

        from __future__ import annotations

        import logging
        from typing import Any

        from revula.sandbox import validate_binary_path
        from revula.tools import TOOL_REGISTRY, error_result, text_result

        logger = logging.getLogger(__name__)


        # ---------------------------------------------------------------------------
        # Tool registration
        # ---------------------------------------------------------------------------

        @TOOL_REGISTRY.register(
            name="{mcp_name}",
            description="{description}",
            input_schema={{
                "type": "object",
                "properties": {{
                    "file_path": {{
                        "type": "string",
                        "description": "Path to the target binary or file.",
                    }},
                    "options": {{
                        "type": "object",
                        "description": "Optional parameters for the analysis.",
                        "properties": {{}},
                        "additionalProperties": True,
                    }},
                }},
                "required": ["file_path"],
            }},
            category="{category}",
            requires_tools=[],
            requires_modules=[],
        )
        async def {func_name}(arguments: dict[str, Any]) -> list[dict[str, Any]]:
            """
            {description}

            Args:
                arguments: MCP tool arguments containing:
                    - file_path: Path to the target file
                    - options: Optional analysis parameters

            Returns:
                List of MCP content blocks with analysis results.
            """
            file_path = arguments.get("file_path", "")
            options = arguments.get("options", {{}})

            if not file_path:
                return error_result("file_path is required")

            try:
                # Validate the file path for security
                validated_path = validate_binary_path(file_path)

                # TODO: Implement analysis logic here
                result = {{
                    "tool": "{mcp_name}",
                    "file": str(validated_path),
                    "status": "not_implemented",
                    "message": "Tool '{mcp_name}' is scaffolded but not yet implemented.",
                }}

                return text_result(result)

            except Exception as e:
                logger.exception("Error in {mcp_name}")
                return error_result(f"{mcp_name} failed: {{type(e).__name__}}: {{e}}")
    ''')


def generate_init_patch(tool_name: str) -> str:
    """Generate the import line to add to the category __init__.py."""
    return f"from revula.tools.{{category}}.{tool_name} import *  # noqa: F401,F403\n"


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------

def create_tool_file(
    tool_name: str,
    category: str,
    description: str,
) -> Path:
    """Create the tool module file and update __init__.py."""
    category_dir = TOOLS_DIR / category
    tool_file = category_dir / f"{tool_name}.py"

    if tool_file.exists():
        raise FileExistsError(f"Tool file already exists: {tool_file}")

    # Ensure category directory exists with __init__.py
    category_dir.mkdir(parents=True, exist_ok=True)
    init_file = category_dir / "__init__.py"
    if not init_file.exists():
        init_file.write_text(
            f'"""Revula {category} tools."""\n',
            encoding="utf-8",
        )

    # Generate and write tool module
    source = generate_tool_module(tool_name, category, description)
    tool_file.write_text(source, encoding="utf-8")

    return tool_file


def update_server_imports(tool_name: str, category: str) -> bool:
    """
    Add the import line to server.py _register_all_tools() if not already present.

    Returns True if the import was added, False if it already existed.
    """
    server_file = PROJECT_ROOT / "src" / "revula" / "server.py"
    if not server_file.exists():
        return False

    module_path = f"revula.tools.{category}.{tool_name}"
    import_line = f'    _safe_import("{module_path}")'

    content = server_file.read_text(encoding="utf-8")

    if module_path in content:
        return False

    # Find the _register_all_tools function and add the import
    # Look for the last _safe_import in the relevant category section or at the end
    lines = content.splitlines(keepends=True)
    insert_idx = None

    # Find the last _safe_import line
    for i, line in enumerate(lines):
        if "_safe_import(" in line:
            insert_idx = i

    if insert_idx is not None:
        # Insert after the last _safe_import
        lines.insert(insert_idx + 1, f"\n    # {category.title()}: {tool_name}\n")
        lines.insert(insert_idx + 2, import_line + "\n")
        server_file.write_text("".join(lines), encoding="utf-8")
        return True

    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scaffold a new Revula tool module.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Valid categories: {', '.join(VALID_CATEGORIES)}

Examples:
  %(prog)s --name scan_headers --category static --description "Scan PE/ELF headers"
  %(prog)s --name frida_hook --category dynamic --description "Set Frida hooks"
  %(prog)s --name detect_packing --category malware --description "Detect packers"
        """,
    )
    parser.add_argument(
        "--name", "-n",
        required=True,
        help="Tool name (snake_case, without 're_' prefix)",
    )
    parser.add_argument(
        "--category", "-c",
        required=True,
        choices=VALID_CATEGORIES,
        help="Tool category (determines the subdirectory)",
    )
    parser.add_argument(
        "--description", "-d",
        required=True,
        help="Short description of what the tool does",
    )
    parser.add_argument(
        "--no-server-update",
        action="store_true",
        help="Don't update server.py with the new import",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    Revula — New Tool Scaffold                        ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Validate
    try:
        tool_name = validate_name(args.name)
        category = validate_category(args.category)
    except ValueError as e:
        error(str(e))
        sys.exit(1)

    description: str = args.description
    mcp_name = f"re_{tool_name}"

    info(f"Tool name:   {mcp_name}")
    info(f"Category:    {category}")
    info(f"Description: {description}")
    info(f"Module:      revula.tools.{category}.{tool_name}")
    print()

    # Create file
    try:
        tool_file = create_tool_file(tool_name, category, description)
        success(f"Created: {tool_file}")
    except FileExistsError as e:
        error(str(e))
        sys.exit(1)

    # Update server.py
    if not args.no_server_update:
        if update_server_imports(tool_name, category):
            success(f"Updated server.py with import for {mcp_name}")
        else:
            info("server.py not updated (import may already exist or server.py not found)")

    # Summary
    print()
    info("Next steps:")
    info(f"  1. Edit {tool_file.relative_to(PROJECT_ROOT)}")
    info(f"     - Replace the TODO with your analysis logic")
    info(f"     - Update input_schema with your parameters")
    info(f"     - Add requires_tools/requires_modules as needed")
    info(f"  2. Add tests in tests/test_{category}.py")
    info(f"  3. Run: python -m pytest tests/ -k {tool_name}")
    print()


if __name__ == "__main__":
    main()
