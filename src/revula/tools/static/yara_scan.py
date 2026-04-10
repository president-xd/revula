"""
Revula YARA Scanner — rule matching with inline compilation, community rules, and match context.

Features:
- Inline YARA rule compilation
- Rule file/directory loading
- Match context (N bytes around match offset)
- Community ruleset integration (Malware Bazaar, Malpedia-compatible, Elastic detection-rules)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from revula.sandbox import validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

COMMUNITY_RULES_DIR = Path.home() / ".revula" / "yara_rules"
LEGACY_COMMUNITY_RULES_DIR = Path.home() / ".revula" / "yara-rules"


def _resolve_community_rules_dir() -> Path:
    """Resolve installed community rules directory (canonical, then legacy)."""
    if COMMUNITY_RULES_DIR.exists():
        return COMMUNITY_RULES_DIR
    if LEGACY_COMMUNITY_RULES_DIR.exists():
        return LEGACY_COMMUNITY_RULES_DIR
    return COMMUNITY_RULES_DIR


# ---------------------------------------------------------------------------
# YARA scanning
# ---------------------------------------------------------------------------


def _compile_rules(
    rules_path: str | None = None,
    rules_inline: str | None = None,
    include_community: bool = False,
    allowed_dirs: list[str] | None = None,
) -> Any:
    """Compile YARA rules from various sources."""
    import yara

    if rules_inline:
        return yara.compile(source=rules_inline)

    if rules_path:
        path = validate_path(rules_path, allowed_dirs=allowed_dirs)
        if path.is_file():
            return yara.compile(filepath=str(path))
        elif path.is_dir():
            # Compile all .yar/.yara files in directory
            filepaths = {}
            for yar_file in sorted(path.glob("**/*.yar")) + sorted(path.glob("**/*.yara")):
                namespace = yar_file.stem
                filepaths[namespace] = str(yar_file)
            if not filepaths:
                raise ValueError(f"No .yar/.yara files found in {path}")
            return yara.compile(filepaths=filepaths)

    if include_community:
        community_dir = _resolve_community_rules_dir()
        if community_dir.exists():
            if allowed_dirs:
                community_dir = validate_path(
                    str(community_dir),
                    allowed_dirs=allowed_dirs,
                    path_kind="dir",
                )
            filepaths = {}
            for yar_file in sorted(community_dir.glob("**/*.yar")):
                filepaths[yar_file.stem] = str(yar_file)
            for yar_file in sorted(community_dir.glob("**/*.yara")):
                filepaths[yar_file.stem] = str(yar_file)
            if filepaths:
                return yara.compile(filepaths=filepaths)
        raise ValueError(
            f"Community rules not found at {COMMUNITY_RULES_DIR} "
            f"(legacy: {LEGACY_COMMUNITY_RULES_DIR}). "
            "Download YARA rulesets and place them there."
        )

    raise ValueError("Must provide rules_path, rules_inline, or set include_community_rules=true")


def _extract_match_context(
    data: bytes,
    offset: int,
    context_bytes: int = 32,
) -> dict[str, Any]:
    """Extract bytes around a match offset for context."""
    start = max(0, offset - context_bytes)
    end = min(len(data), offset + context_bytes)

    before = data[start:offset]
    after = data[offset:end]

    return {
        "offset": offset,
        "before_hex": before.hex(),
        "after_hex": after.hex(),
        "context_hex": data[start:end].hex(),
        "context_start": start,
        "context_end": end,
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_yara_scan",
    description=(
        "Scan binary files or hex data with YARA rules. "
        "Supports: inline rule compilation, rule files/directories, "
        "community rulesets (place in ~/.revula/yara_rules/). "
        "Returns matches with string offsets and configurable match context."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to binary file to scan.",
            },
            "hex_bytes": {
                "type": "string",
                "description": "Hex string to scan (alternative to binary_path).",
            },
            "rules_path": {
                "type": "string",
                "description": "Path to YARA rule file or directory of .yar files.",
            },
            "rules_inline": {
                "type": "string",
                "description": "Inline YARA rule source code to compile and match.",
            },
            "include_community_rules": {
                "type": "boolean",
                "description": "Include community rules from ~/.revula/yara_rules/. Default: false.",
                "default": False,
            },
            "context_bytes": {
                "type": "integer",
                "description": "Number of context bytes around each match. Default: 32.",
                "default": 32,
            },
            "timeout": {
                "type": "integer",
                "description": "YARA scan timeout in seconds. Default: 60.",
                "default": 60,
            },
        },
        "anyOf": [
            {"required": ["binary_path"]},
            {"required": ["hex_bytes"]},
        ],
    },
    category="static",
    requires_modules=["yara"],
)
async def handle_yara_scan(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan with YARA rules."""
    import asyncio

    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")
    rules_path = arguments.get("rules_path")
    rules_inline = arguments.get("rules_inline")
    include_community = arguments.get("include_community_rules", False)
    context_bytes = arguments.get("context_bytes", 32)
    timeout = arguments.get("timeout", 60)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    resolved_rules_path: str | None = None

    if rules_path:
        rules_file = validate_path(rules_path, allowed_dirs=allowed_dirs)
        resolved_rules_path = str(rules_file)
        rules_path = resolved_rules_path

    if not rules_path and not rules_inline and not include_community:
        return error_result(
            "Must provide at least one of: rules_path, rules_inline, or include_community_rules=true"
        )

    # Get binary data
    if hex_bytes:
        try:
            data = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
        except ValueError as e:
            return error_result(f"Invalid hex string: {e}")
        source = "hex_bytes"
    elif binary_path:
        file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
        data = file_path.read_bytes()
        source = str(file_path)
    else:
        return error_result("Must provide binary_path or hex_bytes")

    # Compile rules
    try:
        rules = _compile_rules(
            rules_path=rules_path,
            rules_inline=rules_inline,
            include_community=include_community,
            allowed_dirs=allowed_dirs,
        )
    except Exception as e:
        return error_result(f"YARA rule compilation failed: {e}")

    # Run scan in thread pool (YARA can be slow)
    loop = asyncio.get_running_loop()

    def _scan() -> list[Any]:
        return rules.match(data=data, timeout=timeout)  # type: ignore[no-any-return]

    try:
        matches = await asyncio.wait_for(
            loop.run_in_executor(None, _scan),
            timeout=timeout + 5,
        )
    except TimeoutError:
        return error_result(f"YARA scan timed out after {timeout}s")
    except Exception as e:
        return error_result(f"YARA scan failed: {e}")

    # Format results
    results = []
    for match in matches:
        match_info: dict[str, Any] = {
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags),
            "meta": dict(match.meta) if match.meta else {},
            "strings": [],
        }

        for string_match in match.strings:
            for instance in string_match.instances:
                string_info: dict[str, Any] = {
                    "identifier": string_match.identifier,
                    "offset": instance.offset,
                    "matched_data": instance.matched_data.hex(),
                    "matched_length": instance.matched_length,
                }

                # Add context
                if context_bytes > 0:
                    string_info["context"] = _extract_match_context(
                        data, instance.offset, context_bytes
                    )

                match_info["strings"].append(string_info)

        results.append(match_info)

    return text_result({
        "source": source,
        "data_size": len(data),
        "rules_source": (
            "inline"
            if rules_inline
            else resolved_rules_path or str(_resolve_community_rules_dir())
        ),
        "match_count": len(results),
        "matches": results,
    })
