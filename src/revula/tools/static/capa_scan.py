"""
Revula CAPA Scanner — capability detection via Mandiant capa.

Wraps capa CLI with JSON output parsing. Maps to ATT&CK techniques and MBC behaviors.
Always runs with timeout. Never parses terminal text output — only --json.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


@TOOL_REGISTRY.register(
    name="re_capa",
    description=(
        "Detect capabilities in a binary using Mandiant capa. "
        "Returns ATT&CK techniques, MBC behaviors, and namespaced capabilities. "
        "Backend: capa CLI with --json output. Always runs with configurable timeout."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file to analyze.",
            },
            "format": {
                "type": "string",
                "enum": ["pe", "elf", "auto"],
                "description": "Binary format hint. Default: auto.",
                "default": "auto",
            },
            "rules_path": {
                "type": "string",
                "description": "Path to custom capa rules directory (optional).",
            },
            "timeout": {
                "type": "integer",
                "description": "Analysis timeout in seconds. Default: 300.",
                "default": 300,
            },
        },
        "required": ["binary_path"],
    },
    category="static",
    requires_tools=["capa"],
)
async def handle_capa(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Run capa analysis on a binary."""
    binary_path_str = arguments["binary_path"]
    fmt = arguments.get("format", "auto")
    rules_path = arguments.get("rules_path")
    timeout = arguments.get("timeout", 300)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    capa_path = config.require_tool("capa") if config else "capa"

    cmd = [capa_path, "--json", str(file_path)]

    if fmt != "auto":
        cmd.extend(["-f", fmt])
    if rules_path:
        rules_dir = validate_path(rules_path, allowed_dirs=allowed_dirs, path_kind="dir")
        cmd.extend(["-r", str(rules_dir)])
    else:
        # Auto-detect rules path — pip-installed capa often lacks embedded rules
        from pathlib import Path as _Path

        _rules_candidates = [
            _Path.home() / ".local" / "share" / "capa" / "rules",
            _Path.home() / ".capa" / "rules",
            _Path("/usr/share/capa/rules"),
            _Path("/opt/capa-rules"),
        ]
        for candidate in _rules_candidates:
            if candidate.is_dir():
                cmd.extend(["-r", str(candidate)])
                logger.info("Auto-detected capa rules at %s", candidate)
                break

    result = await safe_subprocess(
        cmd,
        timeout=timeout,
        max_memory_mb=1024,
    )

    if result.timed_out:
        return error_result(f"capa timed out after {timeout}s. Try a simpler binary or increase timeout.")

    if not result.success:
        return error_result(f"capa failed (rc={result.returncode}): {result.stderr[:500]}")

    # Parse JSON output
    try:
        capa_data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return error_result(f"Failed to parse capa JSON output: {e}")

    # Extract structured data
    capabilities: list[dict[str, Any]] = []
    attack_techniques: list[dict[str, Any]] = []
    mbc_behaviors: list[dict[str, Any]] = []

    rules = capa_data.get("rules", {})
    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})

        cap: dict[str, Any] = {
            "name": rule_name,
            "namespace": meta.get("namespace", ""),
            "scope": meta.get("scope", ""),
            "authors": meta.get("authors", []),
            "description": meta.get("description", ""),
        }

        # ATT&CK mapping
        attack = meta.get("attack", [])
        for att in attack:
            technique: dict[str, Any] = {
                "tactic": att.get("tactic", ""),
                "technique": att.get("technique", ""),
                "subtechnique": att.get("subtechnique", ""),
                "id": att.get("id", ""),
            }
            attack_techniques.append(technique)
            cap.setdefault("attack", []).append(technique)

        # MBC mapping
        mbc = meta.get("mbc", [])
        for m in mbc:
            behavior: dict[str, Any] = {
                "objective": m.get("objective", ""),
                "behavior": m.get("behavior", ""),
                "method": m.get("method", ""),
                "id": m.get("id", ""),
            }
            mbc_behaviors.append(behavior)
            cap.setdefault("mbc", []).append(behavior)

        # Match addresses
        addresses = []
        for match_addr in rule_data.get("matches", {}):
            addresses.append(match_addr)
        cap["match_addresses"] = addresses

        capabilities.append(cap)

    # Build summary
    namespaces: dict[str, int] = {}
    for cap in capabilities:
        ns = cap.get("namespace", "uncategorized")
        namespaces[ns] = namespaces.get(ns, 0) + 1

    return text_result({
        "file_path": str(file_path),
        "capability_count": len(capabilities),
        "attack_technique_count": len(attack_techniques),
        "mbc_behavior_count": len(mbc_behaviors),
        "namespace_summary": dict(sorted(namespaces.items(), key=lambda x: -x[1])),
        "attack_techniques": attack_techniques,
        "mbc_behaviors": mbc_behaviors,
        "capabilities": capabilities,
    })
