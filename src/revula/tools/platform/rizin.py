"""
Revula Rizin Integration — Open-source RE framework (successor to radare2).

Provides analysis, disassembly, cross-references, function listing,
and scripted analysis via rizin/r2pipe.
"""

from __future__ import annotations

import logging
import shutil
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


def _rizin() -> str | None:
    """Find rizin binary."""
    return shutil.which("rizin") or shutil.which("rz-bin")


async def _rz_cmd(
    binary_path: str,
    commands: list[str],
    timeout: int = 120,
) -> dict[str, Any]:
    """Run rizin commands on a binary. Returns {command: output}."""
    rizin = _rizin()
    if not rizin:
        return {"error": "rizin not found on PATH"}

    results: dict[str, Any] = {}
    # Use -q (quiet) -c (command) mode
    for cmd in commands:
        proc = await safe_subprocess(
            [rizin, "-q", "-c", cmd, binary_path],
            timeout=timeout,
        )
        results[cmd] = proc.stdout.strip() if proc.success else proc.stderr.strip()

    return results


@TOOL_REGISTRY.register(
    name="re_rizin_analyze",
    description=(
        "Analyze a binary using Rizin: auto-analysis, function listing, "
        "cross-references, strings, imports/exports, sections, and custom commands."
    ),
    category="platform",
    input_schema={
        "type": "object",
        "required": ["binary_path", "action"],
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to binary file.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "info", "functions", "strings", "imports",
                    "exports", "sections", "xrefs_to", "xrefs_from",
                    "disasm", "decompile", "graph", "custom",
                ],
                "description": "Analysis action to perform.",
            },
            "address": {
                "type": "string",
                "description": "Address for disasm/xrefs (hex, e.g. '0x401000').",
            },
            "function_name": {
                "type": "string",
                "description": "Function name for targeted analysis.",
            },
            "custom_commands": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Custom rizin commands for 'custom' action.",
            },
            "count": {
                "type": "integer",
                "description": "Number of instructions/items for disasm. Default: 50.",
            },
        },
    },
)
async def handle_rizin_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Rizin analysis."""
    binary_path = arguments["binary_path"]
    action = arguments["action"]
    address = arguments.get("address", "")
    func_name = arguments.get("function_name", "")
    custom_cmds = arguments.get("custom_commands", [])
    count = arguments.get("count", 50)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    if not _rizin():
        # Try r2pipe as alternative
        try:
            import r2pipe

            r2 = r2pipe.open(str(file_path))
            r2.cmd("aaa")

            if action == "info":
                return text_result({"info": r2.cmdj("ij"), "analyzer": "r2pipe"})
            elif action == "functions":
                return text_result({"functions": r2.cmdj("aflj"), "analyzer": "r2pipe"})
            elif action == "strings":
                return text_result({"strings": r2.cmdj("izj"), "analyzer": "r2pipe"})
            elif action == "imports":
                return text_result({"imports": r2.cmdj("iij"), "analyzer": "r2pipe"})
            elif action == "disasm":
                addr = address or func_name or "main"
                return text_result({
                    "disassembly": r2.cmd(f"pd {count} @ {addr}"),
                    "analyzer": "r2pipe",
                })
            elif action == "custom":
                results = {}
                for cmd in custom_cmds:
                    results[cmd] = r2.cmd(cmd)
                return text_result({"results": results, "analyzer": "r2pipe"})
            else:
                return text_result({"output": r2.cmd(action), "analyzer": "r2pipe"})

        except ImportError:
            return error_result(
                "Neither rizin nor r2pipe found. Install rizin: "
                "https://rizin.re or pip install r2pipe"
            )

    cmd_map = {
        "info": ["aaa", "ij"],
        "functions": ["aaa", "aflj"],
        "strings": ["izj"],
        "imports": ["iij"],
        "exports": ["iEj"],
        "sections": ["iSj"],
        "xrefs_to": ["aaa", f"axtj {address or func_name}"],
        "xrefs_from": ["aaa", f"axfj {address or func_name}"],
        "disasm": ["aaa", f"pd {count} @ {address or func_name or 'main'}"],
        "decompile": ["aaa", f"pdg @ {address or func_name or 'main'}"],
        "graph": ["aaa", f"agfj @ {address or func_name or 'main'}"],
        "custom": ["aaa", *custom_cmds],
    }

    commands = cmd_map.get(action, ["aaa", action])
    results = await _rz_cmd(str(file_path), commands, timeout=120)

    return text_result({
        "binary": str(file_path),
        "action": action,
        "results": results,
        "analyzer": "rizin",
    })


@TOOL_REGISTRY.register(
    name="re_rizin_diff",
    description=(
        "Binary diffing using Rizin: compare two binaries for function-level "
        "and basic-block-level differences."
    ),
    category="platform",
    input_schema={
        "type": "object",
        "required": ["binary_a", "binary_b"],
        "properties": {
            "binary_a": {
                "type": "string",
                "description": "Path to first binary.",
            },
            "binary_b": {
                "type": "string",
                "description": "Path to second binary.",
            },
        },
    },
)
async def handle_rizin_diff(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Binary diffing with Rizin."""
    binary_a = arguments["binary_a"]
    binary_b = arguments["binary_b"]
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    path_a = validate_binary_path(binary_a, allowed_dirs=allowed_dirs)
    path_b = validate_binary_path(binary_b, allowed_dirs=allowed_dirs)

    rz_diff = shutil.which("rz-diff")
    if not rz_diff:
        return error_result("rz-diff not found. Install rizin.")

    # Run byte-level diff with Myers algorithm
    proc = await safe_subprocess(
        [rz_diff, "-d", "myers", str(path_a), str(path_b)],
        timeout=120,
    )
    diff_output = proc.stdout.strip() if proc.success else proc.stderr.strip()

    # Also try ssdeep similarity comparison
    proc_ssdeep = await safe_subprocess(
        [rz_diff, "-d", "ssdeep", str(path_a), str(path_b)],
        timeout=120,
    )
    ssdeep_output = proc_ssdeep.stdout.strip() if proc_ssdeep.success else ""

    return text_result({
        "binary_a": str(path_a),
        "binary_b": str(path_b),
        "diff": diff_output,
        "ssdeep_diff": ssdeep_output if ssdeep_output else None,
        "analyzer": "rz-diff",
    })
