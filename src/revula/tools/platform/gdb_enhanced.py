"""
Revula Enhanced GDB — extends base GDB with heap analysis, ROP gadgets,
GEF/PEDA/pwndbg integration, and advanced debugging features.
"""

from __future__ import annotations

import logging
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


async def _run_gdb_batch(
    binary: str,
    commands: list[str],
    timeout: int = 120,
    core_file: str | None = None,
    gdb_path: str = "gdb",
) -> dict[str, str | int | bool]:
    """Run GDB in batch mode with a list of commands."""
    cmd = [gdb_path, "--batch", "--quiet"]

    for c in commands:
        cmd.extend(["-ex", c])

    if core_file:
        cmd.extend([binary, core_file])
    else:
        cmd.append(binary)

    proc = await safe_subprocess(cmd, timeout=timeout)
    return {
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
        "success": proc.success,
    }


@TOOL_REGISTRY.register(
    name="re_gdb_heap",
    description=(
        "GDB heap analysis: heap info, chunk inspection, bin lists, "
        "arena info, heap search, tcache dump. Uses GEF/pwndbg if available."
    ),
    category="platform",
    requires_tools=["gdb"],
    input_schema={
        "type": "object",
        "required": ["binary_path", "action"],
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Path to binary.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "heap_info", "heap_chunks", "heap_bins",
                    "arena_info", "tcache_dump", "heap_search",
                    "fastbins", "unsorted_bin",
                ],
                "description": "Heap analysis action.",
            },
            "core_file": {
                "type": "string",
                "description": "Path to core dump for post-mortem analysis.",
            },
            "search_value": {
                "type": "string",
                "description": "Value to search for in heap_search.",
            },
            "gdb_path": {
                "type": "string",
                "description": "Path to GDB binary. Default: gdb.",
            },
        },
    },
)
async def handle_gdb_heap(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """GDB heap analysis."""
    binary_path = arguments["binary_path"]
    action = arguments["action"]
    core_file = arguments.get("core_file")
    search_value = arguments.get("search_value", "")
    gdb_path = arguments.get("gdb_path", "gdb")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    # Map actions to GDB/GEF/pwndbg commands
    action_cmds: dict[str, list[str]] = {
        "heap_info": [
            "run &",
            "info proc mappings",
            "heap",  # GEF
            "heap chunks",  # pwndbg
        ],
        "heap_chunks": [
            "run &",
            "heap chunks",  # pwndbg
            "heap chunk 0",  # GEF
        ],
        "heap_bins": [
            "run &",
            "heap bins",  # pwndbg
        ],
        "arena_info": [
            "run &",
            "arena",  # GEF
            "arenas",  # pwndbg
        ],
        "tcache_dump": [
            "run &",
            "tcache",  # pwndbg
            "heap bins tcache",
        ],
        "heap_search": [
            "run &",
            f"find /b /w 0x0, 0xffffffff, {search_value}" if search_value else "echo no_search_value",
        ],
        "fastbins": [
            "run &",
            "fastbins",  # pwndbg
        ],
        "unsorted_bin": [
            "run &",
            "unsortedbin",  # pwndbg
        ],
    }

    commands = action_cmds.get(action)
    if not commands:
        return error_result(f"Unknown heap action: {action}")

    result = await _run_gdb_batch(
        binary_path, commands,
        core_file=core_file, gdb_path=gdb_path,
    )

    return text_result({
        "action": action,
        "output": str(result.get("stdout", ""))[:8000],
        "success": result.get("success", False),
        "analyzer": "gdb_heap",
    })


@TOOL_REGISTRY.register(
    name="re_gdb_rop",
    description=(
        "ROP gadget finding via GDB + ROPgadget/ropper. "
        "Find gadgets, build chains, search for specific patterns."
    ),
    category="platform",
    requires_tools=["ropgadget"],
    input_schema={
        "type": "object",
        "required": ["binary_path", "action"],
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Path to binary.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "find_gadgets", "search_pattern", "rop_chain",
                    "jop_gadgets", "syscall_gadgets",
                ],
                "description": "ROP action.",
            },
            "pattern": {
                "type": "string",
                "description": "Gadget pattern (e.g., 'pop rdi; ret').",
            },
            "depth": {
                "type": "integer",
                "description": "Max gadget depth. Default: 10.",
            },
            "tool": {
                "type": "string",
                "enum": ["ROPgadget", "ropper"],
                "description": "ROP tool to use. Default: ROPgadget.",
            },
        },
    },
)
async def handle_gdb_rop(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """ROP gadget analysis."""
    binary_path = arguments["binary_path"]
    action = arguments["action"]
    pattern = arguments.get("pattern", "")
    depth = arguments.get("depth", 10)
    tool = arguments.get("tool", "ROPgadget")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    if tool == "ROPgadget":
        cmd = ["ROPgadget", "--binary", str(file_path)]

        if action == "find_gadgets":
            cmd.extend(["--depth", str(depth)])
        elif action == "search_pattern":
            if not pattern:
                return error_result("pattern required for search_pattern")
            cmd.extend(["--only", pattern])
        elif action == "rop_chain":
            cmd.append("--ropchain")
        elif action == "jop_gadgets":
            cmd.extend(["--depth", str(depth), "--norop"])
        elif action == "syscall_gadgets":
            cmd.extend(["--only", "syscall|int 0x80|sysenter"])
        else:
            return error_result(f"Unknown ROP action: {action}")

    else:  # ropper
        cmd = ["ropper", "--file", str(file_path)]

        if action == "find_gadgets":
            cmd.extend(["--depth", str(depth)])
        elif action == "search_pattern":
            if not pattern:
                return error_result("pattern required for search_pattern")
            cmd.extend(["--search", pattern])
        elif action == "rop_chain":
            cmd.extend(["--chain", "execve"])
        elif action == "jop_gadgets":
            cmd.extend(["--type", "jop"])
        elif action == "syscall_gadgets":
            cmd.extend(["--search", "syscall"])
        else:
            return error_result(f"Unknown ROP action: {action}")

    proc = await safe_subprocess(cmd, timeout=120)

    gadgets = proc.stdout[:10000] if proc.stdout else ""
    count = gadgets.count("\n")

    return text_result({
        "action": action,
        "tool": tool,
        "gadgets": gadgets,
        "gadget_count": count,
        "success": proc.success,
    })


@TOOL_REGISTRY.register(
    name="re_gdb_exploit_helpers",
    description=(
        "GDB exploit development helpers: checksec, pattern create/find, "
        "offset calculation, format string helpers."
    ),
    category="platform",
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "pattern_create", "pattern_offset",
                    "checksec", "got_plt", "plt_got",
                    "vmmap", "canary_find",
                ],
                "description": "Exploit helper action.",
            },
            "binary_path": {
                "type": "string",
                "description": "Path to binary.",
            },
            "length": {
                "type": "integer",
                "description": "Pattern length for pattern_create. Default: 200.",
            },
            "value": {
                "type": "string",
                "description": "Value for pattern_offset.",
            },
            "core_file": {
                "type": "string",
                "description": "Core dump path.",
            },
        },
    },
)
async def handle_gdb_exploit_helpers(
    arguments: dict[str, Any],
) -> list[dict[str, Any]]:
    """GDB exploit development helpers."""
    action = arguments["action"]
    binary_path = arguments.get("binary_path", "")
    length = arguments.get("length", 200)
    value = arguments.get("value", "")
    core_file = arguments.get("core_file")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    if binary_path:
        validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    if action == "pattern_create":
        # Use pwntools-style pattern generation (safe: pass length as int argument)
        safe_length = int(length)  # Validate as integer
        proc = await safe_subprocess(
            ["python3", "-c",
             "import sys; from pwn import cyclic; print(cyclic(int(sys.argv[1])).decode())",
             str(safe_length)],
            timeout=10,
        )
        if not proc.success:
            # Fallback: generate simple De Bruijn-like pattern
            pattern = _generate_pattern(length)
            return text_result({"pattern": pattern, "length": len(pattern)})
        return text_result({"pattern": proc.stdout.strip(), "length": length})

    elif action == "pattern_offset":
        if not value:
            return error_result("value required for pattern_offset")
        # Validate value is hex before passing
        import re as _re
        if not _re.fullmatch(r"[0-9a-fA-F]+", value):
            return error_result("value must be a hex string (e.g. '41414141')")
        proc = await safe_subprocess(
            ["python3", "-c",
             "import sys; from pwn import cyclic_find; print(cyclic_find(bytes.fromhex(sys.argv[1])))",
             value],
            timeout=10,
        )
        if not proc.success:
            return text_result({"offset": "pwntools not available, manual calc needed", "value": value})
        return text_result({"offset": proc.stdout.strip(), "value": value})

    elif action == "checksec":
        if not binary_path:
            return error_result("binary_path required for checksec")
        proc = await safe_subprocess(
            ["checksec", "--file", binary_path], timeout=30,
        )
        # pwntools checksec outputs to stderr, not stdout
        output = proc.stdout or proc.stderr or ""
        return text_result({
            "output": output[:4000],
            "success": proc.success or bool(output.strip()),
        })

    elif action in ("got_plt", "plt_got"):
        if not binary_path:
            return error_result("binary_path required")
        cmds = ["-ex", "info functions @plt", "-ex", "maintenance info sections .got.plt"]
        result = await _run_gdb_batch(binary_path, [c for c in cmds if not c.startswith("-")])
        return text_result({"output": str(result.get("stdout", ""))[:5000]})

    elif action == "vmmap":
        if not binary_path:
            return error_result("binary_path required")
        result = await _run_gdb_batch(
            binary_path,
            ["starti", "info proc mappings"],
            core_file=core_file,
        )
        return text_result({"output": str(result.get("stdout", ""))[:5000]})

    elif action == "canary_find":
        if not binary_path:
            return error_result("binary_path required")
        result = await _run_gdb_batch(
            binary_path,
            ["starti", "canary"],  # pwndbg/GEF command
            core_file=core_file,
        )
        return text_result({"output": str(result.get("stdout", ""))[:2000]})

    else:
        return error_result(f"Unknown exploit helper action: {action}")


def _generate_pattern(length: int) -> str:
    """Generate De Bruijn-like cyclic pattern."""
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    pattern = []
    for i in range(length):
        a = i // (len(charset) * len(charset)) % 26
        b = i // len(charset) % len(charset)
        c = i % len(charset)
        pattern.append(charset[a])
        if len(pattern) >= length:
            break
        pattern.append(charset[b])
        if len(pattern) >= length:
            break
        pattern.append(charset[c])
        if len(pattern) >= length:
            break
    return "".join(pattern[:length])
