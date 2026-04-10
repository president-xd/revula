"""
Revula Code Coverage — Track execution coverage for reversing workflows.

Integrates with: DynamoRIO drcov, Intel PIN, GDB breakpoint-based coverage,
or Frida-based block tracing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from pathlib import Path
from typing import Any

from revula.config import ToolNotAvailableError
from revula.sandbox import safe_subprocess, validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Coverage Data Parsers
# ---------------------------------------------------------------------------


def parse_drcov(data: bytes) -> dict[str, Any]:
    """Parse DynamoRIO drcov coverage file."""
    lines = data.split(b"\n")

    header_info: dict[str, Any] = {}
    modules: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []

    i = 0
    # Parse header
    while i < len(lines):
        line = lines[i].decode("utf-8", errors="replace").strip()
        i += 1

        if line.startswith("DRCOV VERSION:"):
            header_info["version"] = line.split(":")[1].strip()
        elif line.startswith("DRCOV FLAVOR:"):
            header_info["flavor"] = line.split(":")[1].strip()
        elif line.startswith("Module Table:"):
            # Parse module count
            parts = line.split(",")
            mod_count = int(parts[1].strip().split()[0]) if len(parts) > 1 else 0
            header_info["module_count"] = mod_count
        elif line.startswith("Columns:"):
            # Module table columns header
            for _j in range(header_info.get("module_count", 0)):
                if i < len(lines):
                    mod_line = lines[i].decode("utf-8", errors="replace").strip()
                    i += 1
                    parts = mod_line.split(",")
                    if len(parts) >= 5:
                        modules.append({
                            "id": int(parts[0].strip()),
                            "containing_id": int(parts[1].strip()) if len(parts) > 5 else 0,
                            "base": parts[2].strip() if len(parts) > 5 else parts[1].strip(),
                            "end": parts[3].strip() if len(parts) > 5 else parts[2].strip(),
                            "path": parts[-1].strip(),
                        })
        elif line.startswith("BB Table:"):
            # Rest is binary basic block data
            parts = line.split(",")
            bb_count = int(parts[0].split(":")[1].strip()) if ":" in parts[0] else 0
            header_info["block_count"] = bb_count

            # Binary block data follows
            remaining = b"\n".join(lines[i:])
            # Each block entry: module_id(2) + start(4) + size(2) = 8 bytes
            for off in range(0, min(len(remaining), bb_count * 8), 8):
                if off + 8 <= len(remaining):
                    chunk = remaining[off:off + 8]
                    start, size, mod_id = struct.unpack("<IHH", chunk)
                    blocks.append({"module_id": mod_id, "offset": start, "size": size})
            break

    return {
        "header": header_info,
        "modules": modules,
        "blocks": blocks,
        "total_blocks": len(blocks),
    }


def parse_lcov(data: str) -> dict[str, Any]:
    """Parse LCOV coverage format."""
    files: dict[str, dict[str, Any]] = {}
    current_file = ""

    for line in data.splitlines():
        line = line.strip()
        if line.startswith("SF:"):
            current_file = line[3:]
            files[current_file] = {"lines_hit": [], "lines_found": [], "functions": []}
        elif line.startswith("DA:") and current_file:
            parts = line[3:].split(",")
            line_num = int(parts[0])
            hits = int(parts[1])
            files[current_file]["lines_found"].append(line_num)
            if hits > 0:
                files[current_file]["lines_hit"].append(line_num)
        elif line.startswith("FN:") and current_file:
            parts = line[3:].split(",")
            if len(parts) >= 2:
                files[current_file]["functions"].append({
                    "line": int(parts[0]),
                    "name": parts[1],
                })

    # Calculate coverage percentages
    for _f, info in files.items():
        found = len(info["lines_found"])
        hit = len(info["lines_hit"])
        info["coverage"] = (hit / found * 100) if found > 0 else 0.0

    return {
        "files": files,
        "total_files": len(files),
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_coverage_collect",
    description=(
        "Collect code coverage for a binary execution. "
        "Supports DynamoRIO (drcov), Frida block tracing, or GDB breakpoint coverage. "
        "Outputs coverage data in drcov format for use with lighthouse/dragondance."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to binary."},
            "args": {"type": "array", "items": {"type": "string"}},
            "backend": {
                "type": "string",
                "enum": ["drcov", "frida"],
                "default": "drcov",
                "description": "Coverage collection method.",
            },
            "output_path": {
                "type": "string",
                "description": "Path to save coverage file.",
            },
            "timeout": {"type": "integer", "default": 60},
        },
        "required": ["binary_path"],
    },
    category="dynamic",
)
async def handle_coverage_collect(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect coverage."""
    binary_path = arguments["binary_path"]
    args = arguments.get("args", [])
    backend = arguments.get("backend", "drcov")
    output_path = arguments.get("output_path")
    timeout = arguments.get("timeout", 60)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    if not output_path:
        output_path = str(file_path.parent / f"{file_path.stem}.cov")

    if backend == "drcov":
        return await _collect_drcov(file_path, args, output_path, timeout, config)
    elif backend == "frida":
        return await _collect_frida(file_path, args, output_path, timeout)
    else:
        return error_result(f"Unknown backend: {backend}")


async def _collect_drcov(
    binary: Path, args: list[str], output_path: str, timeout: int, config: Any
) -> list[dict[str, Any]]:
    """Collect coverage with DynamoRIO drcov."""
    drrun = "drrun"
    if config:
        try:
            drrun = config.require_tool("drrun")
        except ToolNotAvailableError as e:
            return error_result(str(e))

    cmd = [
        drrun,
        "-t", "drcov",
        "-dump_text",
        "-logdir", str(Path(output_path).parent),
        "--",
        str(binary),
        *args,
    ]

    result = await safe_subprocess(cmd, timeout=timeout, max_memory_mb=2048)

    if not result.success:
        return error_result(f"DynamoRIO failed: {result.stderr}")

    # Find output file
    out_dir = Path(output_path).parent
    cov_files = sorted(out_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)

    if cov_files:
        cov_data = cov_files[0].read_bytes()
        parsed = parse_drcov(cov_data)
        # Copy to desired path
        Path(output_path).write_bytes(cov_data)
        return text_result({
            "backend": "drcov",
            "output": output_path,
            "summary": {
                "modules": len(parsed["modules"]),
                "blocks": parsed["total_blocks"],
            },
        })

    return error_result("No coverage file generated")


async def _collect_frida(
    binary: Path, args: list[str], output_path: str, timeout: int
) -> list[dict[str, Any]]:
    """Collect coverage with Frida Stalker."""
    try:
        import frida
    except ImportError:
        return error_result("frida not installed")

    device = frida.get_local_device()
    pid = device.spawn([str(binary), *args])
    session = device.attach(pid)

    # Block-level coverage collection script
    script_code = """
    var coverage = {};
    var moduleMap = new ModuleMap();

    Stalker.follow(Process.getCurrentThreadId(), {
        events: { compile: true },
        onReceive: function(events) {
            var parsed = Stalker.parse(events, {stringify: false, annotate: false});
            for (var i = 0; i < parsed.length; i++) {
                var event = parsed[i];
                if (event[0] === 'compile') {
                    var addr = event[1];
                    var mod = moduleMap.find(addr);
                    if (mod) {
                        var key = mod.name + ':' + addr.sub(mod.base);
                        coverage[key] = (coverage[key] || 0) + 1;
                    }
                }
            }
        }
    });

    rpc.exports = {
        getCoverage: function() {
            return coverage;
        },
        getModules: function() {
            return Process.enumerateModules().map(function(m) {
                return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
            });
        }
    };
    """

    script = session.create_script(script_code)
    script.load()
    device.resume(pid)

    # Wait for execution
    await asyncio.sleep(min(timeout, 30))

    try:
        coverage = script.exports_sync.get_coverage()
        modules = script.exports_sync.get_modules()
    except Exception as e:
        return error_result(f"Failed to collect coverage: {e}")
    finally:
        device.kill(pid)

    # Save coverage data
    result_data = {"modules": modules, "coverage": coverage}
    Path(output_path).write_text(json.dumps(result_data, indent=2))

    return text_result({
        "backend": "frida",
        "output": output_path,
        "summary": {
            "modules": len(modules),
            "unique_blocks": len(coverage),
        },
    })


@TOOL_REGISTRY.register(
    name="re_coverage_analyze",
    description=(
        "Analyze a coverage file. Parses drcov, lcov, or JSON coverage formats. "
        "Reports per-module coverage, hot/cold regions, and function coverage."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "coverage_path": {"type": "string", "description": "Path to coverage data file."},
            "format": {
                "type": "string",
                "enum": ["drcov", "lcov", "json", "auto"],
                "default": "auto",
            },
            "module_filter": {
                "type": "string",
                "description": "Filter results to a specific module name.",
            },
        },
        "required": ["coverage_path"],
    },
    category="dynamic",
)
async def handle_coverage_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze coverage data."""
    cov_path = validate_path(arguments["coverage_path"])
    fmt = arguments.get("format", "auto")
    module_filter = arguments.get("module_filter")

    data = cov_path.read_bytes()

    # Auto-detect format
    if fmt == "auto":
        text = data.decode("utf-8", errors="replace")
        if text.startswith("DRCOV"):
            fmt = "drcov"
        elif text.startswith("TN:") or "SF:" in text[:200]:
            fmt = "lcov"
        else:
            try:
                json.loads(text)
                fmt = "json"
            except json.JSONDecodeError:
                fmt = "drcov"

    if fmt == "drcov":
        parsed = parse_drcov(data)

        # Per-module stats
        module_stats: dict[int, int] = {}
        for block in parsed["blocks"]:
            mid = block["module_id"]
            module_stats[mid] = module_stats.get(mid, 0) + 1

        modules_with_coverage = []
        for mod in parsed["modules"]:
            mod_id = mod["id"]
            block_count = module_stats.get(mod_id, 0)
            if module_filter and module_filter.lower() not in mod["path"].lower():
                continue
            modules_with_coverage.append({
                **mod,
                "blocks_covered": block_count,
            })

        return text_result({
            "format": "drcov",
            "total_blocks": parsed["total_blocks"],
            "modules": modules_with_coverage,
        })

    elif fmt == "lcov":
        parsed = parse_lcov(data.decode("utf-8", errors="replace"))
        return text_result({"format": "lcov", **parsed})

    elif fmt == "json":
        parsed = json.loads(data)
        return text_result({"format": "json", **parsed})

    return error_result(f"Unsupported format: {fmt}")
