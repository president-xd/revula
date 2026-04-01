"""
Revula Server — MCP entrypoint with stdio and SSE transport support.

This is the main entry point for the Revula server. It:
- Initializes configuration and detects available tools
- Starts the session manager
- Registers all tool handlers from the tool modules
- Serves via stdio (primary) or SSE (optional for remote access)
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    EmbeddedResource,
    Resource,
    TextContent,
    Tool,
)

from revula import __app_name__, __version__
from revula.cache import ResultCache
from revula.config import format_availability_report, get_config
from revula.rate_limit import RateLimitConfig, RateLimiter
from revula.session import SessionManager
from revula.tools import TOOL_REGISTRY

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,  # MCP uses stdout for protocol, logs go to stderr
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Server instance
# ---------------------------------------------------------------------------

app = Server(__app_name__)
SESSION_MANAGER = SessionManager()
RESULT_CACHE = ResultCache()
RATE_LIMITER = RateLimiter(RateLimitConfig())

# Tool-name prefixes that mutate state and should NOT be cached
_MUTATING_PREFIXES = ("re_patch_", "re_frida_", "re_gdb_", "re_lldb_", "re_adb_", "re_qemu_")

# ---------------------------------------------------------------------------
# Import all tool modules to trigger registration
# ---------------------------------------------------------------------------


def _register_all_tools() -> None:
    """Import all tool modules to trigger @register_tool() decorators."""
    # Static analysis
    _safe_import("revula.tools.static.disasm")
    _safe_import("revula.tools.static.decompile")
    _safe_import("revula.tools.static.pe_elf")
    _safe_import("revula.tools.static.strings")
    _safe_import("revula.tools.static.yara_scan")
    _safe_import("revula.tools.static.capa_scan")
    _safe_import("revula.tools.static.entropy")
    _safe_import("revula.tools.static.symbols")

    # Dynamic analysis
    _safe_import("revula.tools.dynamic.gdb")
    _safe_import("revula.tools.dynamic.lldb")
    _safe_import("revula.tools.dynamic.frida")
    _safe_import("revula.tools.dynamic.coverage")

    # De-obfuscation
    _safe_import("revula.tools.deobfuscation.deobfuscate")

    # Unpacking
    _safe_import("revula.tools.unpacking.unpack")

    # Symbolic execution
    _safe_import("revula.tools.symbolic.symbolic")

    # Binary formats
    _safe_import("revula.tools.binary_formats.formats")

    # Utilities
    _safe_import("revula.tools.utils.hex")
    _safe_import("revula.tools.utils.crypto")
    _safe_import("revula.tools.utils.patch")
    _safe_import("revula.tools.utils.network")

    # Android RE
    _safe_import("revula.tools.android.apk_parse")
    _safe_import("revula.tools.android.dex_analyze")
    _safe_import("revula.tools.android.decompile")
    _safe_import("revula.tools.android.binary_analysis")
    _safe_import("revula.tools.android.device")
    _safe_import("revula.tools.android.frida_android")
    _safe_import("revula.tools.android.traffic")
    _safe_import("revula.tools.android.repack")
    _safe_import("revula.tools.android.scanners")

    # Cross-platform RE tools
    _safe_import("revula.tools.platform.rizin")
    _safe_import("revula.tools.platform.gdb_enhanced")
    _safe_import("revula.tools.platform.qemu")

    # Exploit development
    _safe_import("revula.tools.exploit.shellcode")
    _safe_import("revula.tools.exploit.format_string")
    _safe_import("revula.tools.exploit.rop_builder")
    _safe_import("revula.tools.exploit.libc_database")
    _safe_import("revula.tools.exploit.heap_analysis")

    # Anti-analysis detection & bypass
    _safe_import("revula.tools.antianalysis.detect_bypass")

    # Malware analysis
    _safe_import("revula.tools.malware.triage")

    # Firmware RE
    _safe_import("revula.tools.firmware.firmware")

    # Protocol RE
    _safe_import("revula.tools.protocol.protocol")

    # Admin / infrastructure
    _safe_import("revula.tools.admin")


def _safe_import(module_name: str) -> None:
    """Import a module, logging warnings if it fails (non-fatal)."""
    try:
        __import__(module_name)
        logger.debug("Loaded tool module: %s", module_name)
    except ImportError as e:
        logger.debug("Skipped tool module %s (missing dependency): %s", module_name, e)
    except Exception as e:
        logger.warning("Error loading tool module %s: %s", module_name, e)


# ---------------------------------------------------------------------------
# MCP Handlers
# ---------------------------------------------------------------------------


@app.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """Return all registered tools as MCP Tool objects."""
    tools: list[Tool] = []
    for defn in TOOL_REGISTRY.all():
        tools.append(
            Tool(
                name=defn.name,
                description=defn.description,
                inputSchema=defn.input_schema,
            )
        )
    return tools


@app.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent | EmbeddedResource]:
    """Dispatch a tool call to the appropriate handler."""
    if arguments is None:
        arguments = {}

    logger.info("Tool call: %s(%s)", name, _truncate_args(arguments))

    # Rate limiting
    if not RATE_LIMITER.check(name):
        return [TextContent(type="text", text=json.dumps({
            "error": True,
            "message": f"Rate limit exceeded for tool '{name}'. Try again shortly.",
        }))]

    # Check cache for read-only tools (skip tools that mutate state)
    cacheable = not any(name.startswith(p) for p in _MUTATING_PREFIXES)
    cache_key = ""

    if cacheable:
        cache_key = ResultCache.make_key(name, arguments)
        cached = RESULT_CACHE.get(cache_key)
        if cached is not None:
            logger.debug("Cache HIT: %s", name)
            return _convert_results(cached)

    # Inject session manager into arguments for tools that need it
    arguments["__session_manager__"] = SESSION_MANAGER
    arguments["__config__"] = get_config()

    result = await TOOL_REGISTRY.execute(name, arguments)

    # Cache the result if cacheable and not an error
    if cacheable and cache_key and not _is_error_result(result):
        RESULT_CACHE.put(cache_key, result)

    return _convert_results(result)


def _is_error_result(result: list[dict[str, Any]]) -> bool:
    """Check if a tool result is an error."""
    if not result:
        return False
    first = result[0]
    if first.get("type") == "text":
        try:
            parsed = json.loads(first["text"])
            return bool(parsed.get("error"))
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return False


def _convert_results(result: list[dict[str, Any]]) -> list[TextContent | EmbeddedResource]:
    """Convert raw dicts to MCP content types."""
    contents: list[TextContent | EmbeddedResource] = []
    for item in result:
        if item.get("type") == "text":
            contents.append(TextContent(type="text", text=item["text"]))
        else:
            contents.append(
                TextContent(type="text", text=json.dumps(item, default=str))
            )
    return contents


@app.list_resources()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_resources() -> list[Resource]:
    """List all binary resources tracked by the session manager."""
    resources_data = await SESSION_MANAGER.list_binary_resources()
    resources: list[Resource] = []
    for r in resources_data:
        resources.append(
            Resource(
                uri=r["uri"],
                name=r["name"],
                mimeType=r.get("mime_type", "application/octet-stream"),
            )
        )
    return resources


@app.read_resource()  # type: ignore[no-untyped-call,untyped-decorator]
async def read_resource(uri: str) -> bytes:
    """Read the content of a binary resource."""
    return await SESSION_MANAGER.read_resource(uri)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_args(args: dict[str, Any], max_len: int = 200) -> str:
    """Truncate arguments for logging (avoid logging huge binary data)."""
    sanitized = {}
    for k, v in args.items():
        if k.startswith("__"):
            continue
        if isinstance(v, str) and len(v) > 100:
            sanitized[k] = v[:100] + "..."
        elif isinstance(v, bytes) and len(v) > 50:
            sanitized[k] = f"<{len(v)} bytes>"
        else:
            sanitized[k] = v
    s = str(sanitized)
    return s[:max_len] + "..." if len(s) > max_len else s


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def _run_server() -> None:
    """Main async entry point."""
    config = get_config()
    report = format_availability_report(config)
    logger.info("Starting Revula v%s", __version__)
    logger.info("\n%s", report)

    # Register all tools
    _register_all_tools()
    logger.info("Registered %d tools", TOOL_REGISTRY.count())

    # Start session manager
    await SESSION_MANAGER.start()

    try:
        # Run with stdio transport
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )
    finally:
        await SESSION_MANAGER.stop()


def main() -> None:
    """CLI entry point."""
    try:
        asyncio.run(_run_server())
    except KeyboardInterrupt:
        logger.info("Server interrupted, shutting down...")
    except Exception as e:
        logger.critical("Server crashed: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
