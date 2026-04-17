"""
Revula Server — MCP entrypoint with stdio transport.

This is the main entry point for the Revula server. It:
- Initializes configuration and detects available tools
- Starts the session manager
- Registers all tool handlers from the tool modules
- Serves via stdio transport
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from typing import Any, cast

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    EmbeddedResource,
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    ResourceTemplate,
    TextContent,
    Tool,
    ToolAnnotations,
)

from revula import __app_name__, __version__
from revula.cache import ResultCache
from revula.config import format_availability_report, get_config
from revula.rate_limit import RateLimitConfig, RateLimiter
from revula.session import SessionManager
from revula.tools import TOOL_REGISTRY, ToolExecutionContext

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,  # MCP uses stdout for protocol, logs go to stderr
)
logger = logging.getLogger(__name__)
SENSITIVE_ARG_MARKERS = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "keystore_pass",
    "storepass",
    "keypass",
    "authorization",
)

# ---------------------------------------------------------------------------
# MCP Server instance
# ---------------------------------------------------------------------------

app = Server(__app_name__)
SESSION_MANAGER = SessionManager()
RESULT_CACHE = ResultCache()
RATE_LIMITER: RateLimiter | None = None

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
    _safe_import("revula.tools.exploit.pwn_tools")

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


def _is_cacheable_tool(name: str) -> bool:
    """
    Determine whether a tool is safe to cache.

    Fail-closed by default: tools are cacheable only when explicitly opted in
    at registration (`cacheable=True`).
    """
    tool = TOOL_REGISTRY.get(name)
    return bool(tool and tool.cacheable)


# ---------------------------------------------------------------------------
# MCP Handlers
# ---------------------------------------------------------------------------


def _compact_tool_description(description: str, *, max_len: int = 220) -> str:
    """Trim verbose descriptions to concise selection-focused text."""
    condensed = " ".join(description.split())
    if len(condensed) <= max_len:
        return condensed
    sentences = re.split(r"(?<=[.!?])\s+", condensed)
    concise = " ".join(sentences[:2]).strip()
    if concise and len(concise) <= max_len:
        return concise
    return condensed[: max_len - 1].rstrip() + "…"


def _tool_namespace() -> tuple[str, bool]:
    """Resolve public tool namespace and legacy-name exposure policy from config."""
    config = get_config()
    naming = getattr(config, "tool_naming", None)
    namespace = getattr(naming, "namespace", "revula")
    include_legacy = bool(getattr(naming, "include_legacy_names", False))
    return namespace, include_legacy


def _namespaced_tool_name(canonical_name: str, namespace: str) -> str:
    """Map legacy internal names (re_*) to public namespaced names."""
    if canonical_name.startswith("re_"):
        return f"{namespace}_{canonical_name[3:]}"
    if canonical_name.startswith(f"{namespace}_"):
        return canonical_name
    return f"{namespace}_{canonical_name}"


def _resolve_tool_name(requested_name: str) -> str:
    """Resolve client-requested tool name to internal canonical registry name."""
    if TOOL_REGISTRY.get(requested_name):
        return requested_name

    namespace, _ = _tool_namespace()
    prefix = f"{namespace}_"
    if requested_name.startswith(prefix):
        suffix = requested_name[len(prefix) :]
        candidate = f"re_{suffix}"
        if TOOL_REGISTRY.get(candidate):
            return candidate
        if TOOL_REGISTRY.get(suffix):
            return suffix
    return requested_name


@app.list_tools()  # type: ignore[misc,no-untyped-call]
async def list_tools() -> list[Tool]:
    """Return all registered tools as MCP Tool objects."""
    tools: list[Tool] = []
    namespace, include_legacy = _tool_namespace()
    for defn in TOOL_REGISTRY.all():
        namespaced_name = _namespaced_tool_name(defn.name, namespace)
        metadata = {
            "revula": {
                "canonical_name": defn.name,
                "version": defn.version,
                "deprecated": defn.deprecated,
                "replacement": defn.replacement,
                "aliases": defn.aliases,
                "category": defn.category,
            },
        }
        annotations = ToolAnnotations(
            readOnlyHint=defn.annotations.get("readOnlyHint"),
            destructiveHint=defn.annotations.get("destructiveHint"),
            idempotentHint=defn.annotations.get("idempotentHint"),
            openWorldHint=defn.annotations.get("openWorldHint"),
        )
        tools.append(
            Tool(
                name=namespaced_name,
                description=_compact_tool_description(defn.description),
                inputSchema=defn.input_schema,
                outputSchema=defn.output_schema,
                annotations=annotations,
                _meta=metadata,
            )
        )
        if include_legacy and namespaced_name != defn.name:
            legacy_meta = {
                "revula": {
                    **metadata["revula"],
                    "deprecated": True,
                    "replacement": namespaced_name,
                    "legacy_alias": True,
                },
            }
            tools.append(
                Tool(
                    name=defn.name,
                    description=f"[Deprecated alias] Use '{namespaced_name}'.",
                    inputSchema=defn.input_schema,
                    outputSchema=defn.output_schema,
                    annotations=annotations,
                    _meta=legacy_meta,
                )
            )
    return tools


def _extract_payload(result: list[dict[str, Any]]) -> tuple[Any, bool]:
    """Best-effort extraction of structured payload from tool content blocks."""
    if not result:
        return None, False

    if len(result) == 1 and result[0].get("type") == "text":
        text = str(result[0].get("text", ""))
        try:
            return json.loads(text), True
        except json.JSONDecodeError:
            return text, False

    parsed: list[Any] = []
    parsed_all = True
    for item in result:
        if item.get("type") == "text":
            text = str(item.get("text", ""))
            try:
                parsed.append(json.loads(text))
            except json.JSONDecodeError:
                parsed_all = False
                parsed.append(text)
        else:
            parsed_all = False
            parsed.append(item)
    return parsed, parsed_all


def _extract_error_struct(payload: Any) -> dict[str, Any] | None:
    """Extract structured error info from payload if present."""
    if isinstance(payload, dict) and payload.get("error") is True:
        message = str(payload.get("message", "Tool execution failed"))
        code = str(payload.get("code", "tool_error"))
        hint = payload.get("hint")
        return {
            "code": code,
            "message": message,
            "hint": hint if isinstance(hint, str) else None,
        }
    return None


def _is_error_result(result: list[dict[str, Any]]) -> bool:
    """Check whether a raw tool result represents an error."""
    payload, _ = _extract_payload(result)
    return _extract_error_struct(payload) is not None


def _coerce_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    """Coerce a runtime integer argument into a bounded integer."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return minimum
    if maximum is not None and parsed > maximum:
        return maximum
    return parsed


def _apply_pagination(payload: Any, *, offset: int, limit: int) -> tuple[Any, dict[str, Any] | None]:
    """Apply offset/limit pagination to list-like payloads and return metadata."""
    if offset == 0 and limit <= 0:
        return payload, None

    def _meta(total_count: int, sliced_count: int) -> dict[str, Any]:
        has_more = offset + sliced_count < total_count
        return {
            "offset": offset,
            "limit": limit,
            "total_count": total_count,
            "has_more": has_more,
            "next_offset": (offset + sliced_count) if has_more else None,
        }

    if isinstance(payload, list):
        effective_limit = limit if limit > 0 else len(payload)
        sliced = payload[offset : offset + effective_limit]
        return sliced, _meta(len(payload), len(sliced))

    if isinstance(payload, dict):
        preferred_keys = [
            "strings",
            "symbols",
            "gadgets",
            "classes",
            "methods",
            "imports",
            "exports",
            "dex_files",
            "detected_functions",
            "one_gadgets",
            "urls",
            "ips",
            "domains",
        ]

        candidate_key: str | None = next(
            (key for key in preferred_keys if key in payload and isinstance(payload.get(key), list)),
            None,
        )
        if candidate_key is None:
            list_keys = [k for k, value in payload.items() if isinstance(value, list)]
            if len(list_keys) == 1:
                candidate_key = list_keys[0]

        if candidate_key is not None:
            values = list(payload.get(candidate_key, []))
            effective_limit = limit if limit > 0 else len(values)
            sliced = values[offset : offset + effective_limit]
            updated = dict(payload)
            updated[candidate_key] = sliced
            return updated, _meta(len(values), len(sliced))

    return payload, None


def _convert_results(result: list[dict[str, Any]]) -> list[TextContent | EmbeddedResource]:
    """Convert raw dicts to MCP content types."""
    contents: list[TextContent | EmbeddedResource] = []
    for item in result:
        if item.get("type") == "text":
            contents.append(TextContent(type="text", text=str(item.get("text", ""))))
        else:
            contents.append(TextContent(type="text", text=json.dumps(item, default=str)))
    return contents


def _render_markdown(payload: Any, *, error: dict[str, Any] | None, pagination: dict[str, Any] | None) -> str:
    """Render structured payload as markdown."""
    if error is not None:
        lines = [f"**Error ({error['code']}):** {error['message']}"]
        hint = error.get("hint")
        if hint:
            lines.append(f"**Hint:** {hint}")
        return "\n\n".join(lines)

    body = json.dumps(payload, indent=2, default=str)
    if pagination is not None:
        page = json.dumps(pagination, indent=2, default=str)
        return f"```json\n{body}\n```\n\n**Pagination**\n```json\n{page}\n```"
    return f"```json\n{body}\n```"


def _build_call_tool_result(
    raw_result: list[dict[str, Any]],
    *,
    response_format: str,
    offset: int,
    limit: int,
) -> CallToolResult:
    """Convert raw tool output into MCP CallToolResult with structured content."""
    payload, parsed_json = _extract_payload(raw_result)
    payload, pagination = _apply_pagination(payload, offset=offset, limit=limit)
    if pagination is not None:
        if isinstance(payload, dict):
            payload = dict(payload)
            payload.setdefault("pagination", pagination)
        elif isinstance(payload, list):
            payload = {"items": payload, "pagination": pagination}
            parsed_json = True
    error_struct = _extract_error_struct(payload)
    is_error = error_struct is not None

    if response_format == "markdown":
        rendered = _render_markdown(payload, error=error_struct, pagination=pagination)
        content: list[TextContent | EmbeddedResource] = [TextContent(type="text", text=rendered)]
    elif parsed_json:
        content = [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]
    else:
        # Preserve plain-text result fidelity if handler returned raw text.
        content = _convert_results(raw_result)

    structured = {
        "ok": not is_error,
        "data": payload,
        "error": error_struct,
        "pagination": pagination,
    }
    return CallToolResult(
        content=cast("list[Any]", content),
        structuredContent=structured,
        isError=is_error,
    )


def _runtime_context(config: Any) -> ToolExecutionContext:
    """Build per-request runtime context with optional progress callback."""
    progress_token: str | int | None = None
    report_progress = None
    try:
        request_context = app.request_context
        if request_context.meta is not None:
            progress_token = request_context.meta.progressToken
        if progress_token is not None:
            session = request_context.session

            async def _report(progress: float, total: float | None = None, message: str | None = None) -> None:
                await session.send_progress_notification(progress_token, progress, total, message)

            report_progress = _report
    except LookupError:
        report_progress = None

    return ToolExecutionContext(
        config=config,
        session_manager=SESSION_MANAGER,
        progress_token=progress_token,
        report_progress=report_progress,
    )


@app.call_tool()  # type: ignore[misc]
async def call_tool(name: str, arguments: dict[str, Any] | None) -> CallToolResult:
    """Dispatch a tool call to the appropriate handler."""
    if arguments is None:
        arguments = {}
    config = get_config()

    requested_name = name
    name = _resolve_tool_name(name)
    logger.info("Tool call: %s(%s)", requested_name, _truncate_args(arguments))

    response_format = str(arguments.get("response_format", "json")).lower()
    if response_format not in {"json", "markdown"}:
        response_format = "json"
    offset = _coerce_int(arguments.get("offset", 0), default=0, minimum=0)
    limit_value = arguments.get("limit")
    limit = _coerce_int(limit_value, default=100, minimum=1, maximum=1000) if limit_value is not None else 0

    # Rate limiting
    if RATE_LIMITER is not None and not RATE_LIMITER.check(name):
        rate_limited = [
            {
                "type": "text",
                "text": json.dumps(
                    {
                        "error": True,
                        "code": "rate_limit_exceeded",
                        "message": f"Rate limit exceeded for tool '{requested_name}'. Try again shortly.",
                    }
                ),
            }
        ]
        return _build_call_tool_result(
            rate_limited,
            response_format=response_format,
            offset=offset,
            limit=limit,
        )

    runtime_context = _runtime_context(config)
    if runtime_context.report_progress is not None:
        await runtime_context.report_progress(0.0, 1.0, f"Starting {name}")

    exec_args = {key: value for key, value in arguments.items() if key not in {"response_format", "offset", "limit"}}

    cache_key = ""
    cacheable = _is_cacheable_tool(name)

    if cacheable:
        cache_key = ResultCache.make_key(name, exec_args)
        cached = RESULT_CACHE.get(cache_key)
        if cached is not None:
            logger.debug("Cache HIT: %s", name)
            if runtime_context.report_progress is not None:
                await runtime_context.report_progress(1.0, 1.0, f"Completed {name} (cache)")
            return _build_call_tool_result(
                cached,
                response_format=response_format,
                offset=offset,
                limit=limit,
            )

    result = await TOOL_REGISTRY.execute(name, exec_args, runtime_context=runtime_context)

    # Cache successful deterministic results.
    if cacheable and cache_key and not _is_error_result(result):
        RESULT_CACHE.put(cache_key, result)

    if runtime_context.report_progress is not None:
        await runtime_context.report_progress(1.0, 1.0, f"Completed {name}")

    return _build_call_tool_result(
        result,
        response_format=response_format,
        offset=offset,
        limit=limit,
    )


@app.list_resources()  # type: ignore[misc,no-untyped-call]
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


@app.list_resource_templates()  # type: ignore[misc,no-untyped-call]
async def list_resource_templates() -> list[ResourceTemplate]:
    """Expose first-class binary resource templates."""
    return [
        ResourceTemplate(
            name="revula_binary_by_sha256",
            uriTemplate="binary://{sha256}",
            description="Read a previously registered binary by SHA-256 URI.",
            mimeType="application/octet-stream",
        ),
    ]


@app.read_resource()  # type: ignore[misc,no-untyped-call]
async def read_resource(uri: str) -> bytes:
    """Read the content of a binary resource."""
    return await SESSION_MANAGER.read_resource(uri)


PROMPT_TEMPLATES: dict[str, dict[str, Any]] = {
    "revula_analyze_malware_binary": {
        "description": "Guide a full malware triage workflow over a binary sample.",
        "arguments": [
            PromptArgument(name="binary_path", description="Absolute path to the binary sample.", required=True),
        ],
        "render": lambda args: (
            "You are performing malware triage with Revula.\n"
            f"Target binary: {args.get('binary_path', '<missing>')}\n\n"
            "Steps:\n"
            "1. Register the binary as a resource.\n"
            "2. Run static triage, strings, entropy, and symbol extraction.\n"
            "3. Extract malware configuration and indicators.\n"
            "4. Summarize risk, families/TTP hints, and prioritized next actions."
        ),
    },
    "revula_find_buffer_overflow": {
        "description": "Drive a memory-corruption audit for overflow primitives.",
        "arguments": [
            PromptArgument(name="binary_path", description="Absolute path to target binary.", required=True),
        ],
        "render": lambda args: (
            "Audit this target for buffer overflow vulnerabilities.\n"
            f"Binary: {args.get('binary_path', '<missing>')}\n\n"
            "Use Revula tools to:\n"
            "1. Parse binary protections (NX/PIE/RELRO/canary cues).\n"
            "2. Identify unsafe functions and suspicious code paths.\n"
            "3. Disassemble likely vulnerable routines.\n"
            "4. Produce exploitation feasibility notes and mitigation advice."
        ),
    },
    "revula_build_rop_chain_execve": {
        "description": "Generate a practical ROP workflow for execve('/bin/sh').",
        "arguments": [
            PromptArgument(name="binary_path", description="Absolute path to target binary.", required=True),
        ],
        "render": lambda args: (
            "Build a ROP exploitation plan for execve('/bin/sh').\n"
            f"Binary: {args.get('binary_path', '<missing>')}\n\n"
            "Process:\n"
            "1. Enumerate gadgets with constraints (bad chars, arch).\n"
            "2. Build chain candidates and show gadget rationale.\n"
            "3. Provide pwntools-friendly payload scaffolding.\n"
            "4. List assumptions and constraints to validate at runtime."
        ),
    },
}


@app.list_prompts()  # type: ignore[misc,no-untyped-call]
async def list_prompts() -> list[Prompt]:
    """List reusable MCP prompt templates for common RE workflows."""
    prompts: list[Prompt] = []
    for name, template in PROMPT_TEMPLATES.items():
        prompts.append(
            Prompt(
                name=name,
                description=template["description"],
                arguments=template["arguments"],
            )
        )
    return prompts


@app.get_prompt()  # type: ignore[misc,no-untyped-call]
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    """Render a named prompt template with optional arguments."""
    template = PROMPT_TEMPLATES.get(name)
    if template is None:
        raise ValueError(f"Unknown prompt template: {name}")
    args = arguments or {}
    message = template["render"](args)
    return GetPromptResult(
        description=template["description"],
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text=message),
            )
        ],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_args(args: dict[str, Any], max_len: int = 200) -> str:
    """Truncate arguments for logging (avoid logging huge binary data)."""
    sanitized: dict[str, Any] = {}
    for k, v in args.items():
        if k.startswith("__"):
            continue
        key_lc = k.lower()
        if any(marker in key_lc for marker in SENSITIVE_ARG_MARKERS):
            sanitized[k] = "<redacted>"
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
    global RATE_LIMITER
    RATE_LIMITER = RateLimiter(
        RateLimitConfig(
            global_rpm=config.rate_limit.global_rpm,
            per_tool_rpm=config.rate_limit.per_tool_rpm,
            burst_size=config.rate_limit.burst_size,
            enabled=config.rate_limit.enabled,
        )
    )
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
