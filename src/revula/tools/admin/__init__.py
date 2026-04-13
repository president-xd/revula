"""
Revula Admin Tools — server introspection and management tools.

Provides tools for cache management, rate-limit monitoring, and server health.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from pathlib import Path
from typing import Any

from revula import __version__
from revula.sandbox import validate_binary_path
from revula.session import BinaryResource
from revula.tools import TOOL_REGISTRY, error_result, text_result

# ---------------------------------------------------------------------------
# re_admin_status — server health / summary
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_admin_status",
    description=(
        "Return Revula server health and configuration summary. "
        "Shows version, Python info, registered tools, cache and rate-limit stats."
    ),
    input_schema={
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    category="admin",
)
async def _admin_status(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    from revula.server import RATE_LIMITER, RESULT_CACHE

    config = arguments.get("__config__")
    available_count = 0
    tool_namespace = "revula"
    include_legacy = False
    if config is not None:
        available_count = sum(1 for ti in config.tools.values() if ti.available)
        naming = getattr(config, "tool_naming", None)
        if naming is not None:
            tool_namespace = naming.namespace
            include_legacy = naming.include_legacy_names

    info: dict[str, Any] = {
        "version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.system(),
        "tools_registered": TOOL_REGISTRY.count(),
        "categories": sorted({t.category for t in TOOL_REGISTRY.all()}),
        "cache": RESULT_CACHE.stats(),
        "rate_limit": RATE_LIMITER.stats() if RATE_LIMITER is not None else {"enabled": False},
        "available_ext_tool_count": available_count,
        "tool_namespace": tool_namespace,
        "legacy_tool_names_exposed": include_legacy,
    }
    return text_result(info)


# ---------------------------------------------------------------------------
# re_admin_cache — cache management
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_admin_cache",
    description=(
        "Manage the result cache. Actions: stats (show cache stats), "
        "clear (flush all entries), invalidate (remove one entry by key)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["stats", "clear", "invalidate"],
                "description": "Cache management action",
            },
            "key": {
                "type": "string",
                "description": "Cache key to invalidate (only for 'invalidate' action)",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    category="admin",
)
async def _admin_cache(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    from revula.server import RESULT_CACHE

    action = arguments.get("action", "stats")

    if action == "stats":
        return text_result(RESULT_CACHE.stats())
    elif action == "clear":
        RESULT_CACHE.clear()
        return text_result({"status": "cache cleared"})
    elif action == "invalidate":
        key = arguments.get("key", "")
        if not key:
            return error_result("key is required for invalidate action", code="invalid_arguments")
        RESULT_CACHE.invalidate(key)
        return text_result({"status": f"invalidated key: {key}"})
    else:
        return error_result(f"unknown action: {action}", code="invalid_arguments")


@TOOL_REGISTRY.register(
    name="re_register_binary",
    description=(
        "Register a local binary path as a first-class MCP resource and return a stable "
        "binary://<sha256> URI that can be consumed via resources/read."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file to register as an MCP resource.",
            },
            "resource_name": {
                "type": "string",
                "description": "Optional display name for the resource. Default: file name.",
            },
        },
        "required": ["binary_path"],
        "additionalProperties": False,
    },
    category="admin",
)
async def _register_binary(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Register a binary as an MCP resource for resource-first workflows."""
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(arguments["binary_path"], allowed_dirs=allowed_dirs)

    session_manager = arguments.get("__session_manager__")
    if session_manager is None:
        return error_result("Session manager is unavailable.", code="internal_error")

    data = file_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    uri = f"binary://{sha256}"
    resource_name = arguments.get("resource_name") or Path(file_path).name

    resource = BinaryResource(
        uri=uri,
        name=resource_name,
        path=file_path,
        size=len(data),
        hashes={"sha256": sha256},
    )
    await session_manager.register_resource(resource)

    return text_result(
        {
            "resource_uri": uri,
            "resource_name": resource_name,
            "binary_path": str(file_path),
            "size": len(data),
            "hashes": {"sha256": sha256},
        }
    )
