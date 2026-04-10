"""
Revula Tool Registry — decorator-based tool registration with schema validation.

Each tool module uses @register_tool() to declare MCP tools. The registry:
- Stores tool metadata (name, description, input schema)
- Maps tool names to async handler functions
- Validates arguments against JSON Schema before dispatch
- Provides graceful error handling with structured error responses
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

# A tool handler is an async function: (arguments: dict) -> list[content]
ToolHandler = Callable[[dict[str, Any]], Coroutine[Any, Any, list[dict[str, Any]]]]


@dataclass
class ToolDefinition:
    """Complete definition of an MCP tool."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler
    category: str = "general"
    requires_tools: list[str] = field(default_factory=list)
    requires_modules: list[str] = field(default_factory=list)
    streaming: bool = False

    def to_mcp_tool(self) -> dict[str, Any]:
        """Convert to MCP Tool format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """Central registry for all Revula tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        *,
        category: str = "general",
        requires_tools: list[str] | None = None,
        requires_modules: list[str] | None = None,
        streaming: bool = False,
    ) -> Callable[[ToolHandler], ToolHandler]:
        """
        Decorator to register a tool handler.

        Usage:
            @registry.register(
                name="re_disassemble",
                description="Disassemble binary code...",
                input_schema={...},
                category="static",
                requires_modules=["capstone"],
            )
            async def handle_disassemble(arguments: dict) -> list[dict]:
                ...
        """

        def decorator(func: ToolHandler) -> ToolHandler:
            if not inspect.iscoroutinefunction(func):
                raise TypeError(f"Tool handler '{name}' must be an async function")

            if name in self._tools:
                logger.warning("Overwriting existing tool registration: %s", name)

            self._tools[name] = ToolDefinition(
                name=name,
                description=description,
                input_schema=input_schema,
                handler=func,
                category=category,
                requires_tools=requires_tools or [],
                requires_modules=requires_modules or [],
                streaming=streaming,
            )

            logger.debug("Registered tool: %s (category=%s)", name, category)
            return func

        return decorator

    def get(self, name: str) -> ToolDefinition | None:
        """Get a tool definition by name."""
        return self._tools.get(name)

    def all(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        return list(self._tools.values())

    def by_category(self, category: str) -> list[ToolDefinition]:
        """Get tools filtered by category."""
        return [t for t in self._tools.values() if t.category == category]

    def names(self) -> list[str]:
        """Get all registered tool names."""
        return list(self._tools.keys())

    def count(self) -> int:
        """Get total number of registered tools."""
        return len(self._tools)

    async def execute(self, name: str, arguments: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Execute a tool by name with the given arguments.

        Returns MCP content blocks (TextContent or BlobContent dicts).
        Handles errors gracefully — never crashes, always returns structured errors.
        """
        tool = self._tools.get(name)
        if tool is None:
            return [_error_content(f"Unknown tool: {name}")]

        # Validate user-provided arguments against tool JSON schema.
        # Internal runtime-injected args (e.g., __config__) are excluded.
        validation_error = self._validate_arguments(tool, arguments)
        if validation_error is not None:
            return [_error_content(validation_error)]

        # Check module availability
        for mod in tool.requires_modules:
            try:
                __import__(mod)
            except ImportError:
                from revula.config import PYTHON_MODULES

                hint = PYTHON_MODULES.get(mod, f"pip install {mod}")
                return [
                    _error_content(
                        f"Required Python module '{mod}' is not installed. "
                        f"Install it with: {hint}"
                    )
                ]

        # Check external tool availability
        if tool.requires_tools:
            from revula.config import get_config

            config = get_config()
            for ext_tool in tool.requires_tools:
                if not config.is_available(ext_tool):
                    info = config.tools.get(ext_tool)
                    hint = info.install_hint if info else ""
                    return [
                        _error_content(
                            f"Required external tool '{ext_tool}' is not installed. "
                            f"{hint}"
                        )
                    ]

        # Execute handler
        try:
            result = await tool.handler(arguments)
            if not isinstance(result, list):
                result = [{"type": "text", "text": str(result)}]
            return result
        except Exception as e:
            logger.exception("Error executing tool %s", name)
            return [_error_content(f"Tool '{name}' failed: {type(e).__name__}: {e}")]

    def _validate_arguments(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
    ) -> str | None:
        """Validate tool call arguments and return an error message on failure."""
        user_arguments = {
            key: value
            for key, value in arguments.items()
            if not (isinstance(key, str) and key.startswith("__"))
        }

        try:
            Draft202012Validator.check_schema(tool.input_schema)
            validator = Draft202012Validator(tool.input_schema)
            errors = sorted(
                validator.iter_errors(user_arguments),
                key=lambda err: list(err.path),
            )
            if not errors:
                return None

            err = errors[0]
            location = "$"
            if err.absolute_path:
                location += "." + ".".join(str(part) for part in err.absolute_path)

            return (
                f"Invalid arguments for tool '{tool.name}' at {location}: {err.message}"
            )
        except SchemaError as err:
            logger.error("Invalid input_schema for tool %s: %s", tool.name, err)
            return (
                f"Tool '{tool.name}' has an invalid input schema: {err.message}"
            )
        except ValidationError as err:
            location = "$"
            if err.absolute_path:
                location += "." + ".".join(str(part) for part in err.absolute_path)
            return (
                f"Invalid arguments for tool '{tool.name}' at {location}: {err.message}"
            )


def _error_content(message: str) -> dict[str, Any]:
    """Create an error TextContent block."""
    return {
        "type": "text",
        "text": json.dumps({"error": True, "message": message}),
    }


def text_result(data: Any) -> list[dict[str, Any]]:
    """Helper: wrap a JSON-serializable result as MCP TextContent."""
    if isinstance(data, str):
        return [{"type": "text", "text": data}]
    return [{"type": "text", "text": json.dumps(data, indent=2, default=str)}]


def error_result(message: str) -> list[dict[str, Any]]:
    """Helper: create a structured error result."""
    return [_error_content(message)]


# ---------------------------------------------------------------------------
# Global registry instance
# ---------------------------------------------------------------------------

TOOL_REGISTRY = ToolRegistry()
