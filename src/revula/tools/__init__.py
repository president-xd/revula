"""
Revula Tool Registry — centralized MCP tool registration and validation.

This module owns:
- Tool metadata (schemas, annotations, versioning/deprecation metadata)
- Argument validation (Pydantic-first with JSON Schema fallback)
- Safe dispatch with structured errors
- Schema normalization (strict additionalProperties + shared options)
"""

from __future__ import annotations

import copy
import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    create_model,
)
from pydantic import (
    ValidationError as PydanticValidationError,
)

logger = logging.getLogger(__name__)

# A tool handler is an async function receiving (arguments) or (arguments, runtime_context)
ToolHandler = Callable[..., Coroutine[Any, Any, list[dict[str, Any]]]]

DEFAULT_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "data": {},
        "error": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "hint": {"type": ["string", "null"]},
                    },
                    "required": ["code", "message"],
                    "additionalProperties": False,
                },
            ],
        },
        "pagination": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "minimum": 0},
                        "limit": {"type": "integer", "minimum": 1},
                        "total_count": {"type": "integer", "minimum": 0},
                        "has_more": {"type": "boolean"},
                        "next_offset": {"type": ["integer", "null"], "minimum": 0},
                    },
                    "required": ["offset", "limit", "total_count", "has_more", "next_offset"],
                    "additionalProperties": False,
                },
            ],
        },
    },
    "required": ["ok", "data", "error"],
    "additionalProperties": False,
}

COMMON_INPUT_PROPERTIES: dict[str, Any] = {
    "response_format": {
        "type": "string",
        "enum": ["json", "markdown"],
        "default": "json",
        "description": "Output format. Use json for machine consumption or markdown for human-readable output.",
    },
    "offset": {
        "type": "integer",
        "minimum": 0,
        "default": 0,
        "description": "Pagination offset for list-like outputs.",
    },
    "limit": {
        "type": "integer",
        "minimum": 1,
        "maximum": 1000,
        "default": 100,
        "description": "Pagination limit for list-like outputs.",
    },
}


@dataclass
class ToolExecutionContext:
    """Runtime context passed alongside tool arguments."""

    config: Any
    session_manager: Any
    progress_token: str | int | None = None
    report_progress: Callable[[float, float | None, str | None], Awaitable[None]] | None = None


class RuntimeArguments(dict[str, Any]):
    """Argument view exposing runtime context via reserved keys without mutating user args."""

    def __init__(self, user_arguments: dict[str, Any], context: ToolExecutionContext | None) -> None:
        super().__init__(user_arguments)
        self._context = context

    def _runtime_value(self, key: str) -> Any:
        if self._context is None:
            return None
        if key == "__context__":
            return self._context
        if key == "__config__":
            return self._context.config
        if key == "__session_manager__":
            return self._context.session_manager
        if key == "__progress__":
            return self._context.report_progress
        return None

    def get(self, key: str, default: Any = None) -> Any:
        if key.startswith("__"):
            value = self._runtime_value(key)
            return default if value is None else value
        return super().get(key, default)

    def __getitem__(self, key: str) -> Any:
        if key.startswith("__"):
            value = self._runtime_value(key)
            if value is None:
                raise KeyError(key)
            return value
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str) and key.startswith("__"):
            return self._runtime_value(key) is not None
        return super().__contains__(key)


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
    cacheable: bool = False
    annotations: dict[str, bool] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    version: str = "1.0.0"
    deprecated: bool = False
    replacement: str | None = None
    aliases: list[str] = field(default_factory=list)
    input_model: type[BaseModel] | None = None

    def to_mcp_tool(self) -> dict[str, Any]:
        """Convert to MCP Tool format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "annotations": self.annotations,
            "meta": {
                "revula": {
                    "version": self.version,
                    "deprecated": self.deprecated,
                    "replacement": self.replacement,
                    "aliases": self.aliases,
                },
            },
        }


def _build_error_payload(
    message: str,
    *,
    code: str = "tool_error",
    hint: str | None = None,
) -> dict[str, Any]:
    """Create a structured, protocol-friendly tool error payload."""
    payload: dict[str, Any] = {
        "error": True,
        "code": code,
        "message": message,
    }
    if hint:
        payload["hint"] = hint
    return payload


def _error_content(
    message: str,
    *,
    code: str = "tool_error",
    hint: str | None = None,
) -> dict[str, Any]:
    """Create an error TextContent block."""
    return {
        "type": "text",
        "text": json.dumps(_build_error_payload(message, code=code, hint=hint)),
    }


class ToolRegistry:
    """Central registry for all Revula tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._model_cache: dict[str, type[BaseModel] | None] = {}

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
        cacheable: bool | None = None,
        annotations: dict[str, bool] | None = None,
        output_schema: dict[str, Any] | None = None,
        version: str = "1.0.0",
        deprecated: bool = False,
        replacement: str | None = None,
        aliases: list[str] | None = None,
        input_model: type[BaseModel] | None = None,
    ) -> Callable[[ToolHandler], ToolHandler]:
        """Decorator to register a tool handler."""

        def decorator(func: ToolHandler) -> ToolHandler:
            if not inspect.iscoroutinefunction(func):
                raise TypeError(f"Tool handler '{name}' must be an async function")

            if name in self._tools:
                raise ValueError(f"Duplicate tool registration attempted: {name}")

            normalized_schema = self._normalize_input_schema(input_schema)
            resolved_annotations = self._resolve_annotations(
                name=name,
                category=category,
                description=description,
                requires_tools=requires_tools or [],
                overrides=annotations,
            )
            resolved_cacheable = self._resolve_cacheable(cacheable, resolved_annotations)

            self._tools[name] = ToolDefinition(
                name=name,
                description=description.strip(),
                input_schema=normalized_schema,
                handler=func,
                category=category,
                requires_tools=requires_tools or [],
                requires_modules=requires_modules or [],
                streaming=streaming,
                cacheable=resolved_cacheable,
                annotations=resolved_annotations,
                output_schema=copy.deepcopy(output_schema or DEFAULT_OUTPUT_SCHEMA),
                version=version,
                deprecated=deprecated,
                replacement=replacement,
                aliases=aliases or [],
                input_model=input_model,
            )

            logger.debug(
                "Registered tool: %s (category=%s cacheable=%s)",
                name,
                category,
                resolved_cacheable,
            )
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

    async def execute(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        runtime_context: ToolExecutionContext | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a tool by name with validated arguments.

        Returns MCP content blocks (TextContent/EmbeddedResource dicts).
        """
        tool = self._tools.get(name)
        if tool is None:
            return [_error_content(f"Unknown tool: {name}", code="unknown_tool")]

        validation_error, validated_args = self._validate_arguments(tool, arguments)
        if validation_error is not None:
            return [_error_content(validation_error, code="invalid_arguments")]

        # Check Python module availability
        for mod in tool.requires_modules:
            try:
                __import__(mod)
            except ImportError:
                from revula.config import PYTHON_MODULES

                hint = PYTHON_MODULES.get(mod, f"pip install {mod}")
                return [
                    _error_content(
                        f"Required Python module '{mod}' is not installed.",
                        code="missing_python_module",
                        hint=hint,
                    ),
                ]

        # Check external tool availability
        if tool.requires_tools:
            from revula.config import get_config

            config = runtime_context.config if runtime_context else get_config()
            for ext_tool in tool.requires_tools:
                if not config.is_available(ext_tool):
                    info = config.tools.get(ext_tool)
                    install_hint = info.install_hint if info else None
                    return [
                        _error_content(
                            f"Required external tool '{ext_tool}' is not available.",
                            code="tool_unavailable",
                            hint=install_hint,
                        ),
                    ]

        runtime_args = RuntimeArguments(validated_args, runtime_context)

        # Execute handler
        try:
            signature = inspect.signature(tool.handler)
            if len(signature.parameters) >= 2:
                result = await tool.handler(runtime_args, runtime_context)
            else:
                result = await tool.handler(runtime_args)
            if not isinstance(result, list):
                result = [{"type": "text", "text": str(result)}]
            return result
        except Exception as e:
            from revula.config import ToolNotAvailableError

            if isinstance(e, ToolNotAvailableError):
                return [
                    _error_content(
                        f"Required external tool '{e.tool_name}' is not available.",
                        code="tool_unavailable",
                        hint=e.install_hint or None,
                    )
                ]
            logger.exception("Error executing tool %s", name)
            return [
                _error_content(
                    f"Tool '{name}' failed: {type(e).__name__}: {e}",
                    code="tool_execution_failed",
                ),
            ]

    def _validate_arguments(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        """Validate tool call arguments, returning (error, validated_args)."""
        user_arguments = {
            key: value for key, value in arguments.items() if not (isinstance(key, str) and key.startswith("__"))
        }

        pydantic_model = tool.input_model if tool.input_model is not None else self._build_pydantic_model(tool)
        if pydantic_model is not None:
            try:
                validated = pydantic_model.model_validate(user_arguments)
                return None, validated.model_dump()
            except PydanticValidationError as err:
                first = err.errors()[0]
                location = "$"
                if first.get("loc"):
                    location += "." + ".".join(str(part) for part in first["loc"])
                msg = first.get("msg", "Invalid input")
                return f"Invalid arguments for tool '{tool.name}' at {location}: {msg}", user_arguments

        try:
            Draft202012Validator.check_schema(tool.input_schema)
            validator = Draft202012Validator(tool.input_schema)
            errors = sorted(
                validator.iter_errors(user_arguments),
                key=lambda validation_error: list(validation_error.path),
            )
            if not errors:
                return None, user_arguments

            first_error = errors[0]
            location = "$"
            if first_error.absolute_path:
                location += "." + ".".join(str(part) for part in first_error.absolute_path)

            return (
                f"Invalid arguments for tool '{tool.name}' at {location}: {first_error.message}",
                user_arguments,
            )
        except SchemaError as err:
            logger.error("Invalid input_schema for tool %s: %s", tool.name, err)
            return (
                f"Tool '{tool.name}' has an invalid input schema: {err.message}",
                user_arguments,
            )
        except ValidationError as err:
            location = "$"
            if err.absolute_path:
                location += "." + ".".join(str(part) for part in err.absolute_path)
            return (
                f"Invalid arguments for tool '{tool.name}' at {location}: {err.message}",
                user_arguments,
            )

    def _build_pydantic_model(self, tool: ToolDefinition) -> type[BaseModel] | None:
        """Create a Pydantic model from a JSON schema when feasible."""
        if tool.name in self._model_cache:
            return self._model_cache[tool.name]

        schema = tool.input_schema
        if schema.get("type") != "object" or not isinstance(schema.get("properties"), dict):
            self._model_cache[tool.name] = None
            return None

        properties_raw = schema.get("properties", {})
        if not isinstance(properties_raw, dict):
            self._model_cache[tool.name] = None
            return None
        properties: dict[str, Any] = properties_raw

        required_raw = schema.get("required", [])
        required = set(required_raw) if isinstance(required_raw, list) else set()
        extra_mode: Literal["allow", "forbid"] = "forbid" if schema.get("additionalProperties") is False else "allow"

        fields: dict[str, tuple[Any, Any]] = {}
        try:
            for prop_name, prop_schema_any in properties.items():
                if not isinstance(prop_schema_any, dict):
                    continue
                prop_schema = prop_schema_any
                annotation = self._schema_type_to_python(prop_schema)
                default: Any = ... if prop_name in required else prop_schema.get("default", None)

                field_kwargs: dict[str, Any] = {}
                if isinstance(prop_schema.get("minimum"), int | float):
                    field_kwargs["ge"] = prop_schema["minimum"]
                if isinstance(prop_schema.get("maximum"), int | float):
                    field_kwargs["le"] = prop_schema["maximum"]
                if isinstance(prop_schema.get("minLength"), int):
                    field_kwargs["min_length"] = prop_schema["minLength"]
                if isinstance(prop_schema.get("maxLength"), int):
                    field_kwargs["max_length"] = prop_schema["maxLength"]
                if isinstance(prop_schema.get("pattern"), str):
                    field_kwargs["pattern"] = prop_schema["pattern"]
                if isinstance(prop_schema.get("description"), str):
                    field_kwargs["description"] = prop_schema["description"]

                fields[prop_name] = (annotation, Field(default=default, **field_kwargs))

            model = create_model(
                f"ToolInput_{tool.name}",
                __config__=ConfigDict(extra=extra_mode),
                **fields,  # type: ignore[call-overload]
            )
            typed_model = cast("type[BaseModel]", model)
            self._model_cache[tool.name] = typed_model
            return typed_model
        except Exception as err:
            logger.debug("Could not build Pydantic model for %s: %s", tool.name, err)
            self._model_cache[tool.name] = None
            return None

    def _schema_type_to_python(self, prop_schema: dict[str, Any]) -> Any:
        """Map a JSON schema property to a Python type annotation."""
        if "enum" in prop_schema and isinstance(prop_schema["enum"], list):
            enum_values = tuple(prop_schema["enum"])
            if enum_values:
                first = enum_values[0]
                if isinstance(first, str):
                    return str
                if isinstance(first, bool):
                    return bool
                if isinstance(first, int):
                    return int
                if isinstance(first, float):
                    return float
                return Any

        schema_type = prop_schema.get("type")
        if schema_type == "string":
            return str
        if schema_type == "integer":
            return int
        if schema_type == "number":
            return float
        if schema_type == "boolean":
            return bool
        if schema_type == "array":
            return list[Any]
        if schema_type == "object":
            return dict[str, Any]
        return Any

    def _normalize_input_schema(self, input_schema: dict[str, Any]) -> dict[str, Any]:
        """Harden and standardize input schemas at registration time."""
        schema = copy.deepcopy(input_schema)
        self._enforce_object_additional_properties(schema)
        self._inject_common_schema_properties(schema)
        self._apply_property_constraints(schema)
        return schema

    def _enforce_object_additional_properties(self, schema: Any) -> None:
        """Recursively set additionalProperties=false for object schemas unless explicitly set."""
        if isinstance(schema, dict):
            schema_type = schema.get("type")
            if schema_type == "object" and "additionalProperties" not in schema:
                schema["additionalProperties"] = False

            for key in ("properties", "$defs", "definitions", "patternProperties"):
                nested = schema.get(key)
                if isinstance(nested, dict):
                    for value in nested.values():
                        self._enforce_object_additional_properties(value)

            for key in ("items", "contains", "additionalProperties"):
                if key in schema:
                    self._enforce_object_additional_properties(schema[key])

            for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
                nested_list = schema.get(key)
                if isinstance(nested_list, list):
                    for item in nested_list:
                        self._enforce_object_additional_properties(item)
        elif isinstance(schema, list):
            for item in schema:
                self._enforce_object_additional_properties(item)

    def _inject_common_schema_properties(self, schema: dict[str, Any]) -> None:
        """Inject shared top-level schema properties used across tools."""
        if schema.get("type") != "object":
            return
        props = schema.setdefault("properties", {})
        if not isinstance(props, dict):
            return
        for key, value in COMMON_INPUT_PROPERTIES.items():
            props.setdefault(key, copy.deepcopy(value))

    def _apply_property_constraints(self, schema: Any) -> None:
        """Apply critical safety constraints to known dangerous/large fields."""
        if not isinstance(schema, dict):
            return

        properties = schema.get("properties")
        if isinstance(properties, dict):
            rules_inline = properties.get("rules_inline")
            if isinstance(rules_inline, dict):
                rules_inline.setdefault("maxLength", 200_000)
                rules_inline.setdefault("minLength", 1)

            code_prop = properties.get("code")
            if isinstance(code_prop, dict):
                code_prop.setdefault("maxLength", 1_048_576)
                code_prop.setdefault("minLength", 1)

            bad_chars = properties.get("bad_chars")
            if isinstance(bad_chars, dict):
                bad_chars.setdefault("pattern", r"^(?:[0-9a-fA-F]{2})*$")
                bad_chars.setdefault("maxLength", 512)

            limit_prop = properties.get("limit")
            if isinstance(limit_prop, dict):
                limit_prop.setdefault("minimum", 1)
                limit_prop.setdefault("maximum", 10000)

            offset_prop = properties.get("offset")
            if isinstance(offset_prop, dict):
                offset_prop.setdefault("minimum", 0)

            for path_key in ("binary_path", "apk_path", "firmware_path", "pcap_path"):
                path_prop = properties.get(path_key)
                if isinstance(path_prop, dict):
                    path_prop.setdefault("minLength", 1)
                    path_prop.setdefault("maxLength", 4096)

            for value in properties.values():
                self._apply_property_constraints(value)

        for key in ("items", "contains", "additionalProperties"):
            if key in schema:
                self._apply_property_constraints(schema[key])
        for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
            nested = schema.get(key)
            if isinstance(nested, list):
                for item in nested:
                    self._apply_property_constraints(item)

    def _resolve_annotations(
        self,
        *,
        name: str,
        category: str,
        description: str,
        requires_tools: list[str],
        overrides: dict[str, bool] | None,
    ) -> dict[str, bool]:
        """Infer MCP tool safety annotations and merge explicit overrides."""
        destructive_markers = (
            "patch",
            "write",
            "delete",
            "unpack",
            "repack",
            "inject",
            "spawn",
            "launch",
            "attach",
            "hook",
            "fuzz",
            "memory_write",
            "continue",
            "step",
            "resume",
            "shellcode_generate",
            "bp_set",
            "bp_delete",
            "traffic_intercept",
            "qemu_run",
        )
        open_world_markers = (
            "sandbox",
            "network",
            "traffic",
            "frida",
            "adb",
            "qemu",
            "vt_",
            "hybrid",
            "bazaar",
            "admin",
        )

        name_lc = name.lower()
        desc_lc = description.lower()

        destructive = any(marker in name_lc for marker in destructive_markers)
        if "modify" in desc_lc or "patch" in desc_lc:
            destructive = True

        read_only = not destructive
        if category in {"dynamic", "android", "platform"}:
            read_only = False
        if "action" in desc_lc and category in {"admin", "protocol"}:
            read_only = False

        open_world = category in {"dynamic", "android", "protocol", "platform", "admin"}
        if any(marker in name_lc for marker in open_world_markers):
            open_world = True

        idempotent = read_only and not destructive and not open_world

        annotations: dict[str, bool] = {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world,
        }

        if overrides:
            annotations.update(overrides)
        return annotations

    def _resolve_cacheable(
        self,
        explicit: bool | None,
        annotations: dict[str, bool],
    ) -> bool:
        """Resolve cacheability from explicit flag or safe deterministic defaults."""
        if explicit is not None:
            return explicit
        return bool(
            annotations.get("readOnlyHint")
            and annotations.get("idempotentHint")
            and not annotations.get("destructiveHint")
            and not annotations.get("openWorldHint")
        )


def text_result(data: Any) -> list[dict[str, Any]]:
    """Helper: wrap a JSON-serializable result as MCP TextContent."""
    if isinstance(data, str):
        return [{"type": "text", "text": data}]
    return [{"type": "text", "text": json.dumps(data, indent=2, default=str)}]


def error_result(
    message: str,
    *,
    code: str = "tool_error",
    hint: str | None = None,
) -> list[dict[str, Any]]:
    """Helper: create a structured error result."""
    return [_error_content(message, code=code, hint=hint)]


# ---------------------------------------------------------------------------
# Global registry instance
# ---------------------------------------------------------------------------

TOOL_REGISTRY = ToolRegistry()
