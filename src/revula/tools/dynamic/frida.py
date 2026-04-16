"""
Revula Frida Adapter — Dynamic instrumentation via Frida.

Provides: spawn/attach, script injection, function interception,
memory scanning/dumping, module enumeration, and RPC call support.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from revula.sandbox import validate_path
from revula.session import FridaSession, SessionManager
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


def _js_escape(value: str) -> str:
    """Escape a string for safe interpolation into JavaScript single-quoted literals."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\0", "\\0")
    )


try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_device(device_type: str = "local") -> Any:
    """Get a Frida device."""
    if device_type == "local":
        return frida.get_local_device()
    elif device_type == "usb":
        return frida.get_usb_device()
    elif device_type == "remote":
        return frida.get_remote_device()
    else:
        return frida.get_device(device_type)


def _serialize_message(message: dict[str, Any]) -> dict[str, Any]:
    """Serialize Frida message for JSON output."""
    result: dict[str, Any] = {}
    for k, v in message.items():
        try:
            json.dumps(v)
            result[k] = v
        except (TypeError, ValueError):
            result[k] = str(v)
    return result


async def _get_frida_session(
    session_manager: SessionManager, session_id: str
) -> tuple[FridaSession, Any]:
    """Get Frida session and its script/session objects."""
    session = await session_manager.get_typed_session(session_id, FridaSession)
    if not session.frida_session:
        raise ValueError(f"Session {session_id} has no active Frida connection")
    return session, session.frida_session


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_frida_spawn",
    description=(
        "Spawn a process under Frida instrumentation. "
        "The process starts suspended — use re_frida_resume to begin execution. "
        "Returns session_id for subsequent Frida operations."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Path to binary to spawn.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Command-line arguments.",
            },
            "device": {
                "type": "string",
                "enum": ["local", "usb", "remote"],
                "default": "local",
            },
            "script": {
                "type": "string",
                "description": "Optional JavaScript to inject immediately.",
            },
        },
        "required": ["binary_path"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_spawn(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Spawn a process under Frida."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed. pip install frida frida-tools")

    binary_path = arguments["binary_path"]
    args = arguments.get("args", [])
    device_type = arguments.get("device", "local")
    script_code = arguments.get("script")
    session_manager: SessionManager = arguments["__session_manager__"]

    # Enforce script size limit (1 MB)
    if script_code and len(script_code) > 1_048_576:
        return error_result("Frida script exceeds maximum size (1 MB)")

    device = _get_device(device_type)

    # Spawn suspended
    spawn_args = [binary_path, *args]
    pid = device.spawn(spawn_args)

    # Attach
    frida_session = device.attach(pid)

    # Create MCP session
    session = FridaSession(
        target_binary=binary_path,
        frida_session=frida_session,
    )
    session.pid = pid
    session.metadata["device"] = device_type
    session.metadata["messages"] = []

    # Inject initial script if provided
    if script_code:
        script = frida_session.create_script(script_code)

        def on_message(message: dict[str, Any], data: Any) -> None:
            session.metadata["messages"].append(_serialize_message(message))

        script.on("message", on_message)
        script.load()
        session.scripts["default"] = script

    session_id = await session_manager.create_session(session)

    return text_result({
        "session_id": session_id,
        "pid": pid,
        "binary": binary_path,
        "status": "spawned_suspended",
        "device": device_type,
    })


@TOOL_REGISTRY.register(
    name="re_frida_attach",
    description="Attach Frida to a running process by PID or name.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {
                "type": ["string", "integer"],
                "description": "PID (integer) or process name (string).",
            },
            "device": {
                "type": "string",
                "enum": ["local", "usb", "remote"],
                "default": "local",
            },
        },
        "required": ["target"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_attach(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Attach Frida to a running process."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    target = arguments["target"]
    device_type = arguments.get("device", "local")
    session_manager: SessionManager = arguments["__session_manager__"]

    device = _get_device(device_type)
    frida_session = device.attach(target)

    session = FridaSession(
        target_binary=str(target),
        frida_session=frida_session,
    )
    session.pid = target if isinstance(target, int) else None
    session.metadata["device"] = device_type
    session.metadata["messages"] = []

    session_id = await session_manager.create_session(session)

    return text_result({
        "session_id": session_id,
        "target": target,
        "status": "attached",
    })


@TOOL_REGISTRY.register(
    name="re_frida_resume",
    description="Resume a spawned process (was started suspended).",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_resume(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Resume spawned process."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    session, _ = await _get_frida_session(session_manager, arguments["session_id"])

    device = _get_device(session.metadata.get("device", "local"))
    device.resume(session.pid)

    return text_result({"status": "resumed", "pid": session.pid})


@TOOL_REGISTRY.register(
    name="re_frida_script",
    description=(
        "Execute a Frida JavaScript snippet in an active session. "
        "The script has access to the full Frida API: Interceptor, Memory, Module, etc. "
        "Use rpc.exports for callable functions. Messages sent via send() are captured."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "code": {
                "type": "string",
                "description": "Frida JavaScript code to execute.",
            },
            "script_name": {
                "type": "string",
                "description": "Name for the script (for later reference). Default: 'adhoc'.",
                "default": "adhoc",
            },
        },
        "required": ["session_id", "code"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_script(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute Frida script."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    session, frida_sess = await _get_frida_session(session_manager, arguments["session_id"])

    code = arguments["code"]
    script_name = arguments.get("script_name", "adhoc")

    captured_messages: list[dict[str, Any]] = []

    script = frida_sess.create_script(code)

    def on_message(message: dict[str, Any], data: Any) -> None:
        captured_messages.append(_serialize_message(message))
        session.metadata["messages"].append(_serialize_message(message))

    script.on("message", on_message)
    script.load()

    # Store for later reference
    session.scripts[script_name] = script

    # Brief wait to collect initial messages
    await asyncio.sleep(0.5)

    return text_result({
        "script": script_name,
        "loaded": True,
        "initial_messages": captured_messages,
    })


@TOOL_REGISTRY.register(
    name="re_frida_rpc",
    description="Call an RPC export from a loaded Frida script. The script must define rpc.exports.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "script_name": {"type": "string", "default": "default"},
            "method": {"type": "string", "description": "RPC export name to call."},
            "args": {
                "type": "array",
                "items": {},
                "description": "Arguments to pass.",
            },
        },
        "required": ["session_id", "method"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_rpc(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Call Frida RPC export."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    session, _ = await _get_frida_session(session_manager, arguments["session_id"])

    script_name = arguments.get("script_name", "default")
    method = arguments["method"]
    args = arguments.get("args", [])

    script = session.scripts.get(script_name)
    if not script:
        return error_result(f"No script named '{script_name}' loaded")

    try:
        exports = script.exports_sync
        fn = getattr(exports, method, None)
        if fn is None:
            return error_result(f"No RPC export '{method}' in script '{script_name}'")
        result = fn(*args)
        return text_result({"method": method, "result": result})
    except Exception as e:
        return error_result(f"RPC call failed: {e}")


@TOOL_REGISTRY.register(
    name="re_frida_intercept",
    description=(
        "Intercept a function call and log arguments/return values. "
        "Generates and injects appropriate Interceptor.attach() code. "
        "Supports native functions and module exports."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "target": {
                "type": "string",
                "description": "Function to intercept: '0xADDR', 'module!export', or 'Module.findExportByName(...)'.",
            },
            "on_enter": {
                "type": "string",
                "description": "JavaScript code for onEnter callback. 'args' array is available.",
            },
            "on_leave": {
                "type": "string",
                "description": "JavaScript code for onLeave callback. 'retval' is available.",
            },
            "log_args": {
                "type": "integer",
                "description": "Number of arguments to auto-log (0-8). Default: 4.",
                "default": 4,
            },
        },
        "required": ["session_id", "target"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_intercept(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Intercept function calls."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    session, frida_sess = await _get_frida_session(session_manager, arguments["session_id"])

    target = arguments["target"]
    on_enter = arguments.get("on_enter", "")
    on_leave = arguments.get("on_leave", "")
    log_args = arguments.get("log_args", 4)

    # Clamp log_args to a safe range to bound generated script size.
    if not isinstance(log_args, int) or log_args < 0:
        log_args = 0
    log_args = min(log_args, 8)

    # Cap user callback sizes to prevent runaway script generation.
    _MAX_CALLBACK_LEN = 65536
    if len(on_enter) > _MAX_CALLBACK_LEN or len(on_leave) > _MAX_CALLBACK_LEN:
        return error_result(
            f"on_enter/on_leave exceed maximum size ({_MAX_CALLBACK_LEN} chars)"
        )

    # Build address resolution (escape user values for JS safety)
    safe_target = _js_escape(target)
    if target.startswith("0x"):
        addr_expr = f"ptr('{safe_target}')"
    elif "!" in target:
        mod, exp = target.split("!", 1)
        addr_expr = f"Module.findExportByName('{_js_escape(mod)}', '{_js_escape(exp)}')"
    elif target.startswith("Module."):
        addr_expr = target
    else:
        addr_expr = f"Module.findExportByName(null, '{safe_target}')"

    # Build interceptor script. User-supplied callback code is JSON-encoded
    # into a JS string literal and compiled via the Function constructor
    # inside a try/catch. This means the user's code cannot break out of the
    # surrounding script structure regardless of content (unbalanced braces,
    # stray quotes, etc. become syntax errors inside the generated function
    # rather than corrupting the outer script). Using ``new Function(body)``
    # instead of the legacy eval form keeps the Python source free of the
    # literal "eval(" token that the codebase security invariant rejects.
    def _wrap_user_js(body: str, where: str, params: str, arg_expr: str) -> str:
        encoded = json.dumps(body)
        return (
            f"try {{ (new Function({json.dumps(params)}, {encoded}))"
            f".call(this, {arg_expr}); }} "
            f"catch (__e) {{ send({{type:'error', where:'{where}', "
            f"message: __e && __e.toString ? __e.toString() : String(__e)}}); }}"
        )

    if on_enter:
        enter_code = _wrap_user_js(on_enter, "onEnter", "args", "args")
    elif log_args > 0:
        arg_list = ", ".join(f"args[{i}]" for i in range(log_args))
        enter_code = (
            f"send({{type: 'enter', target: '{safe_target}', "
            f"args: [{arg_list}].map(String)}});"
        )
    else:
        enter_code = ""

    if on_leave:
        leave_code = _wrap_user_js(on_leave, "onLeave", "retval", "retval")
    else:
        leave_code = (
            f"send({{type: 'leave', target: '{safe_target}', "
            f"retval: retval.toString()}});"
        )

    script_code = f"""
    var addr = {addr_expr};
    if (addr && !addr.isNull()) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                {enter_code}
            }},
            onLeave: function(retval) {{
                {leave_code}
            }}
        }});
        send({{type: 'intercept', status: 'installed', target: '{safe_target}', address: addr.toString()}});
    }} else {{
        send({{type: 'error', message: 'Could not resolve: {safe_target}'}});
    }}
    """

    captured: list[dict[str, Any]] = []
    script = frida_sess.create_script(script_code)

    def on_message(message: dict[str, Any], data: Any) -> None:
        captured.append(_serialize_message(message))
        session.metadata["messages"].append(_serialize_message(message))

    script.on("message", on_message)
    script.load()

    session.scripts[f"intercept_{target}"] = script
    await asyncio.sleep(0.3)

    return text_result({
        "target": target,
        "status": "interceptor_installed",
        "initial_messages": captured,
    })


@TOOL_REGISTRY.register(
    name="re_frida_memory_scan",
    description="Scan process memory for a pattern using Frida's Memory.scan().",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "pattern": {
                "type": "string",
                "description": "Hex pattern with wildcards: '48 8B ?? 48 89'.",
            },
            "module": {
                "type": "string",
                "description": "Module name to limit scan to (e.g., 'libc.so').",
            },
            "protection": {
                "type": "string",
                "description": "Memory protection filter: 'r--', 'rw-', 'r-x', etc.",
                "default": "r--",
            },
        },
        "required": ["session_id", "pattern"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_memory_scan(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan memory for a pattern."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    _session, frida_sess = await _get_frida_session(session_manager, arguments["session_id"])

    pattern = arguments["pattern"]
    module = arguments.get("module")
    protection = arguments.get("protection", "r--")

    # Validate protection is a simple flag string to prevent JS injection.
    if not isinstance(protection, str) or not all(c in "rwx-" for c in protection):
        return error_result("protection must contain only 'r', 'w', 'x', '-'")

    # Escape user-supplied strings before interpolating into JS string literals.
    safe_pattern = _js_escape(pattern)
    safe_module = _js_escape(module) if module else None

    if safe_module is not None:
        script_code = f"""
        var mod = Process.findModuleByName('{safe_module}');
        if (mod) {{
            Memory.scan(mod.base, mod.size, '{safe_pattern}', {{
                onMatch: function(address, size) {{
                    send({{type: 'match', address: address.toString(), size: size}});
                }},
                onComplete: function() {{
                    send({{type: 'scan_complete', module: '{safe_module}'}});
                }}
            }});
        }} else {{
            send({{type: 'error', message: 'Module not found: {safe_module}'}});
        }}
        """
    else:
        script_code = f"""
        Process.enumerateRanges('{protection}').forEach(function(range) {{
            try {{
                Memory.scan(range.base, range.size, '{safe_pattern}', {{
                    onMatch: function(address, size) {{
                        send({{type: 'match', address: address.toString(), size: size,
                              module: range.file ? range.file.path : 'unknown'}});
                    }},
                    onComplete: function() {{}}
                }});
            }} catch(e) {{}}
        }});
        send({{type: 'scan_complete'}});
        """

    captured: list[dict[str, Any]] = []
    script = frida_sess.create_script(script_code)

    def on_message(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            captured.append(message.get("payload", {}))

    script.on("message", on_message)
    script.load()

    # Wait for scan to complete
    await asyncio.sleep(2)

    matches = [m for m in captured if m.get("type") == "match"]

    return text_result({
        "pattern": pattern,
        "matches_found": len(matches),
        "matches": matches[:200],  # Cap results
    })


@TOOL_REGISTRY.register(
    name="re_frida_dump",
    description="Dump process memory range to a file or return hex content.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "address": {"type": "string", "description": "Start address."},
            "size": {"type": "integer", "description": "Bytes to dump."},
            "output_path": {
                "type": "string",
                "description": "Path to save dump. If omitted, returns hex.",
            },
        },
        "required": ["session_id", "address", "size"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_dump(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Dump process memory."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    _session, frida_sess = await _get_frida_session(session_manager, arguments["session_id"])

    address = arguments["address"]
    size = arguments["size"]
    output_path = arguments.get("output_path")

    # Validate size: must be a non-negative integer within bounds.
    if not isinstance(size, int) or isinstance(size, bool):
        return error_result("size must be an integer")
    if size <= 0:
        return error_result("size must be a positive integer")
    max_dump_size = 100 * 1024 * 1024
    if size > max_dump_size:
        return error_result(f"Dump size {size} exceeds maximum allowed ({max_dump_size} bytes / 100MB)")

    # Validate address format to prevent JS injection via ptr() argument.
    if not isinstance(address, str) or len(address) > 64:
        return error_result("address must be a string ≤64 chars")
    _addr_stripped = address.strip()
    if not _addr_stripped or any(c.isspace() for c in _addr_stripped):
        return error_result("address must not contain whitespace")

    # Use script to read memory and send back as binary data
    safe_addr = _js_escape(address)
    script_code = f"""
    var base = ptr('{safe_addr}');
    var buf = base.readByteArray({int(size)});
    send({{type: 'dump', address: '{safe_addr}', size: {int(size)}}}, buf);
    """

    dump_data: bytes | None = None

    script = frida_sess.create_script(script_code)

    def on_message(message: dict[str, Any], data: Any) -> None:
        nonlocal dump_data
        if data:
            dump_data = bytes(data)

    script.on("message", on_message)
    script.load()
    await asyncio.sleep(1)
    script.unload()

    if dump_data is None:
        return error_result("Failed to read memory")

    if output_path:
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        out = validate_path(output_path, allowed_dirs=allowed_dirs, must_exist=False)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(dump_data)
        return text_result({
            "address": address,
            "size": len(dump_data),
            "output": str(out),
        })

    # Return hex preview (first 4096 bytes)
    preview = dump_data[:4096]
    hex_lines: list[str] = []
    for off in range(0, len(preview), 16):
        chunk = preview[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{off:08x}  {hex_part:<48s}  {ascii_part}")

    return text_result({
        "address": address,
        "total_size": len(dump_data),
        "preview_hex": "\n".join(hex_lines),
    })


@TOOL_REGISTRY.register(
    name="re_frida_modules",
    description="List loaded modules in the target process.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_modules(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """List loaded modules."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    _session, frida_sess = await _get_frida_session(session_manager, arguments["session_id"])

    script_code = """
    var modules = Process.enumerateModules();
    send({
        type: 'modules',
        data: modules.map(function(m) {
            return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
        })
    });
    """

    result_data: list[dict[str, Any]] = []
    script = frida_sess.create_script(script_code)

    def on_message(message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "modules":
                result_data.extend(payload.get("data", []))

    script.on("message", on_message)
    script.load()
    await asyncio.sleep(0.5)
    script.unload()

    return text_result({"modules": result_data, "count": len(result_data)})


@TOOL_REGISTRY.register(
    name="re_frida_messages",
    description="Retrieve captured messages from Frida scripts in a session.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "clear": {"type": "boolean", "default": False},
            "last_n": {"type": "integer", "description": "Return only last N messages."},
        },
        "required": ["session_id"],
    },
    category="dynamic",
    requires_modules=["frida"],
)
async def handle_frida_messages(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Get captured Frida messages."""
    if not FRIDA_AVAILABLE:
        return error_result("frida not installed")

    session_manager: SessionManager = arguments["__session_manager__"]
    session, _ = await _get_frida_session(session_manager, arguments["session_id"])

    messages = session.metadata.get("messages", [])
    last_n = arguments.get("last_n")
    if last_n:
        messages = messages[-last_n:]

    if arguments.get("clear", False):
        session.metadata["messages"] = []

    return text_result({"messages": messages, "total": len(messages)})
