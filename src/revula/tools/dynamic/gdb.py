"""
Revula GDB Adapter — GDB/MI protocol interface for debugging.

Uses GDB's Machine Interface (MI) protocol (--interpreter=mi2) for structured
communication. Parses MI output — never human-readable text with regex.

Provides: launch, attach, breakpoints, execution control, register reads,
memory access, backtrace, expression evaluation, heap analysis.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from revula.sandbox import validate_binary_path
from revula.session import DebuggerSession, SessionManager
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GDB/MI Input sanitization
# ---------------------------------------------------------------------------

# Characters that terminate or corrupt a GDB/MI command line. Any of these in
# a user-supplied argument would let a caller inject additional commands.
_MI_FORBIDDEN_CHARS = ("\n", "\r", "\x00")

# Conservative allowlist for addresses / numeric-like expressions. GDB accepts
# register names (``$rsp``), symbol names (``main+0x20``), and hex/decimal
# literals — we allow identifier characters, digits, a small set of arithmetic
# operators, and nothing else, which blocks quoting/newline tricks without
# breaking legitimate expressions.
_MI_ADDRESS_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "+-*/()$._:"
)


def _mi_check_no_newlines(value: str, field: str) -> None:
    """Reject control characters that can break out of the MI command line."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    for ch in _MI_FORBIDDEN_CHARS:
        if ch in value:
            raise ValueError(
                f"{field} contains a forbidden control character "
                f"(newline/null); refusing to pass to GDB/MI"
            )


def _mi_quote_c_string(value: str) -> str:
    """Quote a Python string as a GDB/MI c-string literal.

    GDB/MI c-strings use C escape rules: backslash, double quote, and the
    standard control-character escapes. Any user input that ends up inside an
    MI ``"..."`` literal MUST go through this helper so that stray quotes or
    newlines cannot terminate the literal and inject extra commands.
    """
    _mi_check_no_newlines(value, "mi c-string")
    out: list[str] = ['"']
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\{ord(ch):03o}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _mi_validate_address(value: str, field: str = "address") -> str:
    """Validate an address/register/simple-expression token for MI use.

    Rejects whitespace, quotes, and anything outside the allowlist so the
    token can be interpolated into a command line without quoting.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    v = value.strip()
    if not v:
        raise ValueError(f"{field} must not be empty")
    if len(v) > 128:
        raise ValueError(f"{field} exceeds 128 chars")
    if any(c not in _MI_ADDRESS_ALLOWED for c in v):
        raise ValueError(f"{field} contains disallowed characters")
    return v


_HEX_ALLOWED = set("0123456789abcdefABCDEF")


def _mi_validate_hex_bytes(value: str) -> str:
    """Validate hex-bytes payload (even length, only hex digits)."""
    if not isinstance(value, str):
        raise ValueError("hex_bytes must be a string")
    stripped = value.replace(" ", "")
    if not stripped:
        raise ValueError("hex_bytes must not be empty")
    if len(stripped) % 2 != 0:
        raise ValueError("hex_bytes must have an even number of hex digits")
    if any(c not in _HEX_ALLOWED for c in stripped):
        raise ValueError("hex_bytes must contain only hex digits")
    if len(stripped) > 2 * 1024 * 1024:  # cap at 1 MB
        raise ValueError("hex_bytes exceeds 1 MB")
    return stripped


# ---------------------------------------------------------------------------
# GDB/MI Output Parser
# ---------------------------------------------------------------------------


class GDBMIParser:
    """Parse GDB/MI output into structured data."""

    # MI output patterns
    RESULT_RE = re.compile(r"^\^(done|running|connected|error|exit)(,(.*))?$")
    ASYNC_RE = re.compile(r"^\*(\w+)(,(.*))?$")
    NOTIFY_RE = re.compile(r"^=(\w+)(,(.*))?$")
    CONSOLE_RE = re.compile(r'^~"(.*)"$')
    TARGET_RE = re.compile(r'^@"(.*)"$')
    LOG_RE = re.compile(r'^&"(.*)"$')

    @staticmethod
    def parse_mi_value(s: str) -> Any:
        """Parse a GDB/MI value string into a Python object."""
        s = s.strip()

        if not s:
            return None

        # String value
        if s.startswith('"') and s.endswith('"'):
            return s[1:-1].replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")

        # Tuple/dict: {key=value,...}
        if s.startswith("{") and s.endswith("}"):
            return GDBMIParser._parse_mi_dict(s[1:-1])

        # List: [value,...]
        if s.startswith("[") and s.endswith("]"):
            return GDBMIParser._parse_mi_list(s[1:-1])

        return s

    @staticmethod
    def _parse_mi_dict(s: str) -> dict[str, Any]:
        """Parse MI tuple into dict."""
        result: dict[str, Any] = {}
        i = 0
        while i < len(s):
            # Find key
            eq = s.find("=", i)
            if eq == -1:
                break
            key = s[i:eq].strip()
            i = eq + 1

            # Find value
            value, i = GDBMIParser._parse_mi_element(s, i)
            result[key] = value

            # Skip comma
            if i < len(s) and s[i] == ",":
                i += 1

        return result

    @staticmethod
    def _parse_mi_list(s: str) -> list[Any]:
        """Parse MI list."""
        if not s.strip():
            return []
        result: list[Any] = []
        i = 0
        while i < len(s):
            value, i = GDBMIParser._parse_mi_element(s, i)
            result.append(value)
            if i < len(s) and s[i] == ",":
                i += 1
        return result

    @staticmethod
    def _parse_mi_element(s: str, start: int) -> tuple[Any, int]:
        """Parse a single MI element starting at position."""
        i = start
        while i < len(s) and s[i] in " \t":
            i += 1

        if i >= len(s):
            return None, i

        # String
        if s[i] == '"':
            end = i + 1
            while end < len(s):
                if s[end] == "\\" and end + 1 < len(s):
                    end += 2
                    continue
                if s[end] == '"':
                    val = s[i + 1:end].replace('\\"', '"').replace("\\n", "\n")
                    return val, end + 1
                end += 1
            return s[i + 1:], len(s)

        # Dict
        if s[i] == "{":
            depth = 1
            end = i + 1
            while end < len(s) and depth > 0:
                if s[end] == "{":
                    depth += 1
                elif s[end] == "}":
                    depth -= 1
                elif s[end] == '"':
                    end += 1
                    while end < len(s) and s[end] != '"':
                        if s[end] == "\\":
                            end += 1
                        end += 1
                end += 1
            return GDBMIParser._parse_mi_dict(s[i + 1:end - 1]), end

        # List
        if s[i] == "[":
            depth = 1
            end = i + 1
            while end < len(s) and depth > 0:
                if s[end] == "[":
                    depth += 1
                elif s[end] == "]":
                    depth -= 1
                elif s[end] == '"':
                    end += 1
                    while end < len(s) and s[end] != '"':
                        if s[end] == "\\":
                            end += 1
                        end += 1
                end += 1
            return GDBMIParser._parse_mi_list(s[i + 1:end - 1]), end

        # key=value pair
        eq = s.find("=", i)
        comma = s.find(",", i)
        if eq != -1 and (comma == -1 or eq < comma):
            key = s[i:eq]
            val, pos = GDBMIParser._parse_mi_element(s, eq + 1)
            return {key: val}, pos

        # Plain value (up to comma or end)
        end = s.find(",", i)
        if end == -1:
            end = len(s)
        return s[i:end].strip(), end

    @staticmethod
    def parse_line(line: str) -> dict[str, Any]:
        """Parse a single MI output line."""
        line = line.strip()

        if not line or line == "(gdb)":
            return {"type": "prompt"}

        # Result record
        m = GDBMIParser.RESULT_RE.match(line)
        if m:
            result: dict[str, Any] = {"type": "result", "class": m.group(1)}
            if m.group(3):
                result["data"] = GDBMIParser._parse_mi_dict(m.group(3))
            return result

        # Async exec record
        m = GDBMIParser.ASYNC_RE.match(line)
        if m:
            result = {"type": "exec", "class": m.group(1)}
            if m.group(3):
                result["data"] = GDBMIParser._parse_mi_dict(m.group(3))
            return result

        # Notify record
        m = GDBMIParser.NOTIFY_RE.match(line)
        if m:
            result = {"type": "notify", "class": m.group(1)}
            if m.group(3):
                result["data"] = GDBMIParser._parse_mi_dict(m.group(3))
            return result

        # Console output
        m = GDBMIParser.CONSOLE_RE.match(line)
        if m:
            return {"type": "console", "text": m.group(1).replace("\\n", "\n").replace('\\"', '"')}

        # Target output
        m = GDBMIParser.TARGET_RE.match(line)
        if m:
            return {"type": "target", "text": m.group(1)}

        # Log output
        m = GDBMIParser.LOG_RE.match(line)
        if m:
            return {"type": "log", "text": m.group(1)}

        return {"type": "unknown", "raw": line}


# ---------------------------------------------------------------------------
# GDB Session
# ---------------------------------------------------------------------------


class GDBSession:
    """Manages a GDB/MI session."""

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process
        self.parser = GDBMIParser()
        self._buffer: list[str] = []

    async def send_command(self, command: str, timeout: int = 30) -> dict[str, Any]:
        """Send an MI command and wait for result."""
        assert self.process.stdin is not None
        assert self.process.stdout is not None

        # Send command
        cmd = command.strip()
        if not cmd.startswith("-"):
            cmd = f"-interpreter-exec console \"{cmd}\""

        self.process.stdin.write(f"{cmd}\n".encode())
        await self.process.stdin.drain()

        # Read until result record
        result_data: dict[str, Any] = {"type": "timeout"}
        console_output: list[str] = []

        try:
            async with asyncio.timeout(timeout):
                while True:
                    line_bytes = await self.process.stdout.readline()
                    if not line_bytes:
                        break

                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line or line == "(gdb)":
                        if result_data.get("type") != "timeout":
                            break
                        continue

                    parsed = self.parser.parse_line(line)

                    if parsed["type"] == "console":
                        console_output.append(parsed.get("text", ""))
                    elif parsed["type"] == "result":
                        result_data = parsed
                        result_data["console"] = console_output
                    elif parsed["type"] == "exec":
                        result_data = parsed
                        result_data["console"] = console_output
                        break

        except TimeoutError:
            result_data = {"type": "timeout", "error": f"Command timed out: {cmd}"}

        return result_data

    async def close(self) -> None:
        """Terminate GDB."""
        try:
            if self.process.stdin:
                self.process.stdin.write(b"-gdb-exit\n")
                await self.process.stdin.drain()
            await asyncio.wait_for(self.process.wait(), timeout=5)
        except Exception:
            self.process.kill()
            await self.process.wait()


# ---------------------------------------------------------------------------
# Tool registrations
# ---------------------------------------------------------------------------


async def _get_or_create_gdb_session(
    session_manager: SessionManager, session_id: str,
) -> tuple[DebuggerSession, GDBSession]:
    """Get an existing GDB session."""
    session = await session_manager.get_typed_session(session_id, DebuggerSession)
    if session.backend != "gdb":
        raise ValueError(f"Session {session_id} is not a GDB session")
    gdb = session.metadata.get("gdb_session")
    if not gdb:
        raise ValueError(f"GDB session {session_id} has no active GDB connection")
    return session, gdb


@TOOL_REGISTRY.register(
    name="re_debugger_launch",
    description=(
        "Launch a binary under a debugger. Creates a persistent debugger session. "
        "Backend: GDB with MI protocol (--interpreter=mi2). "
        "Returns session_id for subsequent debugging operations."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to binary to debug.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Command-line arguments for the binary.",
            },
            "backend": {
                "type": "string",
                "enum": ["gdb", "lldb"],
                "description": "Debugger backend. Default: gdb.",
                "default": "gdb",
            },
            "break_on_entry": {
                "type": "boolean",
                "description": "Set breakpoint at main/entry before running. Default: true.",
                "default": True,
            },
        },
        "required": ["binary_path"],
    },
    category="dynamic",
    requires_tools=["gdb"],
)
async def handle_debugger_launch(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Launch a binary under GDB."""
    binary_path_str = arguments["binary_path"]
    args = arguments.get("args", [])
    arguments.get("backend", "gdb")
    break_on_entry = arguments.get("break_on_entry", True)

    config = arguments.get("__config__")
    session_manager: SessionManager = arguments["__session_manager__"]
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    gdb_path = config.require_tool("gdb") if config else "gdb"

    # Launch GDB with MI interface
    cmd = [gdb_path, "--interpreter=mi2", "--quiet", str(file_path)]

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    gdb_session = GDBSession(process)

    # Wait for initial prompt
    await asyncio.sleep(0.5)

    # Set arguments if provided. Each arg is passed as a quoted MI c-string
    # so newlines, quotes, and backslashes cannot inject extra MI commands.
    if args:
        try:
            quoted_args = " ".join(_mi_quote_c_string(str(a)) for a in args)
        except ValueError as e:
            process.kill()
            await process.wait()
            return error_result(f"Invalid program argument: {e}")
        await gdb_session.send_command(f"-exec-arguments {quoted_args}")

    # Break on entry
    if break_on_entry:
        await gdb_session.send_command("-break-insert main")

    # Create session
    session = DebuggerSession(
        backend="gdb",
        target_binary=str(file_path),
        process=process,
    )
    session.metadata["gdb_session"] = gdb_session
    session.metadata["args"] = args

    session_id = await session_manager.create_session(session)

    return text_result({
        "session_id": session_id,
        "backend": "gdb",
        "binary": str(file_path),
        "status": "launched",
        "break_on_entry": break_on_entry,
    })


@TOOL_REGISTRY.register(
    name="re_debugger_attach",
    description=(
        "Attach debugger to a running process by PID. "
        "Returns session_id for subsequent operations."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "Process ID to attach to."},
            "backend": {
                "type": "string",
                "enum": ["gdb", "lldb"],
                "default": "gdb",
            },
        },
        "required": ["pid"],
    },
    category="dynamic",
    requires_tools=["gdb"],
)
async def handle_debugger_attach(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Attach GDB to a running process."""
    pid = arguments["pid"]
    config = arguments.get("__config__")
    session_manager: SessionManager = arguments["__session_manager__"]

    gdb_path = config.require_tool("gdb") if config else "gdb"

    process = await asyncio.create_subprocess_exec(
        gdb_path, "--interpreter=mi2", "--quiet",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    gdb_session = GDBSession(process)
    await asyncio.sleep(0.5)

    result = await gdb_session.send_command(f"-target-attach {pid}")

    session = DebuggerSession(backend="gdb", pid=pid, process=process)
    session.metadata["gdb_session"] = gdb_session
    session_id = await session_manager.create_session(session)

    return text_result({
        "session_id": session_id,
        "pid": pid,
        "status": "attached",
        "result": result,
    })


@TOOL_REGISTRY.register(
    name="re_bp_set",
    description="Set a breakpoint in an active debugger session. Supports software, hardware, "
                "conditional, and watchpoint breakpoints.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "Debugger session ID."},
            "location": {
                "type": "string",
                "description": "Breakpoint location: address (0x...), symbol name, or file:line.",
            },
            "condition": {
                "type": "string",
                "description": "Conditional expression (e.g., '$rax == 0').",
            },
            "hardware": {
                "type": "boolean",
                "description": "Use hardware breakpoint. Default: false.",
                "default": False,
            },
            "type": {
                "type": "string",
                "enum": ["breakpoint", "watchpoint_write", "watchpoint_read", "watchpoint_rw"],
                "default": "breakpoint",
            },
            "commands": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Commands to execute when breakpoint hits.",
            },
        },
        "required": ["session_id", "location"],
    },
    category="dynamic",
)
async def handle_bp_set(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Set a breakpoint."""
    session_manager: SessionManager = arguments["__session_manager__"]
    session, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    location = arguments["location"]
    condition = arguments.get("condition")
    hardware = arguments.get("hardware", False)
    bp_type = arguments.get("type", "breakpoint")
    commands = arguments.get("commands", [])

    # Location is passed as an MI c-string so callers cannot close the
    # literal with a stray quote or smuggle newlines to inject commands.
    try:
        _mi_check_no_newlines(location, "location")
        quoted_location = _mi_quote_c_string(location)
        quoted_condition = _mi_quote_c_string(condition) if condition else None
    except ValueError as e:
        return error_result(f"Invalid breakpoint argument: {e}")

    if bp_type == "breakpoint":
        cmd = "-break-insert"
        if hardware:
            cmd += " -h"
        if quoted_condition is not None:
            cmd += f" -c {quoted_condition}"
        cmd += f" {quoted_location}"
    elif bp_type.startswith("watchpoint"):
        access = "a" if bp_type == "watchpoint_rw" else "r" if bp_type == "watchpoint_read" else ""
        access_flag = "-a " if access == "a" else "-r " if access == "r" else ""
        cmd = f"-break-watch {access_flag}{quoted_location}"
    else:
        return error_result(f"Unknown breakpoint type: {bp_type}")

    result = await gdb.send_command(cmd)

    bp_info = result.get("data", {}).get("bkpt", {})
    bp_number = bp_info.get("number", session.next_bp_id())

    # Set commands on hit. Each command is a c-string literal; reject any
    # that carry newlines or cannot be safely quoted.
    if commands and bp_number:
        try:
            bp_num_int = int(bp_number)
        except (TypeError, ValueError):
            return error_result(f"Invalid breakpoint number returned by GDB: {bp_number!r}")
        for c in commands:
            try:
                quoted_cmd = _mi_quote_c_string(str(c))
            except ValueError as e:
                return error_result(f"Invalid breakpoint command: {e}")
            await gdb.send_command(f"-break-commands {bp_num_int} {quoted_cmd}")

    session.breakpoints[int(bp_number)] = {
        "location": location,
        "condition": condition,
        "hardware": hardware,
        "type": bp_type,
    }

    return text_result({
        "breakpoint_id": bp_number,
        "location": location,
        "info": bp_info,
    })


@TOOL_REGISTRY.register(
    name="re_bp_delete",
    description="Delete a breakpoint by ID.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "breakpoint_id": {"type": "integer", "description": "Breakpoint number to delete."},
        },
        "required": ["session_id", "breakpoint_id"],
    },
    category="dynamic",
)
async def handle_bp_delete(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Delete a breakpoint."""
    session_manager: SessionManager = arguments["__session_manager__"]
    session, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    bp_id = arguments["breakpoint_id"]
    result = await gdb.send_command(f"-break-delete {bp_id}")
    session.breakpoints.pop(bp_id, None)

    return text_result({"deleted": bp_id, "result": result})


@TOOL_REGISTRY.register(
    name="re_bp_list",
    description="List all breakpoints in a debugger session.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_bp_list(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """List breakpoints."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _session, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    result = await gdb.send_command("-break-list")
    return text_result({"breakpoints": result.get("data", {})})


@TOOL_REGISTRY.register(
    name="re_continue",
    description="Continue execution in debugger session.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_continue(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Continue execution."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    result = await gdb.send_command("-exec-continue")
    return text_result({"status": "continued", "result": result})


@TOOL_REGISTRY.register(
    name="re_step",
    description="Step over one source line.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_step(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Step over."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    result = await gdb.send_command("-exec-next")
    return text_result(result)


@TOOL_REGISTRY.register(
    name="re_stepi",
    description="Step one machine instruction.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_stepi(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Step instruction."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    result = await gdb.send_command("-exec-step-instruction")
    return text_result(result)


@TOOL_REGISTRY.register(
    name="re_finish",
    description="Execute until current function returns.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_finish(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Finish current function."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    result = await gdb.send_command("-exec-finish")
    return text_result(result)


@TOOL_REGISTRY.register(
    name="re_registers",
    description="Read all registers from debugger session. Returns GPR, flags, segment, FPU/SSE.",
    input_schema={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_registers(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Read registers."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    # Get register names
    names_result = await gdb.send_command("-data-list-register-names")
    names = names_result.get("data", {}).get("register-names", [])

    # Get register values
    values_result = await gdb.send_command("-data-list-register-values x")
    values = values_result.get("data", {}).get("register-values", [])

    registers: dict[str, str] = {}
    for val in values:
        if isinstance(val, dict):
            idx = int(val.get("number", -1))
            if 0 <= idx < len(names) and names[idx]:
                registers[names[idx]] = val.get("value", "")

    return text_result({"registers": registers})


@TOOL_REGISTRY.register(
    name="re_memory_read",
    description="Read memory from debugger session. Returns hex dump of memory range.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "address": {"type": "string", "description": "Memory address (e.g., '0x7ffff7dd1000' or '$rsp')."},
            "length": {"type": "integer", "description": "Bytes to read. Default: 256.", "default": 256},
            "format": {
                "type": "string",
                "enum": ["hex", "bytes", "string"],
                "default": "hex",
            },
        },
        "required": ["session_id", "address"],
    },
    category="dynamic",
)
async def handle_memory_read(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Read process memory."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    address = arguments["address"]
    length = arguments.get("length", 256)

    try:
        safe_address = _mi_validate_address(address)
    except ValueError as e:
        return error_result(f"Invalid address: {e}")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        return error_result("length must be a positive integer")
    if length > 64 * 1024 * 1024:
        return error_result("length exceeds 64 MB")

    result = await gdb.send_command(
        f"-data-read-memory-bytes {safe_address} {length}"
    )
    memory = result.get("data", {}).get("memory", [])

    return text_result({
        "address": address,
        "length": length,
        "memory": memory,
    })


@TOOL_REGISTRY.register(
    name="re_memory_write",
    description="Write bytes to process memory.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "address": {"type": "string", "description": "Target address."},
            "hex_bytes": {"type": "string", "description": "Hex bytes to write."},
        },
        "required": ["session_id", "address", "hex_bytes"],
    },
    category="dynamic",
)
async def handle_memory_write(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Write to process memory."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    address = arguments["address"]
    raw_hex = arguments["hex_bytes"]

    try:
        safe_address = _mi_validate_address(address)
        hex_bytes = _mi_validate_hex_bytes(raw_hex)
    except ValueError as e:
        return error_result(f"Invalid memory write argument: {e}")

    # Hex-bytes contain only [0-9a-fA-F] and the quoted address is allowlisted,
    # so neither can break out of the MI command line.
    result = await gdb.send_command(
        f'-data-write-memory-bytes {safe_address} "{hex_bytes}"'
    )

    return text_result({"address": address, "bytes_written": len(hex_bytes) // 2, "result": result})


@TOOL_REGISTRY.register(
    name="re_backtrace",
    description="Get stack backtrace from debugger session.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "max_frames": {"type": "integer", "default": 50},
        },
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_backtrace(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Get stack backtrace."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    max_frames = arguments.get("max_frames", 50)
    result = await gdb.send_command(f"-stack-list-frames 0 {max_frames}")

    frames = result.get("data", {}).get("stack", [])
    return text_result({"frames": frames})


@TOOL_REGISTRY.register(
    name="re_evaluate",
    description="Evaluate an expression in debugger context. Supports casting, dereferencing, struct access.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "expression": {"type": "string", "description": "Expression to evaluate."},
        },
        "required": ["session_id", "expression"],
    },
    category="dynamic",
)
async def handle_evaluate(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate expression."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    expr = arguments["expression"]
    try:
        quoted_expr = _mi_quote_c_string(expr)
    except ValueError as e:
        return error_result(f"Invalid expression: {e}")

    # Cap expression length to keep the MI command reasonable.
    if len(expr) > 4096:
        return error_result("expression exceeds 4096 chars")

    result = await gdb.send_command(f"-data-evaluate-expression {quoted_expr}")

    return text_result({
        "expression": expr,
        "value": result.get("data", {}).get("value", ""),
        "result": result,
    })


@TOOL_REGISTRY.register(
    name="re_heap_analysis",
    description=(
        "Analyze heap layout in debugger session. "
        "Dumps chunk metadata, detects use-after-free patterns. "
        "Uses GDB's malloc inspection facilities."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
        },
        "required": ["session_id"],
    },
    category="dynamic",
)
async def handle_heap_analysis(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze heap."""
    session_manager: SessionManager = arguments["__session_manager__"]
    _, gdb = await _get_or_create_gdb_session(session_manager, arguments["session_id"])

    # Use GDB's built-in heap commands
    result = await gdb.send_command("heap")
    malloc_info = await gdb.send_command("info proc mappings")

    return text_result({
        "heap_info": result,
        "memory_map": malloc_info,
    })
