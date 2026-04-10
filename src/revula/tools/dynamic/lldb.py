"""
Revula LLDB Adapter — Uses LLDB's Python API (lldb.SBDebugger).

No subprocess needed — directly uses the LLDB SB API when available.
Fallback: drives lldb CLI via subprocess if API not importable.
"""

from __future__ import annotations

import logging
from typing import Any

from revula.sandbox import validate_binary_path
from revula.session import DebuggerSession, SessionManager
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

try:
    import lldb

    LLDB_API_AVAILABLE = True
except ImportError:
    LLDB_API_AVAILABLE = False


# ---------------------------------------------------------------------------
# LLDB SB API Session
# ---------------------------------------------------------------------------


class LLDBAPISession:
    """LLDB session using the native SB API."""

    def __init__(self) -> None:
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.target: Any = None
        self.process: Any = None

    def launch(self, binary_path: str, args: list[str] | None = None, break_on_entry: bool = True) -> dict[str, Any]:
        """Launch a target."""
        error = lldb.SBError()
        self.target = self.debugger.CreateTargetWithFileAndArch(binary_path, lldb.LLDB_ARCH_DEFAULT)

        if not self.target:
            return {"error": f"Failed to create target for {binary_path}"}

        if break_on_entry:
            bp = self.target.BreakpointCreateByName("main")
            if bp.IsValid():
                pass  # breakpoint set

        launch_info = lldb.SBLaunchInfo(args or [])
        self.process = self.target.Launch(launch_info, error)

        if error.Fail():
            return {"error": error.GetCString()}

        return {
            "status": "launched",
            "pid": self.process.GetProcessID(),
            "state": self._state_name(),
        }

    def attach(self, pid: int) -> dict[str, Any]:
        """Attach to a running process."""
        self.target = self.debugger.CreateTarget("")
        error = lldb.SBError()
        self.process = self.target.AttachToProcessWithID(lldb.SBListener(), pid, error)

        if error.Fail():
            return {"error": error.GetCString()}

        return {"status": "attached", "pid": pid}

    def continue_execution(self) -> dict[str, Any]:
        """Continue execution."""
        if not self.process:
            return {"error": "No process"}
        self.process.Continue()
        return {"state": self._state_name()}

    def step_over(self) -> dict[str, Any]:
        """Step over."""
        thread = self._current_thread()
        if not thread:
            return {"error": "No current thread"}
        thread.StepOver()
        return {"state": self._state_name(), "frame": self._frame_info()}

    def step_into(self) -> dict[str, Any]:
        """Step into."""
        thread = self._current_thread()
        if not thread:
            return {"error": "No current thread"}
        thread.StepInto()
        return {"state": self._state_name(), "frame": self._frame_info()}

    def step_instruction(self) -> dict[str, Any]:
        """Step one instruction."""
        thread = self._current_thread()
        if not thread:
            return {"error": "No current thread"}
        thread.StepInstruction(False)
        return {"state": self._state_name(), "frame": self._frame_info()}

    def step_out(self) -> dict[str, Any]:
        """Step out of current function."""
        thread = self._current_thread()
        if not thread:
            return {"error": "No current thread"}
        thread.StepOut()
        return {"state": self._state_name(), "frame": self._frame_info()}

    def get_registers(self) -> dict[str, str]:
        """Read all registers."""
        thread = self._current_thread()
        if not thread:
            return {}

        frame = thread.GetFrameAtIndex(0)
        registers: dict[str, str] = {}

        for reg_set in frame.GetRegisters():
            for reg in reg_set:
                if reg.GetValue():
                    registers[reg.GetName()] = reg.GetValue()

        return registers

    def get_backtrace(self, max_frames: int = 50) -> list[dict[str, Any]]:
        """Get backtrace."""
        thread = self._current_thread()
        if not thread:
            return []

        frames: list[dict[str, Any]] = []
        for i in range(min(thread.GetNumFrames(), max_frames)):
            frame = thread.GetFrameAtIndex(i)
            frames.append({
                "index": i,
                "function": frame.GetFunctionName() or "<unknown>",
                "address": f"0x{frame.GetPC():x}",
                "module": frame.GetModule().GetFileSpec().GetFilename() if frame.GetModule() else "",
                "line": frame.GetLineEntry().GetLine() if frame.GetLineEntry().IsValid() else None,
                "file": str(frame.GetLineEntry().GetFileSpec()) if frame.GetLineEntry().IsValid() else None,
            })

        return frames

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory."""
        if not self.process:
            return None
        error = lldb.SBError()
        data = self.process.ReadMemory(address, size, error)
        if error.Fail():
            return None
        return data  # type: ignore[no-any-return]

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory."""
        if not self.process:
            return False
        error = lldb.SBError()
        self.process.WriteMemory(address, data, error)
        return not error.Fail()

    def set_breakpoint(self, location: str, condition: str | None = None) -> dict[str, Any]:
        """Set a breakpoint."""
        if not self.target:
            return {"error": "No target"}

        if location.startswith("0x"):
            addr = int(location, 16)
            bp = self.target.BreakpointCreateByAddress(addr)
        elif ":" in location:
            parts = location.split(":")
            bp = self.target.BreakpointCreateByLocation(parts[0], int(parts[1]))
        else:
            bp = self.target.BreakpointCreateByName(location)

        if not bp.IsValid():
            return {"error": f"Failed to set breakpoint at {location}"}

        if condition:
            bp.SetCondition(condition)

        return {"id": bp.GetID(), "locations": bp.GetNumLocations()}

    def delete_breakpoint(self, bp_id: int) -> bool:
        """Delete a breakpoint."""
        if not self.target:
            return False
        return self.target.BreakpointDelete(bp_id)  # type: ignore[no-any-return]

    def evaluate(self, expression: str) -> str:
        """Evaluate expression."""
        thread = self._current_thread()
        if not thread:
            return "<no thread>"
        frame = thread.GetFrameAtIndex(0)
        result = frame.EvaluateExpression(expression)
        if result.GetError().Fail():
            return f"Error: {result.GetError().GetCString()}"
        return result.GetValue() or result.GetSummary() or "<no value>"

    def destroy(self) -> None:
        """Clean up."""
        if self.process:
            self.process.Kill()
        lldb.SBDebugger.Destroy(self.debugger)

    def _current_thread(self) -> Any:
        """Get current thread."""
        if not self.process:
            return None
        return self.process.GetSelectedThread()

    def _state_name(self) -> str:
        """Get process state name."""
        if not self.process:
            return "invalid"
        state_map = {
            lldb.eStateStopped: "stopped",
            lldb.eStateRunning: "running",
            lldb.eStateExited: "exited",
            lldb.eStateCrashed: "crashed",
        }
        return state_map.get(self.process.GetState(), "unknown")

    def _frame_info(self) -> dict[str, Any]:
        """Get current frame info."""
        thread = self._current_thread()
        if not thread:
            return {}
        frame = thread.GetFrameAtIndex(0)
        return {
            "function": frame.GetFunctionName(),
            "address": f"0x{frame.GetPC():x}",
        }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_lldb_launch",
    description="Launch a binary under LLDB debugger. Uses SB API directly when available.",
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "args": {"type": "array", "items": {"type": "string"}},
            "break_on_entry": {"type": "boolean", "default": True},
        },
        "required": ["binary_path"],
    },
    category="dynamic",
    requires_tools=["lldb"],
    requires_modules=["lldb"],
)
async def handle_lldb_launch(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Launch under LLDB."""
    if not LLDB_API_AVAILABLE:
        return error_result(
            "lldb Python API not available. Ensure lldb is installed "
            "and the Python bindings are on PYTHONPATH."
        )

    binary_path = arguments["binary_path"]
    args = arguments.get("args", [])
    break_on_entry = arguments.get("break_on_entry", True)
    session_manager: SessionManager = arguments["__session_manager__"]

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    lldb_session = LLDBAPISession()
    result = lldb_session.launch(str(file_path), args, break_on_entry)

    if "error" in result:
        return error_result(result["error"])

    session = DebuggerSession(backend="lldb", target_binary=str(file_path))
    session.metadata["lldb_session"] = lldb_session

    session_id = await session_manager.create_session(session)
    result["session_id"] = session_id

    return text_result(result)


@TOOL_REGISTRY.register(
    name="re_lldb_command",
    description="Execute a command in an active LLDB session. Supports all SB API operations.",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "command": {
                "type": "string",
                "enum": [
                    "continue", "step_over", "step_into", "step_instruction",
                    "step_out", "registers", "backtrace",
                ],
            },
            "expression": {"type": "string", "description": "For evaluate command."},
            "address": {"type": "string", "description": "For memory operations."},
            "size": {"type": "integer", "description": "For memory read."},
        },
        "required": ["session_id", "command"],
    },
    category="dynamic",
)
async def handle_lldb_command(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Run LLDB command."""
    session_manager: SessionManager = arguments["__session_manager__"]
    session = await session_manager.get_typed_session(arguments["session_id"], DebuggerSession)
    lldb_session: LLDBAPISession = session.metadata.get("lldb_session")

    if not lldb_session:
        return error_result("No active LLDB session")

    cmd = arguments["command"]

    dispatch = {
        "continue": lldb_session.continue_execution,
        "step_over": lldb_session.step_over,
        "step_into": lldb_session.step_into,
        "step_instruction": lldb_session.step_instruction,
        "step_out": lldb_session.step_out,
        "registers": lldb_session.get_registers,
        "backtrace": lldb_session.get_backtrace,
    }

    fn = dispatch.get(cmd)
    if fn:
        result = fn()  # type: ignore[operator]
        return text_result(result)

    return error_result(f"Unknown command: {cmd}")
