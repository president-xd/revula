"""
Revula Session Manager — thread-safe session lifecycle for debuggers, Frida, and analysis.

Sessions persist across MCP tool calls within a conversation. Each session:
- Has a unique UUID
- Has a type (debugger, frida, analysis)
- Tracks creation/last-access time for TTL cleanup
- Stores backend-specific state
- Is cleaned up automatically after idle timeout
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session types
# ---------------------------------------------------------------------------


class SessionType(StrEnum):
    DEBUGGER = "debugger"
    FRIDA = "frida"
    ANALYSIS = "analysis"
    R2 = "r2"


class SessionState(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    TERMINATED = "terminated"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Session base + concrete classes
# ---------------------------------------------------------------------------


@dataclass
class SessionBase(ABC):
    """Abstract base for all session types."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_type: SessionType = SessionType.ANALYSIS
    state: SessionState = SessionState.ACTIVE
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """Update last access time."""
        self.last_accessed = time.time()

    @property
    def idle_seconds(self) -> float:
        """Seconds since last access."""
        return time.time() - self.last_accessed

    @abstractmethod
    async def cleanup(self) -> None:
        """Release all resources held by this session."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize session for status reporting."""
        return {
            "session_id": self.session_id,
            "type": self.session_type.value,
            "state": self.state.value,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "idle_seconds": round(self.idle_seconds, 1),
            "metadata": self.metadata,
        }


@dataclass
class DebuggerSession(SessionBase):
    """Session for GDB or LLDB."""

    session_type: SessionType = SessionType.DEBUGGER
    backend: str = "gdb"  # gdb | lldb
    process: Any = None  # subprocess.Popen or similar
    pid: int | None = None
    target_binary: str | None = None
    breakpoints: dict[int, dict[str, Any]] = field(default_factory=dict)
    _bp_counter: int = 0

    def next_bp_id(self) -> int:
        self._bp_counter += 1
        return self._bp_counter

    async def cleanup(self) -> None:
        """Terminate debugger process."""
        logger.info("Cleaning up debugger session %s (%s)", self.session_id[:8], self.backend)
        self.state = SessionState.TERMINATED
        if self.process is not None:
            try:
                if hasattr(self.process, "terminate"):
                    self.process.terminate()
                if hasattr(self.process, "wait"):
                    # Give it a moment to die gracefully
                    try:
                        if asyncio.iscoroutinefunction(getattr(self.process, "wait", None)):
                            await asyncio.wait_for(self.process.wait(), timeout=5)
                        else:
                            self.process.wait(timeout=5)
                    except Exception:
                        if hasattr(self.process, "kill"):
                            self.process.kill()
            except Exception as e:
                logger.warning("Error cleaning up debugger process: %s", e)
            finally:
                self.process = None


@dataclass
class FridaSession(SessionBase):
    """Session for Frida instrumentation."""

    session_type: SessionType = SessionType.FRIDA
    device_type: str = "local"  # local | usb | remote
    pid: int | None = None
    target_name: str | None = None
    target_binary: str | None = None
    frida_session: Any = None  # frida.core.Session
    scripts: dict[str, Any] = field(default_factory=dict)  # script_id -> Script

    async def cleanup(self) -> None:
        """Detach Frida session and unload scripts."""
        logger.info("Cleaning up Frida session %s", self.session_id[:8])
        self.state = SessionState.TERMINATED

        # Unload scripts
        for script_id, script in list(self.scripts.items()):
            try:
                if hasattr(script, "unload"):
                    script.unload()
            except Exception as e:
                logger.warning("Error unloading script %s: %s", script_id, e)
        self.scripts.clear()

        # Detach session
        if self.frida_session is not None:
            try:
                if hasattr(self.frida_session, "detach"):
                    self.frida_session.detach()
            except Exception as e:
                logger.warning("Error detaching Frida session: %s", e)
            finally:
                self.frida_session = None


@dataclass
class AnalysisSession(SessionBase):
    """Session for persistent analysis state (r2, angr projects, etc.)."""

    session_type: SessionType = SessionType.ANALYSIS
    binary_path: str | None = None
    binary_hash: str | None = None
    backend: str = "generic"  # r2 | angr | ghidra
    handle: Any = None  # r2pipe instance, angr.Project, etc.
    cache: dict[str, Any] = field(default_factory=dict)

    async def cleanup(self) -> None:
        """Close analysis handles."""
        logger.info("Cleaning up analysis session %s (%s)", self.session_id[:8], self.backend)
        self.state = SessionState.TERMINATED

        if self.handle is not None:
            try:
                if hasattr(self.handle, "quit"):
                    self.handle.quit()
                elif hasattr(self.handle, "close"):
                    self.handle.close()
            except Exception as e:
                logger.warning("Error cleaning up analysis handle: %s", e)
            finally:
                self.handle = None


# ---------------------------------------------------------------------------
# Binary Resource tracking
# ---------------------------------------------------------------------------


@dataclass
class BinaryResource:
    """A binary file tracked as an MCP resource."""

    uri: str
    name: str
    path: Path
    size: int
    mime_type: str = "application/octet-stream"
    hashes: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------


class SessionManager:
    """
    Thread-safe session manager with TTL-based cleanup.

    All public methods acquire the async lock to ensure thread safety.
    Sessions are keyed by UUID and auto-cleaned after idle timeout.
    """

    DEFAULT_TTL = 1800  # 30 minutes

    def __init__(self, ttl: int = DEFAULT_TTL) -> None:
        self._lock = asyncio.Lock()
        self._sessions: dict[str, SessionBase] = {}
        self._resources: dict[str, BinaryResource] = {}
        self._ttl = ttl
        self._cleanup_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Session manager started (TTL=%ds)", self._ttl)

    async def stop(self) -> None:
        """Stop the cleanup task and close all sessions."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            self._cleanup_task = None

        # Cleanup all sessions
        async with self._lock:
            for session in list(self._sessions.values()):
                try:
                    await session.cleanup()
                except Exception as e:
                    logger.warning("Error during shutdown cleanup: %s", e)
            self._sessions.clear()

        logger.info("Session manager stopped")

    # ---- Session CRUD ----

    async def create_session(self, session: SessionBase) -> str:
        """Register a new session, return its ID."""
        async with self._lock:
            self._sessions[session.session_id] = session
            logger.info(
                "Created %s session: %s",
                session.session_type.value,
                session.session_id[:8],
            )
            return session.session_id

    async def get_session(self, session_id: str) -> SessionBase:
        """Get a session by ID, updating its last access time."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"Session not found: {session_id}")
            if session.state == SessionState.TERMINATED:
                raise KeyError(f"Session terminated: {session_id}")
            session.touch()
            return session

    async def get_typed_session(self, session_id: str, expected_type: type) -> Any:
        """Get a session and verify its type."""
        session = await self.get_session(session_id)
        if not isinstance(session, expected_type):
            raise TypeError(
                f"Expected {expected_type.__name__}, got {type(session).__name__} "
                f"for session {session_id}"
            )
        return session

    async def close_session(self, session_id: str) -> None:
        """Explicitly close and remove a session."""
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if session:
                await session.cleanup()
                logger.info("Closed session: %s", session_id[:8])

    async def list_sessions(self) -> list[dict[str, Any]]:
        """List all active sessions."""
        async with self._lock:
            return [
                s.to_dict()
                for s in self._sessions.values()
                if s.state != SessionState.TERMINATED
            ]

    # ---- Resource management ----

    async def register_resource(self, resource: BinaryResource) -> str:
        """Register a binary resource, return its URI."""
        async with self._lock:
            self._resources[resource.uri] = resource
            logger.info("Registered resource: %s (%s)", resource.name, resource.uri)
            return resource.uri

    async def list_binary_resources(self) -> list[dict[str, Any]]:
        """List all registered binary resources."""
        async with self._lock:
            return [
                {
                    "uri": r.uri,
                    "name": r.name,
                    "size": r.size,
                    "mime_type": r.mime_type,
                    "hashes": r.hashes,
                }
                for r in self._resources.values()
            ]

    async def read_resource(self, uri: str) -> bytes:
        """Read the content of a binary resource."""
        async with self._lock:
            resource = self._resources.get(uri)
            if resource is None:
                raise KeyError(f"Resource not found: {uri}")
            if not resource.path.exists():
                raise FileNotFoundError(f"Resource file missing: {resource.path}")
            return resource.path.read_bytes()

    async def get_resource_info(self, uri: str) -> BinaryResource:
        """Get resource metadata."""
        async with self._lock:
            resource = self._resources.get(uri)
            if resource is None:
                raise KeyError(f"Resource not found: {uri}")
            return resource

    # ---- TTL cleanup ----

    async def _cleanup_loop(self) -> None:
        """Background task that cleans up idle sessions."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in session cleanup loop: %s", e)

    async def _cleanup_expired(self) -> None:
        """Remove sessions that have been idle longer than TTL."""
        async with self._lock:
            expired = [
                sid
                for sid, session in self._sessions.items()
                if session.idle_seconds > self._ttl
                and session.state != SessionState.TERMINATED
            ]

            for sid in expired:
                session = self._sessions.pop(sid)
                logger.info(
                    "Expiring idle session: %s (%s, idle %.0fs)",
                    sid[:8],
                    session.session_type.value,
                    session.idle_seconds,
                )
                try:
                    await session.cleanup()
                except Exception as e:
                    logger.warning("Error cleaning up expired session %s: %s", sid[:8], e)

    # ---- Stats ----

    async def stats(self) -> dict[str, Any]:
        """Get session manager statistics."""
        async with self._lock:
            by_type: dict[str, int] = {}
            for s in self._sessions.values():
                if s.state != SessionState.TERMINATED:
                    by_type[s.session_type.value] = by_type.get(s.session_type.value, 0) + 1

            return {
                "total_sessions": len(self._sessions),
                "active_by_type": by_type,
                "total_resources": len(self._resources),
                "ttl_seconds": self._ttl,
            }
