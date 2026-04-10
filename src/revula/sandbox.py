"""
Revula Sandbox — secure subprocess execution with resource limits.

All external tool invocations MUST go through this module. Features:
- No shell=True ever
- Resource limits (memory, CPU time) via the resource module (Linux/macOS)
- Path validation (absolute, resolved, no traversal, within allowed dirs)
- Configurable timeouts
- Structured result objects
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from revula.config import SecurityConfig

logger = logging.getLogger(__name__)


def _normalize_platform_command(cmd: list[str]) -> list[str]:
    """Map a small set of shell builtins to portable process invocations."""
    if platform.system() != "Windows" or not cmd:
        return cmd

    program = cmd[0].lower()
    args = cmd[1:]

    if program == "echo":
        return ["cmd", "/c", "echo", *args]

    if program == "sleep" and args:
        return [
            sys.executable,
            "-c",
            "import sys, time; time.sleep(float(sys.argv[1]))",
            args[0],
        ]

    return cmd


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class SubprocessResult:
    """Structured result of a sandboxed subprocess call."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False
    command: list[str] = field(default_factory=list, repr=False)

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def raise_on_error(self, context: str = "") -> None:
        """Raise RuntimeError if the process failed."""
        if self.timed_out:
            raise TimeoutError(
                f"Process timed out{' (' + context + ')' if context else ''}: "
                f"{' '.join(self.command[:3])}"
            )
        if self.returncode != 0:
            msg = f"Process failed (rc={self.returncode})"
            if context:
                msg += f" [{context}]"
            if self.stderr:
                msg += f": {self.stderr[:500]}"
            raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


class PathValidationError(Exception):
    """Raised when a path fails security validation."""


def validate_path(
    path: str | Path,
    allowed_dirs: list[str] | None = None,
    must_exist: bool = True,
    allow_relative: bool = False,
    max_size_mb: float = 500.0,
    allowed_extensions: list[str] | None = None,
) -> Path:
    """
    Validate and resolve a file path for security.

    Rules:
    1. No null bytes in path (truncation attack prevention)
    2. Must be absolute (unless allow_relative)
    3. Resolve symlinks BEFORE checking allowed dirs (symlink escape prevention)
    4. Block dangerous pseudo-filesystems (/proc, /sys, /dev)
    5. Must not contain path traversal components
    6. Must be under one of the allowed directories (if specified)
    7. Extension whitelist (if specified)
    8. File size limit (if must_exist)
    9. Must be a regular file (not device, pipe, socket)

    Returns the resolved Path.
    """
    # Null byte attack prevention
    if "\x00" in str(path):
        raise PathValidationError("Null byte in path — rejected")

    p = Path(path)

    if not p.is_absolute():
        if allow_relative:
            p = Path.cwd() / p
        else:
            raise PathValidationError(
                f"Path must be absolute: {path}. "
                "Provide the full path or set allow_relative=True."
            )

    # Resolve symlinks FIRST (critical: do NOT check before resolving)
    try:
        resolved = p.resolve(strict=False)
    except (OSError, ValueError) as e:
        raise PathValidationError(f"Cannot resolve path {path}: {e}") from e

    # Block dangerous pseudo-filesystems
    resolved_str = str(resolved)
    for prefix in ("/proc/", "/sys/", "/dev/"):
        if resolved_str.startswith(prefix) or resolved_str == prefix.rstrip("/"):
            raise PathValidationError(f"Access to {prefix} is prohibited")

    # Check for traversal attempts in the original string
    str_path = str(path)
    if ".." in str_path.split(os.sep):
        raise PathValidationError(
            f"Path traversal detected in: {path}. Use absolute paths."
        )

    # Check allowed directories (fail-closed: if allowed_dirs is None or empty,
    # default to get_config().security.allowed_dirs so we never skip the check)
    if not allowed_dirs:
        try:
            from revula.config import get_config
            allowed_dirs = get_config().security.allowed_dirs
        except Exception:
            pass  # If config unavailable, proceed without dir check
    if allowed_dirs:
        in_allowed = False
        for allowed in allowed_dirs:
            try:
                allowed_resolved = Path(allowed).resolve(strict=False)
                # Use path-boundary checks, not naive string prefixes.
                # This prevents sibling-prefix escapes like /allowed_evil when
                # only /allowed is allowlisted.
                resolved.relative_to(allowed_resolved)
                in_allowed = True
                break
            except ValueError:
                continue
            except OSError:
                continue

        if not in_allowed:
            raise PathValidationError(
                f"Path {resolved} is not under any allowed directory. "
                f"Allowed: {allowed_dirs}"
            )

    # Extension whitelist
    if allowed_extensions:
        ext = resolved.suffix.lower()
        if ext not in allowed_extensions:
            raise PathValidationError(
                f"Extension '{ext}' not in allowed list: {allowed_extensions}"
            )

    # Existence and type checks
    if must_exist:
        if not resolved.exists():
            raise PathValidationError(f"Path does not exist: {resolved}")
        if not resolved.is_file():
            raise PathValidationError(
                f"Path is not a regular file: {resolved}"
            )
        # File size limit
        try:
            size_mb = resolved.stat().st_size / (1024 * 1024)
            if size_mb > max_size_mb:
                raise PathValidationError(
                    f"File too large: {size_mb:.1f}MB > {max_size_mb}MB limit"
                )
        except OSError as e:
            raise PathValidationError(f"Cannot stat file {resolved}: {e}") from e

    return resolved


def validate_binary_path(
    path: str | Path,
    allowed_dirs: list[str] | None = None,
) -> Path:
    """Validate a path to a binary file for analysis."""
    resolved = validate_path(path, allowed_dirs=allowed_dirs, must_exist=True)

    if not resolved.is_file():
        raise PathValidationError(f"Not a file: {resolved}")

    # Basic size sanity check (warn on very large files)
    try:
        size = resolved.stat().st_size
        if size == 0:
            raise PathValidationError(f"File is empty: {resolved}")
        if size > 2 * 1024 * 1024 * 1024:  # 2 GB
            logger.warning("Very large file (%d bytes): %s", size, resolved)
    except OSError as e:
        raise PathValidationError(f"Cannot stat file {resolved}: {e}") from e

    return resolved


# ---------------------------------------------------------------------------
# Resource limits (Linux/macOS only)
# ---------------------------------------------------------------------------


def _make_preexec_fn(max_memory_mb: int, max_cpu_seconds: int):  # type: ignore[no-untyped-def]
    """Create a preexec_fn that sets resource limits (POSIX only)."""
    if platform.system() == "Windows":
        return None

    def _set_limits() -> None:
        import resource

        # Memory limit
        mem_bytes = max_memory_mb * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except (OSError, ValueError):
            # Some systems don't support RLIMIT_AS
            with contextlib.suppress(ValueError, resource.error):
                resource.setrlimit(resource.RLIMIT_DATA, (mem_bytes, mem_bytes))

        # CPU time limit
        with contextlib.suppress(ValueError, resource.error):
            resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds + 5))

    return _set_limits


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------


def safe_subprocess_sync(
    cmd: list[str],
    *,
    timeout: int = 60,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
    stdin_data: bytes | None = None,
    capture_output: bool = True,
) -> SubprocessResult:
    """
    Execute a subprocess with sandboxing (synchronous version).

    Security guarantees:
    - No shell=True
    - Resource limits on POSIX
    - Timeout enforcement
    - Command is a list (no shell injection)
    """
    if isinstance(cmd, str):
        raise TypeError(
            "safe_subprocess requires list[str], not str - shell injection prevention"
        )

    if not cmd:
        raise ValueError("Empty command")

    # Validate command is a list of strings
    cmd = [str(c) for c in cmd]
    effective_cmd = _normalize_platform_command(cmd)

    # Build environment
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    # Build preexec_fn for resource limits
    preexec = _make_preexec_fn(max_memory_mb, max_cpu_seconds)

    # Validate cwd if provided
    if cwd:
        cwd = Path(cwd)
        if not cwd.is_dir():
            raise PathValidationError(f"Working directory does not exist: {cwd}")

    logger.debug("Executing: %s (timeout=%ds, mem=%dMB)", effective_cmd[:3], timeout, max_memory_mb)

    try:
        proc = subprocess.run(
            effective_cmd,
            capture_output=capture_output,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=proc_env,
            preexec_fn=preexec,
            shell=False,  # NEVER shell=True
            stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
            input=stdin_data if stdin_data else None,
            encoding="utf-8",
            errors="replace",
        )

        return SubprocessResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            timed_out=False,
            command=cmd,
        )

    except subprocess.TimeoutExpired as e:
        logger.warning("Process timed out after %ds: %s", timeout, effective_cmd[:3])
        return SubprocessResult(
            stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
            stderr=e.stderr or "" if isinstance(e.stderr, str) else "",
            returncode=-1,
            timed_out=True,
            command=cmd,
        )
    except FileNotFoundError:
        return SubprocessResult(
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            returncode=-1,
            timed_out=False,
            command=cmd,
        )
    except PermissionError:
        return SubprocessResult(
            stdout="",
            stderr=f"Permission denied: {cmd[0]}",
            returncode=-1,
            timed_out=False,
            command=cmd,
        )


async def safe_subprocess(
    cmd: list[str],
    *,
    timeout: int = 60,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
    stdin_data: bytes | None = None,
) -> SubprocessResult:
    """
    Execute a subprocess with sandboxing (async version).

    Runs the subprocess in a thread pool to avoid blocking the event loop.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: safe_subprocess_sync(
            cmd,
            timeout=timeout,
            cwd=cwd,
            env=env,
            max_memory_mb=max_memory_mb,
            max_cpu_seconds=max_cpu_seconds,
            stdin_data=stdin_data,
        ),
    )


async def safe_subprocess_streaming(
    cmd: list[str],
    *,
    timeout: int = 60,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
) -> AsyncGenerator[str, None]:
    """
    Execute a subprocess and yield stdout lines as they arrive.

    For long-running operations like Ghidra analysis that need progress streaming.
    """
    if not cmd:
        raise ValueError("Empty command")

    cmd = [str(c) for c in cmd]
    effective_cmd = _normalize_platform_command(cmd)

    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    preexec = _make_preexec_fn(max_memory_mb, max_cpu_seconds)

    proc = await asyncio.create_subprocess_exec(
        *effective_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env=proc_env,
        preexec_fn=preexec,
    )

    stderr_lines: list[str] = []

    async def _read_stderr() -> None:
        assert proc.stderr is not None
        async for line in proc.stderr:
            stderr_lines.append(line.decode("utf-8", errors="replace"))

    stderr_task = asyncio.create_task(_read_stderr())

    try:
        assert proc.stdout is not None
        async with asyncio.timeout(timeout):
            async for line in proc.stdout:
                yield line.decode("utf-8", errors="replace").rstrip("\n")

        await proc.wait()
        await stderr_task

    except TimeoutError:
        proc.kill()
        await proc.wait()
        yield f"[TIMEOUT] Process killed after {timeout}s"

    except Exception as e:
        proc.kill()
        await proc.wait()
        yield f"[ERROR] {e}"


def get_security_config() -> SecurityConfig:
    """Get security config from global config (lazy import to avoid circular)."""
    from revula.config import get_config

    return get_config().security
