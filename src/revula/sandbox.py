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
from typing import TYPE_CHECKING, Literal

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
    path_kind: Literal["file", "dir", "any"] = "file",
) -> Path:
    """
    Validate and resolve a path for security.

    Rules:
    1. No null bytes in path (truncation attack prevention)
    2. Must be absolute (unless allow_relative)
    3. Resolve symlinks BEFORE checking allowed dirs (symlink escape prevention)
    4. Block dangerous pseudo-filesystems (/proc, /sys, /dev)
    5. Must not contain path traversal components
    6. Must be under one of the allowed directories (if specified)
    7. Extension whitelist (if specified)
    8. Type check based on path_kind (file/dir/any) when must_exist=True
    9. File size limit (files only, if must_exist=True)

    Returns the resolved Path.
    """
    # Null byte attack prevention
    if "\x00" in str(path):
        raise PathValidationError("Null byte in path — rejected")

    p = Path(path)
    if path_kind not in {"file", "dir", "any"}:
        raise ValueError(
            f"Invalid path_kind '{path_kind}'. Expected one of: file, dir, any."
        )

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

    # Check allowed directories (fail-closed).
    # If no allowlist is provided, load config defaults; if that fails or resolves
    # to an empty list, deny path access rather than silently allowing it.
    if not allowed_dirs:
        try:
            from revula.config import get_config
            allowed_dirs = get_config().security.allowed_dirs
        except Exception as e:
            raise PathValidationError(
                "Could not load allowed directories from config; refusing access."
            ) from e
    if not allowed_dirs:
        raise PathValidationError(
            "No allowed directories configured; refusing path access."
        )
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
    if allowed_extensions and path_kind == "file":
        ext = resolved.suffix.lower()
        if ext not in allowed_extensions:
            raise PathValidationError(
                f"Extension '{ext}' not in allowed list: {allowed_extensions}"
            )

    # Existence and type checks
    if must_exist:
        if not resolved.exists():
            raise PathValidationError(f"Path does not exist: {resolved}")
        if path_kind == "file":
            if not resolved.is_file():
                raise PathValidationError(
                    f"Path is not a regular file: {resolved}"
                )
        elif path_kind == "dir":
            if not resolved.is_dir():
                raise PathValidationError(f"Path is not a directory: {resolved}")
        elif not (resolved.is_file() or resolved.is_dir()):
            raise PathValidationError(
                f"Path is not a regular file or directory: {resolved}"
            )

        if resolved.is_file():
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
    timeout: int | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    max_memory_mb: int | None = None,
    max_cpu_seconds: int | None = None,
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
    timeout, max_memory_mb, max_cpu_seconds = _resolve_security_limits(
        timeout=timeout,
        max_memory_mb=max_memory_mb,
        max_cpu_seconds=max_cpu_seconds,
    )

    preflight_error = _preflight_external_tool(cmd[0])
    if preflight_error:
        return SubprocessResult(
            stdout="",
            stderr=preflight_error,
            returncode=-1,
            timed_out=False,
            command=cmd,
        )

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
    timeout: int | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    max_memory_mb: int | None = None,
    max_cpu_seconds: int | None = None,
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
    timeout: int | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    max_memory_mb: int | None = None,
    max_cpu_seconds: int | None = None,
) -> AsyncGenerator[str, None]:
    """
    Execute a subprocess and yield stdout lines as they arrive.

    For long-running operations like Ghidra analysis that need progress streaming.
    """
    if not cmd:
        raise ValueError("Empty command")

    cmd = [str(c) for c in cmd]
    timeout, max_memory_mb, max_cpu_seconds = _resolve_security_limits(
        timeout=timeout,
        max_memory_mb=max_memory_mb,
        max_cpu_seconds=max_cpu_seconds,
    )

    preflight_error = _preflight_external_tool(cmd[0])
    if preflight_error:
        yield f"[ERROR] {preflight_error}"
        return

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


def _resolve_security_limits(
    *,
    timeout: int | None,
    max_memory_mb: int | None,
    max_cpu_seconds: int | None,
) -> tuple[int, int, int]:
    """Resolve subprocess security limits from explicit args or global security config."""
    security = get_security_config()

    effective_timeout = security.default_timeout if timeout is None else int(timeout)
    if effective_timeout <= 0:
        raise ValueError("timeout must be > 0")
    effective_timeout = min(effective_timeout, security.max_timeout)

    effective_memory = security.max_memory_mb if max_memory_mb is None else int(max_memory_mb)
    if effective_memory <= 0:
        raise ValueError("max_memory_mb must be > 0")

    effective_cpu = effective_timeout if max_cpu_seconds is None else int(max_cpu_seconds)
    if effective_cpu <= 0:
        raise ValueError("max_cpu_seconds must be > 0")
    effective_cpu = min(effective_cpu, security.max_timeout)

    return effective_timeout, effective_memory, effective_cpu


def _preflight_external_tool(command: str) -> str | None:
    """Return a clear install hint when a known external tool is unavailable."""
    # Explicit paths should proceed to normal subprocess execution.
    command_path = Path(command)
    if command_path.is_absolute() and command_path.exists():
        return None

    from revula.config import TOOL_BINARIES, get_config

    config = get_config()
    command_name = command_path.name.lower()
    for tool_name, candidates in TOOL_BINARIES.items():
        normalized_candidates = {Path(c).name.lower() for c in candidates}
        if command_name not in normalized_candidates:
            continue

        info = config.tools.get(tool_name)
        if info and not info.available:
            hint = f" {info.install_hint}" if info.install_hint else ""
            return f"Required external tool '{tool_name}' is not installed.{hint}"
        break

    return None
