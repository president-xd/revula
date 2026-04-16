"""
Revula Decompiler — multi-backend decompilation with caching.

Backends:
- Ghidra headless (analyzeHeadless) — primary, with project caching by binary hash
- Binary Ninja API (if licensed)
- RetDec (open source fallback)

Ghidra headless takes ~30s on first run — streams progress.
Caches analysis DB in ~/.revula/ghidra_projects/ keyed by binary hash.
Never re-analyzes the same binary twice.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

from revula.config import CACHE_DIR, GHIDRA_PROJECTS_DIR
from revula.sandbox import safe_subprocess, safe_subprocess_streaming, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ghidra discovery helpers
# ---------------------------------------------------------------------------


def _find_java_cmd() -> str:
    """Find the Java executable for Ghidra."""
    import shutil

    # Check JAVA_HOME first
    java_home = os.environ.get("JAVA_HOME", "")
    if java_home:
        cmd = Path(java_home) / "bin" / "java"
        if cmd.exists():
            return str(cmd)

    # Try common JDK locations
    for jdk_path in [
        "/usr/lib/jvm/java-21-openjdk-amd64",
        "/usr/lib/jvm/java-17-openjdk-amd64",
        "/usr/lib/jvm/default-java",
    ]:
        cmd = Path(jdk_path) / "bin" / "java"
        if cmd.exists():
            return str(cmd)

    # Fallback to PATH
    java = shutil.which("java")
    if java:
        return java

    raise RuntimeError("Java not found. Install JDK 17+ for Ghidra.")


def _find_ghidra_install() -> Path:
    """Find the Ghidra installation directory."""
    candidates = [
        Path("/usr/share/ghidra"),
        Path.home() / "ghidra",
        Path("/opt/ghidra"),
    ]
    # Check GHIDRA_INSTALL_DIR env
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if env_dir:
        candidates.insert(0, Path(env_dir))

    for p in candidates:
        if (p / "Ghidra").is_dir():
            return p

    raise RuntimeError("Ghidra installation not found. Set GHIDRA_INSTALL_DIR or install to /usr/share/ghidra")


# ---------------------------------------------------------------------------
# Ghidra headless backend
# ---------------------------------------------------------------------------


def _get_binary_hash(file_path: Path) -> str:
    """Compute SHA256 hash of binary for caching."""
    return hashlib.sha256(file_path.read_bytes()).hexdigest()


async def _decompile_ghidra(
    binary_path: Path,
    function: str,
    binary_hash: str,
    progress: Callable[[float, float | None, str | None], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """
    Decompile using Ghidra headless.

    Caches the analysis project by binary hash. Re-uses existing analysis
    if the binary hasn't changed.
    """
    project_dir = GHIDRA_PROJECTS_DIR / binary_hash[:16]
    project_name = f"revula_{binary_hash[:8]}"

    # Check if project already exists (cached analysis)
    project_exists = (project_dir / f"{project_name}.gpr").exists()

    # Build Ghidra command — call Java directly to bypass LaunchSupport JDK issues
    java_cmd = _find_java_cmd()
    ghidra_install = _find_ghidra_install()
    utility_jar = ghidra_install / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    scripts_dir = str(Path(__file__).parent.parent.parent / "scripts")

    if not utility_jar.exists():
        raise RuntimeError(f"Ghidra Utility.jar not found at {utility_jar}")

    # Base Java args for Ghidra headless
    java_base = [
        java_cmd,
        "-Djava.system.class.loader=ghidra.GhidraClassLoader",
        "-Dfile.encoding=UTF8",
        "-Djava.awt.headless=true",
        "-Dpython.console.encoding=UTF-8",
        "-Xshare:off",
        "-XX:ParallelGCThreads=2",
        "-XX:CICompilerCount=2",
        "-Xmx1500M",
        "-cp",
        str(utility_jar),
        "ghidra.Ghidra",
        "ghidra.app.util.headless.AnalyzeHeadless",
    ]

    env = dict(os.environ)
    last_stdout = ""
    last_stderr = ""
    last_rc = 0

    if not project_exists:
        # Import and analyze binary
        project_dir.mkdir(parents=True, exist_ok=True)
        if progress is not None:
            await progress(0.15, 1.0, "Starting Ghidra import + analysis")

        cmd = [
            *java_base,
            str(project_dir),
            project_name,
            "-import",
            str(binary_path),
            "-overwrite",
            "-scriptPath",
            scripts_dir,
            "-postScript",
            "DecompileFunction.py",
            function,
            str(project_dir),
        ]

        success, last_stdout, last_stderr, last_rc = await _run_streamed_subprocess(
            cmd,
            timeout=300,
            max_memory_mb=65536,
            max_cpu_seconds=600,
            env=env,
            progress=progress,
            progress_message="Ghidra analysis in progress",
        )

        if not success:
            combined = (last_stdout or "") + "\n" + (last_stderr or "")
            # Check if it's just a script error — Ghidra may have still loaded
            if "Revula:" in combined or "/* Function" in combined:
                pass  # Script produced output despite non-zero exit
            else:
                # Try basic analysis without the custom script
                if progress is not None:
                    await progress(0.35, 1.0, "Retrying with basic Ghidra analysis")
                cmd_basic = [
                    *java_base,
                    str(project_dir),
                    project_name,
                    "-import",
                    str(binary_path),
                    "-overwrite",
                ]

                success, last_stdout, last_stderr, last_rc = await _run_streamed_subprocess(
                    cmd_basic,
                    timeout=300,
                    max_memory_mb=65536,
                    max_cpu_seconds=600,
                    env=env,
                    progress=progress,
                    progress_message="Ghidra fallback analysis running",
                )

                if not success:
                    err_msg = (last_stderr or last_stdout or "unknown error")[:500]
                    raise RuntimeError(f"Ghidra analysis failed: {err_msg}")
    else:
        # Process existing project
        env = dict(os.environ)
        if progress is not None:
            await progress(0.2, 1.0, "Using cached Ghidra project")

        cmd = [
            *java_base,
            str(project_dir),
            project_name,
            "-process",
            binary_path.name,
            "-noanalysis",
            "-scriptPath",
            scripts_dir,
            "-postScript",
            "DecompileFunction.py",
            function,
            str(project_dir),
        ]

        success, last_stdout, last_stderr, last_rc = await _run_streamed_subprocess(
            cmd,
            timeout=120,
            max_memory_mb=65536,
            max_cpu_seconds=300,
            env=env,
            progress=progress,
            progress_message="Ghidra decompilation in progress",
        )

        if not success:
            raise RuntimeError(f"Ghidra decompilation failed: {last_stderr[:500]}")

    # Look for output file — primary method (most reliable).
    # We only accept candidates under directories we control (the project dir
    # and its parent). The previous implementation also consulted a predictable
    # ``/tmp/<function>_decompiled.c`` path, which a local attacker could
    # pre-create as a symlink pointing to an arbitrary file the process can
    # read (information disclosure / symlink race). That location has been
    # removed, and every candidate is opened with O_NOFOLLOW so a symlink at
    # the expected location is refused rather than followed.
    code = ""
    output_file = project_dir / f"{function}_decompiled.c"

    def _read_regular_file_nofollow(path: Path) -> str | None:
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as err:
            logger.warning(
                "Refusing to read decompiler output at %s: %s", path, err
            )
            return None
        try:
            st = os.fstat(fd)
            import stat as _stat
            if not _stat.S_ISREG(st.st_mode):
                logger.warning("Decompiler output %s is not a regular file", path)
                return None
            with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as fh:
                fd = -1  # ownership transferred
                return fh.read()
        finally:
            if fd >= 0:
                os.close(fd)

    for candidate in [
        output_file,
        project_dir.parent / f"{function}_decompiled.c",
    ]:
        data = _read_regular_file_nofollow(candidate)
        if data is not None:
            code = data
            break

    # Fallback: extract from stdout/stderr (Ghidra println() goes through log4j)
    if not code:
        combined_output = (last_stdout or "") + "\n" + (last_stderr or "")
        code = _extract_decompiled_from_output(combined_output)

    if not code or "not captured" in code:
        logger.warning(
            "Ghidra decompilation output not found. rc=%d stdout=%d stderr=%d",
            last_rc,
            len(last_stdout or ""),
            len(last_stderr or ""),
        )
        code = "(Decompiled output not captured — Ghidra analysis succeeded but script output not found)"

    return {
        "backend": "ghidra",
        "function": function,
        "cached": project_exists,
        "project_dir": str(project_dir),
        "decompiled_code": code,
    }


def _extract_decompiled_from_output(output: str) -> str:
    """Extract decompiled code from Ghidra stdout/stderr (fallback).

    Ghidra headless routes println() through its logger, so output lines
    are prefixed with ``INFO  DecompileFunction.py> ``.  We strip that
    prefix when present.
    """
    lines = output.splitlines()
    in_code = False
    code_lines: list[str] = []
    script_prefix = "DecompileFunction.py> "

    for line in lines:
        # Strip Ghidra INFO prefix if present
        clean = line
        if script_prefix in clean:
            clean = clean.split(script_prefix, 1)[1]

        if "/* Function" in clean:
            in_code = True
            continue
        if "/* End of decompilation */" in clean:
            break
        if in_code:
            code_lines.append(clean)

    return "\n".join(code_lines) if code_lines else "(Decompiled output not captured — check Ghidra project directly)"


# ---------------------------------------------------------------------------
# RetDec backend
# ---------------------------------------------------------------------------


async def _decompile_retdec(
    binary_path: Path,
    function: str | None = None,
) -> dict[str, Any]:
    """Decompile using RetDec (open source)."""
    from revula.config import get_config

    config = get_config()
    retdec_path = config.require_tool("retdec_decompiler")

    output_dir = CACHE_DIR / "retdec"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{binary_path.stem}.c"

    cmd = [retdec_path, str(binary_path), "-o", str(output_file)]

    if function:
        # Try to pass function address/name
        try:
            addr = int(function, 16) if function.startswith("0x") else int(function)
            cmd.extend(["--select-ranges", f"{addr:#x}-{addr + 0x1000:#x}"])
        except ValueError:
            cmd.extend(["--select-functions", function])

    result = await safe_subprocess(
        cmd,
        timeout=300,
        max_memory_mb=2048,
    )

    if not result.success:
        raise RuntimeError(f"RetDec failed: {result.stderr[:500]}")

    code = ""
    if output_file.exists():
        code = output_file.read_text()

    return {
        "backend": "retdec",
        "function": function,
        "output_file": str(output_file),
        "decompiled_code": code,
    }


# ---------------------------------------------------------------------------
# Binary Ninja backend (requires license)
# ---------------------------------------------------------------------------


async def _decompile_binja(
    binary_path: Path,
    function: str,
) -> dict[str, Any]:
    """Decompile using Binary Ninja API (requires license)."""
    import asyncio

    loop = asyncio.get_running_loop()

    def _do_binja() -> dict[str, Any]:
        import binaryninja

        bv = binaryninja.open_view(str(binary_path))
        try:
            # Find function by name or address
            func = None
            try:
                addr = int(function, 16) if function.startswith("0x") else int(function)
                func = bv.get_function_at(addr)
            except ValueError:
                for f in bv.functions:
                    if f.name == function:
                        func = f
                        break

            if func is None:
                raise ValueError(f"Function not found: {function}")

            # Get high-level IL (decompiled)
            hlil = func.hlil
            code_lines = []
            for line in hlil.root.lines:
                code_lines.append(str(line))

            return {
                "backend": "binaryninja",
                "function": function,
                "function_name": func.name,
                "address": f"0x{func.start:x}",
                "decompiled_code": "\n".join(code_lines),
            }
        finally:
            bv.file.close()

    return await loop.run_in_executor(None, _do_binja)


async def _run_streamed_subprocess(
    cmd: list[str],
    *,
    timeout: int,
    max_memory_mb: int,
    max_cpu_seconds: int,
    env: dict[str, str],
    progress: Callable[[float, float | None, str | None], Awaitable[None]] | None,
    progress_message: str,
) -> tuple[bool, str, str, int]:
    """Run a subprocess via streaming API and reconstruct a structured result."""
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    exit_code = 0
    line_counter = 0

    async for line in safe_subprocess_streaming(
        cmd,
        timeout=timeout,
        max_memory_mb=max_memory_mb,
        max_cpu_seconds=max_cpu_seconds,
        env=env,
        include_stderr=True,
        emit_exit_meta=True,
    ):
        if line.startswith("[stderr] "):
            stderr_lines.append(line.removeprefix("[stderr] "))
        elif line.startswith("[exit_code] "):
            try:
                exit_code = int(line.split(" ", 1)[1])
            except (ValueError, IndexError):
                exit_code = -1
        elif line.startswith("[TIMEOUT]") or line.startswith("[ERROR]"):
            stderr_lines.append(line)
            exit_code = -1
        else:
            stdout_lines.append(line)

        line_counter += 1
        if progress is not None and line_counter % 50 == 0:
            await progress(0.55, 1.0, progress_message)

    success = exit_code == 0 and not any(
        line.startswith("[TIMEOUT]") or line.startswith("[ERROR]") for line in stderr_lines
    )
    return success, "\n".join(stdout_lines), "\n".join(stderr_lines), exit_code


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_decompile",
    description=(
        "Decompile a function from a binary file to C pseudocode. "
        "Backends: Ghidra headless (primary, ~30s first run, cached by binary hash), "
        "Binary Ninja API (if licensed), RetDec (open source fallback). "
        "Specify function by address (0x...) or name."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file.",
            },
            "function": {
                "type": "string",
                "description": "Function address (e.g., '0x401000') or name (e.g., 'main').",
            },
            "backend": {
                "type": "string",
                "enum": ["ghidra", "retdec", "binaryninja", "auto"],
                "description": "Decompilation backend. 'auto' selects best available. Default: auto.",
                "default": "auto",
            },
        },
        "required": ["binary_path", "function"],
    },
    category="static",
)
async def handle_decompile(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Decompile a function from a binary."""
    binary_path_str = arguments["binary_path"]
    function = arguments["function"]
    backend = arguments.get("backend", "auto")
    progress = arguments.get("__progress__")
    progress_cb = progress if callable(progress) else None

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    if progress_cb is not None:
        await progress_cb(0.05, 1.0, "Preparing decompilation context")

    binary_hash = _get_binary_hash(file_path)

    if backend == "auto":
        # Priority: ghidra > binja > retdec
        # Check Ghidra via direct Java detection (we bypass analyzeHeadless)
        ghidra_available = False
        try:
            _find_java_cmd()
            _find_ghidra_install()
            ghidra_available = True
        except RuntimeError as e:
            logger.debug("Ghidra auto-detection failed: %s", e)

        if ghidra_available:
            backend = "ghidra"
        else:
            try:
                import importlib.util

                if importlib.util.find_spec("binaryninja"):
                    backend = "binaryninja"
                else:
                    raise ImportError("binaryninja not found")
            except ImportError:
                if config and config.is_available("retdec_decompiler"):
                    backend = "retdec"
                else:
                    return error_result(
                        "No decompilation backend available. Install one of: "
                        "Ghidra (https://ghidra-sre.org/), "
                        "Binary Ninja (https://binary.ninja/), "
                        "RetDec (https://github.com/avast/retdec)"
                    )

    try:
        if progress_cb is not None:
            await progress_cb(0.1, 1.0, f"Running backend: {backend}")
        if backend == "ghidra":
            result = await _decompile_ghidra(
                file_path,
                function,
                binary_hash,
                progress=progress_cb,
            )
        elif backend == "binaryninja":
            result = await _decompile_binja(file_path, function)
        elif backend == "retdec":
            result = await _decompile_retdec(file_path, function)
        else:
            return error_result(f"Unknown backend: {backend}")
    except Exception as e:
        return error_result(f"Decompilation failed ({backend}): {e}")

    if progress_cb is not None:
        await progress_cb(0.95, 1.0, "Packaging decompilation result")

    result["binary_path"] = str(file_path)
    result["binary_hash"] = binary_hash

    # Cap decompiled source size so a pathological function cannot exhaust
    # MCP transport buffers / client memory. 5 MB is well above any legitimate
    # single-function decompilation; anything larger is truncated with a
    # marker so callers know to re-run with a narrower target.
    max_decompiled_bytes = 5 * 1024 * 1024
    code = result.get("decompiled_code")
    if isinstance(code, str):
        encoded = code.encode("utf-8", errors="replace")
        if len(encoded) > max_decompiled_bytes:
            truncated = encoded[:max_decompiled_bytes].decode(
                "utf-8", errors="replace"
            )
            result["decompiled_code"] = (
                truncated
                + f"\n\n/* ... truncated: output exceeded "
                f"{max_decompiled_bytes} bytes ... */\n"
            )
            result["truncated"] = True
            result["original_size_bytes"] = len(encoded)

    return text_result(result)
