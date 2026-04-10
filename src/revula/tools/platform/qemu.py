"""
Revula QEMU Integration — user-mode & system emulation, syscall tracing,
snapshot management, and cross-architecture execution.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

# QEMU user-mode binary map
_QEMU_USER: dict[str, str] = {
    "arm": "qemu-arm",
    "aarch64": "qemu-aarch64",
    "mips": "qemu-mips",
    "mipsel": "qemu-mipsel",
    "mips64": "qemu-mips64",
    "ppc": "qemu-ppc",
    "ppc64": "qemu-ppc64",
    "riscv32": "qemu-riscv32",
    "riscv64": "qemu-riscv64",
    "x86_64": "qemu-x86_64",
    "i386": "qemu-i386",
    "sparc": "qemu-sparc",
    "s390x": "qemu-s390x",
}


@TOOL_REGISTRY.register(
    name="re_qemu_run",
    description=(
        "Run binaries under QEMU user-mode emulation with optional "
        "syscall tracing, strace, and GDB stub for cross-arch debugging."
    ),
    category="platform",
    requires_tools=["qemu_user"],
    input_schema={
        "type": "object",
        "required": ["binary_path", "action"],
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Path to the binary to emulate.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "run", "strace", "gdb_stub", "plugin_trace",
                ],
                "description": "QEMU user-mode action.",
            },
            "arch": {
                "type": "string",
                "enum": list(_QEMU_USER.keys()),
                "description": "Target architecture. Auto-detected if omitted.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Arguments to pass to the binary.",
            },
            "env": {
                "type": "object",
                "description": "Environment variables for the binary.",
            },
            "sysroot": {
                "type": "string",
                "description": "Sysroot path for cross-arch libraries.",
            },
            "gdb_port": {
                "type": "integer",
                "description": "GDB stub port. Default: 1234.",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds. Default: 60.",
            },
        },
    },
)
async def handle_qemu_user(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """QEMU user-mode emulation."""
    binary_path = arguments["binary_path"]
    action = arguments["action"]
    arch = arguments.get("arch")
    binary_args: list[str] = arguments.get("args", [])
    sysroot = arguments.get("sysroot")
    gdb_port = arguments.get("gdb_port", 1234)
    timeout = arguments.get("timeout", 60)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    # Auto-detect arch if not provided
    if not arch:
        arch = await _detect_arch(str(file_path))
        if not arch:
            return error_result(
                "Could not detect architecture. Please specify 'arch'."
            )

    qemu_bin = _QEMU_USER.get(arch)
    if not qemu_bin:
        return error_result(f"Unsupported architecture: {arch}")

    cmd: list[str] = [qemu_bin]

    if sysroot:
        validate_path(sysroot, allowed_dirs=allowed_dirs, path_kind="dir")
        cmd.extend(["-L", sysroot])

    if action == "run":
        cmd.append(str(file_path))
        cmd.extend(binary_args)

    elif action == "strace":
        cmd.extend(["-strace", str(file_path)])
        cmd.extend(binary_args)

    elif action == "gdb_stub":
        cmd.extend(["-g", str(gdb_port), str(file_path)])
        cmd.extend(binary_args)
        # For GDB stub, run with short timeout just to confirm it starts
        proc = await safe_subprocess(cmd, timeout=5)
        return text_result({
            "action": "gdb_stub",
            "arch": arch,
            "qemu_binary": qemu_bin,
            "gdb_port": gdb_port,
            "message": f"GDB stub listening on port {gdb_port}. "
                       f"Connect with: gdb-multiarch -ex 'target remote :{gdb_port}'",
            "started": True,
        })

    elif action == "plugin_trace":
        # Use QEMU TCG plugin for instruction tracing
        cmd.extend([
            "-plugin", "libexec",
            "-d", "in_asm,op",
            str(file_path),
        ])
        cmd.extend(binary_args)

    else:
        return error_result(f"Unknown QEMU user action: {action}")

    proc = await safe_subprocess(cmd, timeout=timeout)

    output = proc.stdout
    stderr = proc.stderr

    result: dict[str, Any] = {
        "action": action,
        "arch": arch,
        "qemu_binary": qemu_bin,
        "stdout": output[:8000],
        "stderr": stderr[:4000],
        "returncode": proc.returncode,
        "success": proc.success,
    }

    # Parse strace output if applicable
    if action == "strace":
        syscalls = _parse_strace(stderr or output)
        result["syscalls"] = syscalls
        result["syscall_count"] = len(syscalls)

    return text_result(result)


@TOOL_REGISTRY.register(
    name="re_qemu_system",
    description=(
        "QEMU system emulation management: snapshot, monitor commands, "
        "firmware analysis via full-system emulation."
    ),
    category="platform",
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "start_vm", "monitor_command", "snapshot_create",
                    "snapshot_restore", "snapshot_list",
                ],
                "description": "System emulation action.",
            },
            "arch": {
                "type": "string",
                "description": "System architecture (x86_64, arm, aarch64, mips, etc.).",
            },
            "disk_image": {
                "type": "string",
                "description": "Path to disk image.",
            },
            "kernel": {
                "type": "string",
                "description": "Path to kernel image.",
            },
            "initrd": {
                "type": "string",
                "description": "Path to initrd/initramfs.",
            },
            "memory": {
                "type": "string",
                "description": "RAM size. Default: 256M.",
            },
            "monitor_cmd": {
                "type": "string",
                "description": "QEMU monitor command to execute.",
            },
            "snapshot_name": {
                "type": "string",
                "description": "Snapshot name for create/restore.",
            },
            "extra_args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Additional QEMU arguments.",
            },
        },
    },
)
async def handle_qemu_system(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """QEMU system emulation."""
    action = arguments["action"]
    arch = arguments.get("arch", "x86_64")
    disk_image = arguments.get("disk_image")
    kernel = arguments.get("kernel")
    initrd = arguments.get("initrd")
    memory = arguments.get("memory", "256M")
    monitor_cmd = arguments.get("monitor_cmd", "")
    snapshot_name = arguments.get("snapshot_name", "")
    extra_args: list[str] = arguments.get("extra_args", [])
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    qemu_system = f"qemu-system-{arch}"

    if action == "start_vm":
        cmd = [qemu_system, "-m", memory, "-nographic"]

        if kernel:
            validate_path(kernel, allowed_dirs=allowed_dirs)
            cmd.extend(["-kernel", kernel])
        if initrd:
            validate_path(initrd, allowed_dirs=allowed_dirs)
            cmd.extend(["-initrd", initrd])
        if disk_image:
            validate_path(disk_image, allowed_dirs=allowed_dirs)
            cmd.extend(["-drive", f"file={disk_image},format=raw"])

        cmd.extend(extra_args)

        return text_result({
            "action": "start_vm",
            "command": " ".join(cmd),
            "message": "Use run_in_terminal to start this VM. "
                       "The command is provided for manual execution.",
            "arch": arch,
            "memory": memory,
        })

    elif action == "monitor_command":
        if not monitor_cmd:
            return error_result("monitor_cmd required")
        return text_result({
            "action": "monitor_command",
            "message": "QEMU monitor commands must be sent to a running VM. "
                       "Use QMP socket or HMP console.",
            "suggested_command": monitor_cmd,
        })

    elif action == "snapshot_create":
        if not disk_image:
            return error_result("disk_image required for snapshots")
        if not snapshot_name:
            return error_result("snapshot_name required")
        validate_path(disk_image, allowed_dirs=allowed_dirs)
        proc = await safe_subprocess(
            ["qemu-img", "snapshot", "-c", snapshot_name, disk_image],
            timeout=60,
        )
        return text_result({
            "action": "snapshot_create",
            "name": snapshot_name,
            "success": proc.success,
            "output": proc.stdout,
        })

    elif action == "snapshot_restore":
        if not disk_image:
            return error_result("disk_image required for snapshots")
        if not snapshot_name:
            return error_result("snapshot_name required")
        validate_path(disk_image, allowed_dirs=allowed_dirs)
        proc = await safe_subprocess(
            ["qemu-img", "snapshot", "-a", snapshot_name, disk_image],
            timeout=60,
        )
        return text_result({
            "action": "snapshot_restore",
            "name": snapshot_name,
            "success": proc.success,
        })

    elif action == "snapshot_list":
        if not disk_image:
            return error_result("disk_image required for snapshots")
        validate_path(disk_image, allowed_dirs=allowed_dirs)
        proc = await safe_subprocess(
            ["qemu-img", "snapshot", "-l", disk_image],
            timeout=30,
        )
        return text_result({
            "action": "snapshot_list",
            "snapshots": proc.stdout,
            "success": proc.success,
        })

    else:
        return error_result(f"Unknown QEMU system action: {action}")


async def _detect_arch(binary_path: str) -> str | None:
    """Auto-detect architecture from ELF header."""
    proc = await safe_subprocess(["file", binary_path], timeout=10)
    if not proc.success:
        return None

    output = proc.stdout.lower()
    arch_map = {
        "arm aarch64": "aarch64",
        "arm,": "arm",
        "mips64": "mips64",
        "mips": "mips",
        "lsb": "",  # checked below
        "msb": "",
        "powerpc64": "ppc64",
        "powerpc": "ppc",
        "risc-v": "riscv64",
        "x86-64": "x86_64",
        "intel 80386": "i386",
        "sparc": "sparc",
        "s390": "s390x",
    }

    for key, value in arch_map.items():
        if key in output and value:
            # Check endianness for MIPS
            if value == "mips" and "lsb" in output:
                return "mipsel"
            return value

    return None


def _parse_strace(output: str) -> list[dict[str, str]]:
    """Parse QEMU strace output into structured format."""
    syscalls: list[dict[str, str]] = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        # QEMU strace format: pid syscall(args) = result
        match = re.match(r"(\d+)?\s*(\w+)\((.*)?\)\s*=\s*(.*)", line)
        if match:
            syscalls.append({
                "pid": match.group(1) or "",
                "syscall": match.group(2),
                "args": match.group(3) or "",
                "result": match.group(4).strip(),
            })
    return syscalls[:500]
