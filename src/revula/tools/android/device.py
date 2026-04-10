"""
Revula Android Device Management — ADB bridge + Frida server setup.

Provides tools for device listing, app management, Frida server deployment,
logcat streaming, and screenshot/screenrecord.
"""

from __future__ import annotations

import logging
import shutil
from typing import Any

from revula.sandbox import SubprocessResult, safe_subprocess, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


def _adb() -> str | None:
    """Find adb binary."""
    return shutil.which("adb")


async def _adb_cmd(
    args: list[str],
    device: str | None = None,
    timeout: int = 30,
) -> SubprocessResult:
    """Run an adb command."""
    adb_path = _adb()
    if not adb_path:
        return SubprocessResult(stdout="", stderr="adb not found on PATH", returncode=-1)

    cmd = [adb_path]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)

    return await safe_subprocess(cmd, timeout=timeout)


# ---------------------------------------------------------------------------
# Tool: re_android_device
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_device",
    description=(
        "Manage Android devices via ADB: list devices, get device info, "
        "install/uninstall apps, push/pull files, start Frida server, logcat."
    ),
    category="android",
    requires_tools=["adb"],
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "list_devices",
                    "device_info",
                    "list_packages",
                    "install_apk",
                    "uninstall_package",
                    "push_file",
                    "pull_file",
                    "shell",
                    "logcat",
                    "start_frida_server",
                    "screenshot",
                    "get_pid",
                ],
                "description": "Action to perform.",
            },
            "device": {
                "type": "string",
                "description": "Device serial (from list_devices). Required when multiple devices.",
            },
            "package_name": {
                "type": "string",
                "description": "Package name for install/uninstall/get_pid/logcat filter.",
            },
            "apk_path": {
                "type": "string",
                "description": "Local APK path for install.",
            },
            "local_path": {
                "type": "string",
                "description": "Local file path for push/pull.",
            },
            "remote_path": {
                "type": "string",
                "description": "Remote device path for push/pull.",
            },
            "shell_command": {
                "type": "string",
                "description": "Shell command for 'shell' action.",
            },
            "frida_server_path": {
                "type": "string",
                "description": "Local path to Frida server binary for start_frida_server.",
            },
            "logcat_lines": {
                "type": "integer",
                "description": "Number of logcat lines to return. Default: 100.",
            },
        },
    },
)
async def handle_device(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Handle Android device management."""
    action = arguments["action"]
    device = arguments.get("device")

    if action == "list_devices":
        proc = await _adb_cmd(["devices", "-l"])
        if proc.returncode != 0:
            return error_result(f"adb devices failed: {proc.stderr}")

        devices: list[dict[str, str]] = []
        for line in proc.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "offline":
                dev: dict[str, str] = {"serial": parts[0], "state": parts[1]}
                for kv in parts[2:]:
                    if ":" in kv:
                        k, v = kv.split(":", 1)
                        dev[k] = v
                devices.append(dev)
        return text_result({"devices": devices})

    elif action == "device_info":
        props = [
            "ro.product.model", "ro.product.manufacturer",
            "ro.build.version.release", "ro.build.version.sdk",
            "ro.product.cpu.abi", "ro.debuggable",
            "ro.build.type", "ro.build.display.id",
        ]
        info: dict[str, str] = {}
        for prop in props:
            proc = await _adb_cmd(["shell", "getprop", prop], device=device)
            if proc.returncode == 0:
                info[prop] = proc.stdout.strip()

        # Check root
        proc = await _adb_cmd(["shell", "id"], device=device)
        info["current_user"] = proc.stdout.strip() if proc.returncode == 0 else "unknown"
        info["is_root"] = str("uid=0" in (proc.stdout or ""))

        # Check Frida server
        proc = await _adb_cmd(
            ["shell", "ps -A | grep frida-server || echo 'not running'"],
            device=device,
        )
        info["frida_server"] = "running" if "frida-server" in (proc.stdout or "") else "not running"

        return text_result(info)

    elif action == "list_packages":
        flags = "-3"  # Third-party only by default
        proc = await _adb_cmd(["shell", "pm", "list", "packages", flags], device=device)
        if proc.returncode != 0:
            return error_result(f"Failed to list packages: {proc.stderr}")

        packages = [
            line.replace("package:", "").strip()
            for line in proc.stdout.strip().split("\n")
            if line.startswith("package:")
        ]
        return text_result({"packages": sorted(packages), "count": len(packages)})

    elif action == "install_apk":
        apk_path = arguments.get("apk_path")
        if not apk_path:
            return error_result("apk_path required for install")
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        validated = validate_path(apk_path, allowed_dirs=allowed_dirs)
        proc = await _adb_cmd(["install", "-r", str(validated)], device=device, timeout=120)
        if proc.returncode != 0:
            return error_result(f"Install failed: {proc.stderr}")
        return text_result({"message": "APK installed", "output": proc.stdout.strip()})

    elif action == "uninstall_package":
        pkg = arguments.get("package_name")
        if not pkg:
            return error_result("package_name required for uninstall")
        proc = await _adb_cmd(["uninstall", pkg], device=device)
        return text_result({"message": proc.stdout.strip() if proc.returncode == 0 else f"Failed: {proc.stderr}"})

    elif action == "push_file":
        local = arguments.get("local_path")
        remote = arguments.get("remote_path")
        if not local or not remote:
            return error_result("local_path and remote_path required for push")
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        validated_local = validate_path(local, allowed_dirs=allowed_dirs)
        proc = await _adb_cmd(["push", str(validated_local), remote], device=device, timeout=120)
        return text_result({
            "success": proc.returncode == 0,
            "output": proc.stdout.strip(),
            "error": proc.stderr.strip(),
        })

    elif action == "pull_file":
        remote = arguments.get("remote_path")
        import tempfile
        local = arguments.get("local_path", tempfile.gettempdir())
        if not remote:
            return error_result("remote_path required for pull")
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        validated_local = validate_path(local, allowed_dirs=allowed_dirs, must_exist=False)
        proc = await _adb_cmd(["pull", remote, str(validated_local)], device=device, timeout=120)
        return text_result({
            "success": proc.returncode == 0,
            "output": proc.stdout.strip(),
            "local_path": str(validated_local),
        })

    elif action == "shell":
        shell_cmd = arguments.get("shell_command")
        if not shell_cmd:
            return error_result("shell_command required for shell action")
        # Split by spaces for safe_subprocess (no shell=True)
        proc = await _adb_cmd(["shell", shell_cmd], device=device, timeout=60)
        return text_result({"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr})

    elif action == "logcat":
        lines = arguments.get("logcat_lines", 100)
        pkg = arguments.get("package_name")
        cmd = ["logcat", "-d", "-t", str(lines)]

        if pkg:
            # Get PID for package filter
            proc = await _adb_cmd(["shell", "pidof", pkg], device=device)
            pid = proc.stdout.strip()
            if pid:
                cmd.extend(["--pid", pid])

        proc = await _adb_cmd(cmd, device=device, timeout=30)
        return text_result({"logcat": proc.stdout, "lines": len(proc.stdout.strip().split("\n"))})

    elif action == "start_frida_server":
        frida_path = arguments.get("frida_server_path")
        if not frida_path:
            return error_result("frida_server_path required")

        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        validated_frida = validate_path(frida_path, allowed_dirs=allowed_dirs)

        # Push Frida server to device
        remote = "/data/local/tmp/frida-server"
        proc = await _adb_cmd(["push", str(validated_frida), remote], device=device, timeout=120)
        if proc.returncode != 0:
            return error_result(f"Failed to push frida-server: {proc.stderr}")

        # chmod + start
        await _adb_cmd(["shell", "chmod", "755", remote], device=device)
        # Kill existing
        await _adb_cmd(["shell", "pkill", "-f", "frida-server"], device=device)
        # Start in background (we use & to background it)
        await _adb_cmd(
            ["shell", f"{remote} -D &"],
            device=device,
            timeout=5,
        )

        return text_result({
            "message": "Frida server started",
            "remote_path": remote,
        })

    elif action == "screenshot":
        remote = "/data/local/tmp/revula_screenshot.png"
        proc = await _adb_cmd(["shell", "screencap", "-p", remote], device=device)
        if proc.returncode != 0:
            return error_result(f"Screenshot failed: {proc.stderr}")

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".png", prefix="revula_screenshot_", delete=False) as tmp:
            local = tmp.name
        await _adb_cmd(["pull", remote, local], device=device)
        return text_result({"screenshot_path": local, "remote_path": remote})

    elif action == "get_pid":
        pkg = arguments.get("package_name")
        if not pkg:
            return error_result("package_name required")
        proc = await _adb_cmd(["shell", "pidof", pkg], device=device)
        pid = proc.stdout.strip()
        return text_result({"package": pkg, "pid": int(pid) if pid.isdigit() else None})

    return error_result(f"Unknown action: {action}")
