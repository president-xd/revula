"""
Revula Android Repackaging — APK modification, resign, and Frida Gadget injection.

Tools for modifying APKs: decode → patch → rebuild → sign → align,
and automated Frida Gadget injection for instrumentation without root.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


def _find(name: str) -> str | None:
    return shutil.which(name)


# ---------------------------------------------------------------------------
# Tool: re_android_repack
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_repack",
    description=(
        "Decode, modify, and rebuild an Android APK. Workflow: "
        "decode (apktool d) → apply patches → rebuild (apktool b) → "
        "zipalign → sign (apksigner/jarsigner). "
        "Actions: decode, build, sign, full_repack."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {
                "type": "string",
                "enum": ["decode", "build", "sign", "zipalign", "full_repack"],
                "description": "Repackaging action.",
            },
            "apk_path": {
                "type": "string",
                "description": "Input APK path (for decode/full_repack).",
            },
            "decode_dir": {
                "type": "string",
                "description": "Decoded APK directory (for build/full_repack).",
            },
            "output_apk": {
                "type": "string",
                "description": "Output APK path.",
            },
            "keystore": {
                "type": "string",
                "description": "Keystore file for signing. Uses debug keystore if not provided.",
            },
            "keystore_pass": {
                "type": "string",
                "description": "Keystore password. Default: 'android'.",
            },
            "key_alias": {
                "type": "string",
                "description": "Key alias. Default: 'androiddebugkey'.",
            },
            "smali_patches": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "description": "Relative smali file path."},
                        "find": {"type": "string"},
                        "replace": {"type": "string"},
                    },
                },
                "description": "Smali patches to apply during full_repack.",
            },
        },
    },
)
async def handle_repack(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """APK repackaging."""
    action = arguments["action"]
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    if action == "decode":
        apk_path = arguments.get("apk_path")
        if not apk_path:
            return error_result("apk_path required for decode")
        file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

        apktool = _find("apktool")
        if not apktool:
            return error_result("apktool not found. Install: https://ibotpeaches.github.io/Apktool/")

        decode_dir = arguments.get("decode_dir") or tempfile.mkdtemp(prefix="revula_decode_")
        cmd = [apktool, "d", str(file_path), "-o", decode_dir, "-f"]
        proc = await safe_subprocess(cmd, timeout=120)

        if proc.returncode != 0:
            return error_result(f"apktool decode failed: {proc.stderr}")

        return text_result({
            "action": "decode",
            "decode_dir": decode_dir,
            "output": proc.stdout[:5000],
        })

    elif action == "build":
        decode_dir = arguments.get("decode_dir")
        if not decode_dir:
            return error_result("decode_dir required for build")
        validate_path(decode_dir, allowed_dirs=allowed_dirs, path_kind="dir")

        apktool = _find("apktool")
        if not apktool:
            return error_result("apktool not found")

        output_apk = arguments.get("output_apk") or os.path.join(decode_dir, "dist", "output.apk")
        cmd = [apktool, "b", decode_dir, "-o", output_apk]
        proc = await safe_subprocess(cmd, timeout=120)

        if proc.returncode != 0:
            return error_result(f"apktool build failed: {proc.stderr}")

        return text_result({
            "action": "build",
            "output_apk": output_apk,
            "size": os.path.getsize(output_apk) if os.path.exists(output_apk) else 0,
        })

    elif action == "zipalign":
        apk_path = arguments.get("apk_path") or arguments.get("output_apk")
        if not apk_path:
            return error_result("apk_path required for zipalign")

        zipalign = _find("zipalign")
        if not zipalign:
            return error_result("zipalign not found. Install Android SDK Build Tools.")

        aligned = apk_path.replace(".apk", "-aligned.apk")
        cmd = [zipalign, "-f", "4", apk_path, aligned]
        proc = await safe_subprocess(cmd, timeout=60)

        if proc.returncode != 0:
            return error_result(f"zipalign failed: {proc.stderr}")

        # Replace original
        shutil.move(aligned, apk_path)
        return text_result({"action": "zipalign", "output": apk_path})

    elif action == "sign":
        apk_path = arguments.get("apk_path") or arguments.get("output_apk")
        if not apk_path:
            return error_result("apk_path required for sign")

        keystore = arguments.get("keystore")
        ks_pass = arguments.get("keystore_pass", "android")
        alias = arguments.get("key_alias", "androiddebugkey")

        # Try apksigner first, fall back to jarsigner
        apksigner = _find("apksigner")
        if apksigner:
            if keystore:
                cmd = [
                    apksigner, "sign",
                    "--ks", keystore,
                    "--ks-pass", f"pass:{ks_pass}",
                    "--ks-key-alias", alias,
                    apk_path,
                ]
            else:
                # Generate a debug keystore
                debug_ks = _ensure_debug_keystore()
                cmd = [
                    apksigner, "sign",
                    "--ks", debug_ks,
                    "--ks-pass", "pass:android",
                    "--ks-key-alias", "androiddebugkey",
                    apk_path,
                ]
            proc = await safe_subprocess(cmd, timeout=60)
            if proc.returncode != 0:
                return error_result(f"apksigner failed: {proc.stderr}")
            return text_result({"action": "sign", "signer": "apksigner", "apk": apk_path})

        jarsigner = _find("jarsigner")
        if jarsigner:
            if not keystore:
                keystore = _ensure_debug_keystore()
            cmd = [
                jarsigner,
                "-keystore", keystore,
                "-storepass", ks_pass,
                "-sigalg", "SHA256withRSA",
                "-digestalg", "SHA-256",
                apk_path,
                alias,
            ]
            proc = await safe_subprocess(cmd, timeout=60)
            if proc.returncode != 0:
                return error_result(f"jarsigner failed: {proc.stderr}")
            return text_result({"action": "sign", "signer": "jarsigner", "apk": apk_path})

        return error_result("No signing tool found (apksigner or jarsigner)")

    elif action == "full_repack":
        apk_path = arguments.get("apk_path")
        if not apk_path:
            return error_result("apk_path required for full_repack")
        file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

        # Step 1: Decode
        decode_result = await handle_repack({
            **arguments,
            "action": "decode",
        })
        if any("error" in str(r) for r in decode_result):
            return decode_result

        decode_dir = arguments.get("decode_dir") or tempfile.mkdtemp(prefix="revula_decode_")

        # Step 2: Apply smali patches
        patches_applied = 0
        smali_patches = arguments.get("smali_patches", [])
        for patch in smali_patches:
            smali_file = os.path.join(decode_dir, patch.get("file", ""))
            if os.path.exists(smali_file):
                content = Path(smali_file).read_text(errors="replace")
                find = patch.get("find", "")
                replace = patch.get("replace", "")
                if find in content:
                    content = content.replace(find, replace)
                    Path(smali_file).write_text(content)
                    patches_applied += 1

        # Step 3: Build
        output_apk = arguments.get("output_apk") or str(file_path).replace(
            ".apk", "-repack.apk"
        )
        build_args = {**arguments, "action": "build", "decode_dir": decode_dir, "output_apk": output_apk}
        await handle_repack(build_args)

        # Step 4: Sign
        sign_args = {**arguments, "action": "sign", "apk_path": output_apk}
        await handle_repack(sign_args)

        return text_result({
            "action": "full_repack",
            "original": str(file_path),
            "output": output_apk,
            "decode_dir": decode_dir,
            "patches_applied": patches_applied,
            "size": os.path.getsize(output_apk) if os.path.exists(output_apk) else 0,
        })

    return error_result(f"Unknown action: {action}")


def _ensure_debug_keystore() -> str:
    """Ensure a debug keystore exists."""
    debug_ks = os.path.expanduser("~/.android/debug.keystore")
    if os.path.exists(debug_ks):
        return debug_ks

    # Create one
    os.makedirs(os.path.dirname(debug_ks), exist_ok=True)
    keytool = _find("keytool")
    if keytool:
        from revula.sandbox import safe_subprocess_sync

        safe_subprocess_sync(
            [
                keytool, "-genkey", "-v",
                "-keystore", debug_ks,
                "-alias", "androiddebugkey",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-storepass", "android",
                "-keypass", "android",
                "-dname", "CN=Android Debug,O=Android,C=US",
            ],
            timeout=30,
        )
    return debug_ks


# ---------------------------------------------------------------------------
# Tool: re_android_gadget_inject
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_gadget_inject",
    description=(
        "Inject Frida Gadget into an APK for instrumentation without root. "
        "Decodes APK, injects gadget .so + config into native libs, patches "
        "smali to load the library, rebuilds and signs."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["apk_path", "gadget_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Input APK path.",
            },
            "gadget_path": {
                "type": "string",
                "description": "Path to frida-gadget-*.so (matching target arch).",
            },
            "gadget_config": {
                "type": "object",
                "description": "Frida Gadget config (JSON). Optional.",
            },
            "target_arch": {
                "type": "string",
                "enum": ["armeabi-v7a", "arm64-v8a", "x86", "x86_64"],
                "description": "Target architecture. Default: arm64-v8a.",
            },
            "output_apk": {
                "type": "string",
                "description": "Output APK path.",
            },
            "gadget_lib_name": {
                "type": "string",
                "description": "Name for injected lib. Default: libfrida-gadget.so.",
            },
        },
    },
)
async def handle_gadget_inject(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Inject Frida Gadget into APK."""
    apk_path = arguments["apk_path"]
    gadget_path = arguments["gadget_path"]
    gadget_config = arguments.get("gadget_config")
    arch = arguments.get("target_arch", "arm64-v8a")
    output_apk = arguments.get("output_apk")
    gadget_name = arguments.get("gadget_lib_name", "libfrida-gadget.so")
    config_arg = arguments.get("__config__")
    allowed_dirs = config_arg.security.allowed_dirs if config_arg else None

    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)
    gadget_file = validate_binary_path(gadget_path, allowed_dirs=allowed_dirs)

    apktool = _find("apktool")
    if not apktool:
        return error_result("apktool required for gadget injection")

    # Step 1: Decode
    decode_dir = tempfile.mkdtemp(prefix="revula_gadget_")
    cmd = [apktool, "d", str(file_path), "-o", decode_dir, "-f"]
    proc = await safe_subprocess(cmd, timeout=120)
    if proc.returncode != 0:
        return error_result(f"Decode failed: {proc.stderr}")

    # Step 2: Inject gadget .so
    lib_dir = os.path.join(decode_dir, "lib", arch)
    os.makedirs(lib_dir, exist_ok=True)

    gadget_dest = os.path.join(lib_dir, gadget_name)
    shutil.copy2(str(gadget_file), gadget_dest)

    # Step 3: Write gadget config if provided
    if gadget_config:
        import json

        config_name = gadget_name.replace(".so", ".config.so")
        config_path = os.path.join(lib_dir, config_name)
        Path(config_path).write_text(json.dumps(gadget_config, indent=2))

    # Step 4: Patch smali to load gadget
    # Find the main activity or Application class
    manifest_path = os.path.join(decode_dir, "AndroidManifest.xml")
    main_class = None

    if os.path.exists(manifest_path):
        manifest_content = Path(manifest_path).read_text(errors="replace")
        # Find application class
        import re

        app_match = re.search(r'android:name="([^"]+)"', manifest_content)
        if app_match:
            main_class = app_match.group(1)

    # Find a suitable smali file to inject loadLibrary
    injected = False
    if main_class:
        smali_path = main_class.replace(".", "/") + ".smali"
        for smali_root in ["smali", "smali_classes2", "smali_classes3"]:
            full_path = os.path.join(decode_dir, smali_root, smali_path)
            if os.path.exists(full_path):
                content = Path(full_path).read_text(errors="replace")
                # Inject loadLibrary in static initializer or constructor
                load_lib_name = gadget_name.replace("lib", "").replace(".so", "")
                inject_code = (
                    f'\n    const-string v0, "{load_lib_name}"\n'
                    f"    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
                )

                if ".method static constructor <clinit>" in content:
                    content = content.replace(
                        ".method static constructor <clinit>()V\n",
                        ".method static constructor <clinit>()V\n"
                        "    .locals 1\n"
                        + inject_code,
                    )
                elif ".method public constructor <init>" in content:
                    # Find first line after .locals in constructor
                    lines = content.split("\n")
                    new_lines = []
                    in_init = False
                    inserted = False
                    for line in lines:
                        new_lines.append(line)
                        if ".method public constructor <init>" in line:
                            in_init = True
                        if in_init and ".locals" in line and not inserted:
                            # Ensure enough locals
                            new_lines.append(f'    const-string v0, "{load_lib_name}"')
                            new_lines.append(
                                "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
                            )
                            inserted = True
                            in_init = False
                    content = "\n".join(new_lines)

                Path(full_path).write_text(content)
                injected = True
                break

    # Step 5: Ensure internet permission
    if os.path.exists(manifest_path):
        manifest = Path(manifest_path).read_text(errors="replace")
        if "android.permission.INTERNET" not in manifest:
            manifest = manifest.replace(
                "<application",
                '<uses-permission android:name="android.permission.INTERNET"/>\n    <application',
            )
            Path(manifest_path).write_text(manifest)

    # Step 6: Rebuild
    if not output_apk:
        output_apk = str(file_path).replace(".apk", "-gadget.apk")

    cmd = [apktool, "b", decode_dir, "-o", output_apk]
    proc = await safe_subprocess(cmd, timeout=120)
    if proc.returncode != 0:
        return error_result(f"Rebuild failed: {proc.stderr}")

    # Step 7: Sign
    sign_args = {
        "action": "sign",
        "apk_path": output_apk,
    }
    if config_arg:
        sign_args["__config__"] = config_arg
    await handle_repack(sign_args)

    return text_result({
        "output_apk": output_apk,
        "gadget_injected": gadget_dest,
        "smali_patched": injected,
        "arch": arch,
        "decode_dir": decode_dir,
        "size": os.path.getsize(output_apk) if os.path.exists(output_apk) else 0,
    })
