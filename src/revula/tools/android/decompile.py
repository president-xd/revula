"""
Revula Android Decompile + Smali tools.

Provides jadx/cfr/Fernflower decompilation, baksmali disassembly, smali assembly,
and smali patching capabilities.
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_tool(name: str) -> str | None:
    """Find a tool binary on PATH."""
    return shutil.which(name)


def _read_output_tree(output_dir: str, max_files: int = 200) -> dict[str, Any]:
    """Walk an output directory and return a tree with file sizes."""
    tree: dict[str, Any] = {"root": output_dir, "files": [], "total_files": 0}
    count = 0
    for root, _dirs, files in os.walk(output_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, output_dir)
            if count < max_files:
                tree["files"].append({
                    "path": rel,
                    "size": os.path.getsize(full),
                })
            count += 1
    tree["total_files"] = count
    if count > max_files:
        tree["_note"] = f"Showing {max_files} of {count} files"
    return tree


# ---------------------------------------------------------------------------
# Tool: re_android_decompile
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_decompile",
    description=(
        "Decompile Android APK/DEX to Java source using jadx (primary), CFR, or Fernflower. "
        "Returns output directory path and file listing."
    ),
    category="android",
    requires_tools=["jadx"],
    input_schema={
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to APK or DEX file.",
            },
            "output_dir": {
                "type": "string",
                "description": "Output directory for decompiled sources. Default: auto-generated temp dir.",
            },
            "decompiler": {
                "type": "string",
                "enum": ["jadx", "cfr", "fernflower", "auto"],
                "description": "Decompiler backend. Default: auto (tries jadx → cfr → fernflower).",
            },
            "class_filter": {
                "type": "string",
                "description": "Only decompile classes matching this package prefix (e.g. 'com.example').",
            },
            "show_source": {
                "type": "boolean",
                "description": "If true, return source code of matching classes inline. Default: false.",
            },
        },
    },
)
async def handle_decompile(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Decompile APK to Java source."""
    apk_path = arguments["apk_path"]
    output_dir = arguments.get("output_dir")
    decompiler = arguments.get("decompiler", "auto")
    class_filter = arguments.get("class_filter")
    show_source = arguments.get("show_source", False)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    if output_dir:
        out_path = validate_path(
            output_dir,
            allowed_dirs=allowed_dirs,
            must_exist=False,
            path_kind="dir",
        )
        out_path.mkdir(parents=True, exist_ok=True)
    else:
        base_dir = Path(allowed_dirs[0]).expanduser() if allowed_dirs else Path(tempfile.gettempdir())
        out_path = Path(tempfile.mkdtemp(prefix="revula_decompile_", dir=str(base_dir)))
        if allowed_dirs:
            out_path = validate_path(str(out_path), allowed_dirs=allowed_dirs, path_kind="dir")

    # Try decompilers in order
    decompilers_to_try = (
        [decompiler] if decompiler != "auto" else ["jadx", "cfr", "fernflower"]
    )

    used_decompiler = None

    for dec in decompilers_to_try:
        tool_path = _find_tool(dec)
        if not tool_path:
            if dec == "cfr":
                # CFR is a jar — check user-writable locations
                jar_paths = [
                    os.path.expanduser("~/.local/share/cfr/cfr.jar"),
                    os.path.expanduser("~/.revula/tools/cfr/cfr.jar"),
                ]
                for jp in jar_paths:
                    if os.path.exists(jp):
                        tool_path = jp
                        break
            if not tool_path:
                continue

        if dec == "jadx":
            cmd = [tool_path, "-d", str(out_path), str(file_path)]
            if class_filter:
                cmd.extend(["--class-name-filter", class_filter])
            proc = await safe_subprocess(cmd, timeout=300)
            if proc.returncode == 0:
                used_decompiler = "jadx"
                break

        elif dec == "cfr":
            if tool_path.endswith(".jar"):
                cmd = [
                    "java", "-jar", tool_path,
                    str(file_path),
                    "--outputdir", str(out_path),
                ]
            else:
                cmd = [tool_path, str(file_path), "--outputdir", str(out_path)]
            proc = await safe_subprocess(cmd, timeout=300)
            if proc.returncode == 0:
                used_decompiler = "cfr"
                break

        elif dec == "fernflower":
            ff_path = _find_tool("fernflower") or _find_tool("java-decompiler")
            if ff_path:
                cmd = [ff_path, str(file_path), str(out_path)]
                proc = await safe_subprocess(cmd, timeout=300)
                if proc.returncode == 0:
                    used_decompiler = "fernflower"
                    break

    if not used_decompiler:
        return error_result(
            f"No decompiler available. Tried: {', '.join(decompilers_to_try)}. "
            "Install jadx: https://github.com/skylot/jadx"
        )

    result: dict[str, Any] = {
        "decompiler": used_decompiler,
        "output_dir": str(out_path),
        "file_tree": _read_output_tree(str(out_path)),
    }

    # Include source code if requested
    if show_source:
        sources: list[dict[str, str]] = []
        for root, _dirs, files in os.walk(str(out_path)):
            for f in files:
                if f.endswith(".java"):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, str(out_path))
                    # Apply class filter
                    if class_filter and class_filter.replace(".", "/") not in rel:
                        continue
                    try:
                        content = Path(full).read_text(errors="replace")
                        sources.append({"path": rel, "source": content[:50000]})
                    except (OSError, UnicodeError) as e:
                        logger.debug("Failed to read decompiled source %s: %s", full, e)
                    if len(sources) >= 50:
                        break
            if len(sources) >= 50:
                break
        result["sources"] = sources

    return text_result(result)


# ---------------------------------------------------------------------------
# Tool: re_android_smali_disasm
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_smali_disasm",
    description=(
        "Disassemble APK/DEX to Smali using baksmali. "
        "Returns output directory and file listing."
    ),
    category="android",
    requires_tools=["baksmali"],
    input_schema={
        "type": "object",
        "required": ["input_path"],
        "properties": {
            "input_path": {
                "type": "string",
                "description": "Absolute path to APK or DEX file.",
            },
            "output_dir": {
                "type": "string",
                "description": "Output directory for Smali files.",
            },
            "class_name": {
                "type": "string",
                "description": "Specific class to extract (e.g. 'Lcom/example/Main;').",
            },
        },
    },
)
async def handle_smali_disasm(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Disassemble DEX to Smali."""
    input_path = arguments["input_path"]
    output_dir = arguments.get("output_dir")
    class_name = arguments.get("class_name")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(input_path, allowed_dirs=allowed_dirs)

    baksmali = _find_tool("baksmali")
    if not baksmali:
        return error_result(
            "baksmali not found on PATH. Install: "
            "https://github.com/JesusFreke/smali"
        )

    if output_dir:
        out_path = validate_path(
            output_dir,
            allowed_dirs=allowed_dirs,
            must_exist=False,
            path_kind="dir",
        )
        out_path.mkdir(parents=True, exist_ok=True)
    else:
        base_dir = Path(allowed_dirs[0]).expanduser() if allowed_dirs else Path(tempfile.gettempdir())
        out_path = Path(tempfile.mkdtemp(prefix="revula_smali_", dir=str(base_dir)))
        if allowed_dirs:
            out_path = validate_path(str(out_path), allowed_dirs=allowed_dirs, path_kind="dir")

    cmd = [baksmali, "disassemble", str(file_path), "-o", str(out_path)]
    proc = await safe_subprocess(cmd, timeout=120)

    if proc.returncode != 0:
        return error_result(f"baksmali failed (rc={proc.returncode}): {proc.stderr}")

    result: dict[str, Any] = {
        "output_dir": str(out_path),
        "file_tree": _read_output_tree(str(out_path)),
    }

    # If specific class requested, return its source
    if class_name:
        cls_path = class_name.lstrip("L").rstrip(";").replace("/", os.sep) + ".smali"
        full_cls_path = out_path / cls_path
        if full_cls_path.exists():
            result["class_source"] = full_cls_path.read_text(errors="replace")[:100000]
        else:
            result["class_source_error"] = f"Class file not found: {cls_path}"

    return text_result(result)


# ---------------------------------------------------------------------------
# Tool: re_android_smali_assemble
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_smali_assemble",
    description=(
        "Assemble Smali files back to a DEX file using smali."
    ),
    category="android",
    requires_tools=["smali"],
    input_schema={
        "type": "object",
        "required": ["smali_dir"],
        "properties": {
            "smali_dir": {
                "type": "string",
                "description": "Directory containing Smali files.",
            },
            "output_dex": {
                "type": "string",
                "description": "Output DEX file path. Default: out.dex in smali_dir.",
            },
        },
    },
)
async def handle_smali_assemble(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Assemble Smali back to DEX."""
    smali_dir = arguments["smali_dir"]
    output_dex = arguments.get("output_dex")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    dir_path = validate_path(smali_dir, allowed_dirs=allowed_dirs, path_kind="dir")

    smali_tool = _find_tool("smali")
    if not smali_tool:
        return error_result("smali not found on PATH.")

    if not output_dex:
        output_dex = str(dir_path / "out.dex")
    output_path = validate_path(
        output_dex,
        allowed_dirs=allowed_dirs,
        must_exist=False,
        path_kind="file",
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [smali_tool, "assemble", str(dir_path), "-o", str(output_path)]
    proc = await safe_subprocess(cmd, timeout=120)

    if proc.returncode != 0:
        return error_result(f"smali assemble failed (rc={proc.returncode}): {proc.stderr}")

    return text_result({
        "output_dex": str(output_path),
        "size": os.path.getsize(output_path),
        "message": "DEX assembled successfully",
    })


# ---------------------------------------------------------------------------
# Tool: re_android_smali_patch
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_smali_patch",
    description=(
        "Patch a Smali file: replace specific instructions, modify method bodies, "
        "insert hooks, or apply find-and-replace."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["smali_file", "patches"],
        "properties": {
            "smali_file": {
                "type": "string",
                "description": "Absolute path to the Smali file to patch.",
            },
            "patches": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["find", "replace"],
                    "properties": {
                        "find": {
                            "type": "string",
                            "description": "Text to find in Smali source.",
                        },
                        "replace": {
                            "type": "string",
                            "description": "Replacement text.",
                        },
                    },
                },
                "description": "Array of find-replace patches to apply.",
            },
            "backup": {
                "type": "boolean",
                "description": "Create .bak backup before patching. Default: true.",
            },
        },
    },
)
async def handle_smali_patch(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Patch a Smali file."""
    smali_file = arguments["smali_file"]
    patches = arguments["patches"]
    backup = arguments.get("backup", True)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_path(smali_file, allowed_dirs=allowed_dirs)

    if not file_path.exists():
        return error_result(f"File not found: {smali_file}")

    content = file_path.read_text(errors="replace")
    original = content

    applied: list[dict[str, Any]] = []
    for i, patch in enumerate(patches):
        find = patch["find"]
        replace = patch["replace"]
        count = content.count(find)
        if count > 0:
            content = content.replace(find, replace)
            applied.append({
                "patch_index": i,
                "find": find[:100],
                "occurrences": count,
                "status": "applied",
            })
        else:
            applied.append({
                "patch_index": i,
                "find": find[:100],
                "occurrences": 0,
                "status": "not_found",
            })

    if content != original:
        if backup:
            # Open the backup path with O_NOFOLLOW | O_EXCL so a pre-existing
            # symlink (or hardlink race) cannot redirect the write to another
            # file the process is allowed to clobber. If a file already exists
            # at that exact path we remove it first (but only if it's a
            # regular file we own), since .bak overwrite is the expected
            # behaviour.
            bak_path = Path(str(file_path) + ".bak")
            try:
                st = os.lstat(bak_path)
                import stat as _stat
                if not _stat.S_ISREG(st.st_mode):
                    return error_result(
                        f"Refusing to write backup: {bak_path} exists and is not a regular file"
                    )
                os.unlink(bak_path)
            except FileNotFoundError:
                pass
            fd = os.open(
                str(bak_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(original)

        file_path.write_text(content)

    return text_result({
        "file": str(file_path),
        "patches_applied": sum(1 for p in applied if p["status"] == "applied"),
        "patches_not_found": sum(1 for p in applied if p["status"] == "not_found"),
        "details": applied,
        "backup_created": backup and content != original,
    })
