"""
Revula Android Native Binary Analysis.

Performs checksec-style analysis on native .so libraries inside APKs:
NX, PIE, RELRO, stack canary, RPATH/RUNPATH, symbol stripping, Fortify, etc.
"""

from __future__ import annotations

import logging
import struct
import zipfile
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ELF Constants
# ---------------------------------------------------------------------------

ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 0x1

DT_NEEDED = 1
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

SHT_SYMTAB = 2
SHT_DYNSYM = 11

STT_FUNC = 2


def _parse_elf_basic(data: bytes) -> dict[str, Any] | None:
    """Parse ELF headers for security features. Returns None if not ELF."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None

    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]  # 1=LE, 2=BE

    is_64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"

    if is_64:
        # 64-bit ELF header
        e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
        e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
        e_phoff = struct.unpack_from(f"{endian}Q", data, 32)[0]
        e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
        e_phentsize = struct.unpack_from(f"{endian}H", data, 54)[0]
        e_phnum = struct.unpack_from(f"{endian}H", data, 56)[0]
        e_shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
        e_shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
        struct.unpack_from(f"{endian}H", data, 62)[0]
    else:
        e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
        e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
        e_phoff = struct.unpack_from(f"{endian}I", data, 28)[0]
        e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
        e_phentsize = struct.unpack_from(f"{endian}H", data, 42)[0]
        e_phnum = struct.unpack_from(f"{endian}H", data, 44)[0]
        e_shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
        e_shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
        struct.unpack_from(f"{endian}H", data, 50)[0]

    machine_names = {
        3: "x86", 8: "MIPS", 40: "ARM", 62: "x86_64",
        183: "AArch64", 243: "RISC-V",
    }

    result: dict[str, Any] = {
        "bits": 64 if is_64 else 32,
        "endian": "little" if ei_data == 1 else "big",
        "type": "shared_object" if e_type == ET_DYN else f"type_{e_type}",
        "machine": machine_names.get(e_machine, f"unknown_{e_machine}"),
        "pie": e_type == ET_DYN,
    }

    # Parse program headers
    nx = False
    relro = False
    bind_now = False
    dt_entries: list[tuple[int, int]] = []

    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        if ph_off + e_phentsize > len(data):
            break

        if is_64:
            p_type = struct.unpack_from(f"{endian}I", data, ph_off)[0]
            p_flags = struct.unpack_from(f"{endian}I", data, ph_off + 4)[0]
            p_offset = struct.unpack_from(f"{endian}Q", data, ph_off + 8)[0]
            p_filesz = struct.unpack_from(f"{endian}Q", data, ph_off + 32)[0]
        else:
            p_type = struct.unpack_from(f"{endian}I", data, ph_off)[0]
            p_offset = struct.unpack_from(f"{endian}I", data, ph_off + 4)[0]
            p_filesz = struct.unpack_from(f"{endian}I", data, ph_off + 16)[0]
            p_flags = struct.unpack_from(f"{endian}I", data, ph_off + 24)[0]

        if p_type == PT_GNU_STACK:
            nx = (p_flags & PF_X) == 0

        if p_type == PT_GNU_RELRO:
            relro = True

        if p_type == PT_DYNAMIC:
            # Parse dynamic section for BIND_NOW
            dt_size = 16 if is_64 else 8
            pos = p_offset
            while pos + dt_size <= min(p_offset + p_filesz, len(data)):
                if is_64:
                    d_tag = struct.unpack_from(f"{endian}Q", data, pos)[0]
                    d_val = struct.unpack_from(f"{endian}Q", data, pos + 8)[0]
                else:
                    d_tag = struct.unpack_from(f"{endian}I", data, pos)[0]
                    d_val = struct.unpack_from(f"{endian}I", data, pos + 4)[0]

                dt_entries.append((d_tag, d_val))

                if d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                    bind_now = True
                if d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
                    bind_now = True
                if d_tag == 0:  # DT_NULL
                    break
                pos += dt_size

    result["nx"] = nx
    result["relro"] = "full" if (relro and bind_now) else "partial" if relro else "none"
    result["bind_now"] = bind_now

    # Check for stack canary (__stack_chk_fail in dynamic symbols)
    has_canary = b"__stack_chk_fail" in data
    result["stack_canary"] = has_canary

    # Fortify source
    has_fortify = b"__fortify_fail" in data or b"__sprintf_chk" in data
    result["fortify_source"] = has_fortify

    # RPATH / RUNPATH
    result["rpath"] = any(d_tag == DT_RPATH for d_tag, _ in dt_entries)
    result["runpath"] = any(d_tag == DT_RUNPATH for d_tag, _ in dt_entries)

    # Check if stripped (look for .symtab section)
    stripped = True
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        if sh_off + e_shentsize > len(data):
            break
        if is_64:
            sh_type = struct.unpack_from(f"{endian}I", data, sh_off + 4)[0]
        else:
            sh_type = struct.unpack_from(f"{endian}I", data, sh_off + 4)[0]

        if sh_type == SHT_SYMTAB:
            stripped = False
            break

    result["stripped"] = stripped

    # Count exported functions (from .dynsym)
    exported_count = 0
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        if sh_off + e_shentsize > len(data):
            break
        if is_64:
            sh_type = struct.unpack_from(f"{endian}I", data, sh_off + 4)[0]
        else:
            sh_type = struct.unpack_from(f"{endian}I", data, sh_off + 4)[0]

        if sh_type == SHT_DYNSYM:
            exported_count += 1

    result["has_dynamic_symbols"] = exported_count > 0

    # Detect JNI exports
    jni_exports: list[str] = []
    for match_start in range(len(data) - 6):
        if data[match_start:match_start + 5] == b"Java_":
            # Find end of symbol
            end = match_start + 5
            while end < len(data) and data[end] not in (0, 0x20, 0x0A):
                end += 1
            try:
                sym = data[match_start:end].decode("ascii")
                if len(sym) > 6 and sym.isascii():
                    jni_exports.append(sym)
            except Exception:
                pass
        if len(jni_exports) >= 500:
            break

    result["jni_exports"] = list(set(jni_exports))[:200]
    result["jni_export_count"] = len(set(jni_exports))

    return result


# ---------------------------------------------------------------------------
# Tool: re_android_binary_analysis
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_binary_analysis",
    description=(
        "Analyze native .so libraries in an APK: checksec (NX, PIE, RELRO, canary, "
        "Fortify, stripped), JNI exports, per-architecture breakdown. "
        "Works without external tools."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to APK file.",
            },
            "lib_filter": {
                "type": "string",
                "description": "Filter by library name (substring match).",
            },
            "arch_filter": {
                "type": "string",
                "enum": ["armeabi-v7a", "arm64-v8a", "x86", "x86_64", "all"],
                "description": "Filter by architecture. Default: all.",
            },
        },
    },
)
async def handle_binary_analysis(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze native libraries in APK."""
    apk_path = arguments["apk_path"]
    lib_filter = arguments.get("lib_filter")
    arch_filter = arguments.get("arch_filter", "all")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    libraries: list[dict[str, Any]] = []
    security_summary: dict[str, int] = {
        "total": 0, "nx_enabled": 0, "pie_enabled": 0,
        "full_relro": 0, "canary": 0, "fortified": 0, "stripped": 0,
    }

    with zipfile.ZipFile(str(file_path), "r") as zf:
        for entry in zf.namelist():
            if not (entry.startswith("lib/") and entry.endswith(".so")):
                continue

            parts = entry.split("/")
            if len(parts) < 3:
                continue

            arch = parts[1]
            lib_name = parts[-1]

            # Apply filters
            if arch_filter != "all" and arch != arch_filter:
                continue
            if lib_filter and lib_filter not in lib_name:
                continue

            data = zf.read(entry)
            analysis = _parse_elf_basic(data)

            if analysis is None:
                libraries.append({
                    "name": lib_name,
                    "path": entry,
                    "arch": arch,
                    "size": len(data),
                    "error": "Not a valid ELF file",
                })
                continue

            analysis["name"] = lib_name
            analysis["path"] = entry
            analysis["arch"] = arch
            analysis["size"] = len(data)

            # Security score (0-100)
            sec_score = 0
            if analysis.get("nx"):
                sec_score += 20
            if analysis.get("pie"):
                sec_score += 20
            if analysis.get("relro") == "full":
                sec_score += 20
            elif analysis.get("relro") == "partial":
                sec_score += 10
            if analysis.get("stack_canary"):
                sec_score += 20
            if analysis.get("fortify_source"):
                sec_score += 10
            if analysis.get("stripped"):
                sec_score += 10
            analysis["security_score"] = sec_score

            libraries.append(analysis)

            # Update summary
            security_summary["total"] += 1
            if analysis.get("nx"):
                security_summary["nx_enabled"] += 1
            if analysis.get("pie"):
                security_summary["pie_enabled"] += 1
            if analysis.get("relro") == "full":
                security_summary["full_relro"] += 1
            if analysis.get("stack_canary"):
                security_summary["canary"] += 1
            if analysis.get("fortify_source"):
                security_summary["fortified"] += 1
            if analysis.get("stripped"):
                security_summary["stripped"] += 1

    # Architecture breakdown
    arch_breakdown: dict[str, list[str]] = {}
    for lib in libraries:
        arch = lib.get("arch", "unknown")
        if arch not in arch_breakdown:
            arch_breakdown[arch] = []
        arch_breakdown[arch].append(lib.get("name", ""))

    return text_result({
        "apk": str(file_path),
        "total_native_libs": len(libraries),
        "security_summary": security_summary,
        "arch_breakdown": arch_breakdown,
        "libraries": libraries,
    })
