"""
Revula Binary Format Specializations.

Provides: APK/DEX analysis, .NET IL disassembly, Java class parsing,
and WebAssembly (WASM) analysis.
"""

from __future__ import annotations

import hashlib
import logging
import struct
import zipfile
from pathlib import Path
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# APK / DEX Analysis
# ---------------------------------------------------------------------------


DEX_HEADER_MAGIC = b"dex\n"


def _parse_dex_header(data: bytes) -> dict[str, Any]:
    """Parse DEX file header."""
    if len(data) < 112:
        return {"error": "Data too small for DEX"}
    if data[:4] != DEX_HEADER_MAGIC:
        return {"error": "Not a DEX file"}

    version = data[4:8].decode("ascii", errors="replace").strip("\x00")
    checksum = struct.unpack_from("<I", data, 8)[0]
    sha1 = data[12:32].hex()
    file_size = struct.unpack_from("<I", data, 32)[0]
    header_size = struct.unpack_from("<I", data, 36)[0]

    string_ids_size = struct.unpack_from("<I", data, 56)[0]
    struct.unpack_from("<I", data, 60)[0]
    type_ids_size = struct.unpack_from("<I", data, 64)[0]
    proto_ids_size = struct.unpack_from("<I", data, 72)[0]
    field_ids_size = struct.unpack_from("<I", data, 80)[0]
    method_ids_size = struct.unpack_from("<I", data, 88)[0]
    class_defs_size = struct.unpack_from("<I", data, 96)[0]

    return {
        "version": version,
        "checksum": f"0x{checksum:08x}",
        "sha1": sha1,
        "file_size": file_size,
        "header_size": header_size,
        "string_ids": string_ids_size,
        "type_ids": type_ids_size,
        "proto_ids": proto_ids_size,
        "field_ids": field_ids_size,
        "method_ids": method_ids_size,
        "class_defs": class_defs_size,
    }


@TOOL_REGISTRY.register(
    name="re_apk_analyze",
    description=(
        "Analyze an Android APK file. Extracts: manifest, permissions, "
        "activities, services, receivers, providers, native libraries, "
        "DEX class list, and certificate information."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "apk_path": {"type": "string", "description": "Path to APK file."},
            "extract_dex": {
                "type": "boolean",
                "default": False,
                "description": "Extract DEX files for further analysis.",
            },
            "output_dir": {
                "type": "string",
                "description": "Directory for extracted files.",
            },
        },
        "required": ["apk_path"],
    },
    category="binary_formats",
)
async def handle_apk_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze APK."""
    apk_path = arguments["apk_path"]
    extract_dex = arguments.get("extract_dex", False)
    output_dir = arguments.get("output_dir")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    result: dict[str, Any] = {
        "apk": str(file_path),
        "size": file_path.stat().st_size,
        "md5": hashlib.md5(file_path.read_bytes()).hexdigest(),
        "sha256": hashlib.sha256(file_path.read_bytes()).hexdigest(),
    }

    try:
        with zipfile.ZipFile(str(file_path), "r") as zf:
            entries = zf.namelist()
            result["total_files"] = len(entries)

            # Categorize files
            dex_files = [e for e in entries if e.endswith(".dex")]
            native_libs = [e for e in entries if e.startswith("lib/") and e.endswith(".so")]
            assets = [e for e in entries if e.startswith("assets/")]

            result["dex_files"] = dex_files
            result["native_libraries"] = native_libs
            result["assets_count"] = len(assets)

            # Parse DEX headers
            dex_info: list[dict[str, Any]] = []
            for dex_name in dex_files:
                dex_data = zf.read(dex_name)
                header = _parse_dex_header(dex_data)
                header["filename"] = dex_name
                header["size"] = len(dex_data)
                dex_info.append(header)

            result["dex_info"] = dex_info

            # Try to parse AndroidManifest.xml with aapt if available
            if "AndroidManifest.xml" in entries:
                result["has_manifest"] = True
                # Try aapt for manifest parsing
                try:
                    aapt_result = await safe_subprocess(
                        ["aapt", "dump", "badging", str(file_path)],
                        timeout=30,
                    )
                    if aapt_result.success:
                        manifest = _parse_aapt_output(aapt_result.stdout)
                        result["manifest"] = manifest
                except Exception:
                    result["manifest_note"] = "Install aapt for manifest parsing"

            # Check for suspicious files
            suspicious = []
            for entry in entries:
                if entry.endswith((".sh", ".py", ".js")):
                    suspicious.append({"file": entry, "reason": "Script file in APK"})
                if "su" in entry.lower() and entry.endswith((".so", "")):
                    suspicious.append({"file": entry, "reason": "Potential root binary"})

            result["suspicious_files"] = suspicious

            # Extract DEX if requested
            if extract_dex and output_dir:
                out = Path(output_dir)
                out.mkdir(parents=True, exist_ok=True)
                extracted: list[str] = []
                for dex_name in dex_files:
                    dex_out = out / dex_name
                    dex_out.parent.mkdir(parents=True, exist_ok=True)
                    dex_out.write_bytes(zf.read(dex_name))
                    extracted.append(str(dex_out))
                result["extracted"] = extracted

    except zipfile.BadZipFile:
        return error_result("Not a valid ZIP/APK file")

    return text_result(result)


def _parse_aapt_output(output: str) -> dict[str, Any]:
    """Parse aapt dump badging output."""
    manifest: dict[str, Any] = {}
    permissions: list[str] = []
    activities: list[str] = []

    for line in output.splitlines():
        if line.startswith("package:"):
            # Parse package info: package: name='com.example' versionCode='1' versionName='1.0'
            parts = line.split("'")
            if len(parts) >= 2:
                manifest["package_name"] = parts[1]
            if len(parts) >= 4:
                manifest["version_code"] = parts[3]
            if len(parts) >= 6:
                manifest["version_name"] = parts[5]
            manifest["package_line"] = line.strip()
        elif line.startswith("uses-permission:"):
            perm = line.split("'")[1] if "'" in line else line.split(":")[1].strip()
            permissions.append(perm)
        elif line.startswith("launchable-activity:"):
            activities.append(line.split("'")[1] if "'" in line else "")
        elif line.startswith("sdkVersion:"):
            manifest["min_sdk"] = line.split("'")[1] if "'" in line else ""
        elif line.startswith("targetSdkVersion:"):
            manifest["target_sdk"] = line.split("'")[1] if "'" in line else ""

    manifest["permissions"] = permissions
    manifest["activities"] = activities

    return manifest


# ---------------------------------------------------------------------------
# .NET IL Analysis
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_dotnet_analyze",
    description=(
        "Analyze a .NET assembly. Extracts: metadata, type definitions, "
        "method signatures, IL disassembly, and references. "
        "Uses dnlib/ildasm when available, falls back to header parsing."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "assembly_path": {"type": "string", "description": "Path to .NET assembly."},
            "decompile": {
                "type": "boolean",
                "default": False,
                "description": "Attempt IL decompilation with ilspy/dnspy.",
            },
            "type_filter": {
                "type": "string",
                "description": "Filter types by name substring.",
            },
        },
        "required": ["assembly_path"],
    },
    category="binary_formats",
)
async def handle_dotnet_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze .NET assembly."""
    assembly_path = arguments["assembly_path"]
    decompile = arguments.get("decompile", False)
    type_filter = arguments.get("type_filter")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(assembly_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()
    result: dict[str, Any] = {"assembly": str(file_path)}

    # Check for PE + CLI header
    if data[:2] != b"MZ":
        return error_result("Not a PE file")

    # Try monodis for IL listing
    monodis_result = await safe_subprocess(
        ["monodis", "--typedef", str(file_path)],
        timeout=30,
    )

    if monodis_result.success:
        types: list[dict[str, Any]] = []
        for line in monodis_result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("//"):
                if type_filter and type_filter.lower() not in line.lower():
                    continue
                types.append({"definition": line})
        result["types"] = types

    # Try monodis for method list
    methods_result = await safe_subprocess(
        ["monodis", "--method", str(file_path)],
        timeout=30,
    )

    if methods_result.success:
        methods: list[str] = []
        for line in methods_result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("//"):
                methods.append(line)
        result["methods"] = methods[:500]
        result["method_count"] = len(methods)

    # Try ildasm / ikdasm
    if decompile:
        for tool in ["ikdasm", "ildasm"]:
            il_result = await safe_subprocess(
                [tool, str(file_path)],
                timeout=60,
            )
            if il_result.success:
                result["il_disassembly"] = il_result.stdout[:50000]
                result["il_tool"] = tool
                break

    # Fallback: parse .NET metadata from PE
    if "types" not in result:
        result["note"] = "Install mono-utils for detailed analysis (monodis, ikdasm)"
        result.update(_parse_dotnet_pe_headers(data))

    return text_result(result)


def _parse_dotnet_pe_headers(data: bytes) -> dict[str, Any]:
    """Parse .NET metadata from PE headers."""
    info: dict[str, Any] = {}

    # Find CLI header
    if len(data) < 512:
        return info

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return info

    # Check for .NET metadata directory
    # Optional header starts at pe_offset + 24
    opt_header = pe_offset + 24
    magic = struct.unpack_from("<H", data, opt_header)[0]

    if magic == 0x10B:  # PE32
        cli_dir_offset = opt_header + 208
    elif magic == 0x20B:  # PE32+
        cli_dir_offset = opt_header + 224
    else:
        return info

    if cli_dir_offset + 8 <= len(data):
        cli_rva = struct.unpack_from("<I", data, cli_dir_offset)[0]
        cli_size = struct.unpack_from("<I", data, cli_dir_offset + 4)[0]
        info["cli_header"] = {
            "rva": f"0x{cli_rva:x}",
            "size": cli_size,
            "is_dotnet": cli_rva > 0,
        }

    return info


# ---------------------------------------------------------------------------
# Java Class Analysis
# ---------------------------------------------------------------------------


JAVA_CLASS_MAGIC = b"\xCA\xFE\xBA\xBE"

# Java access flags
JAVA_ACCESS_FLAGS = {
    0x0001: "PUBLIC",
    0x0010: "FINAL",
    0x0020: "SUPER",
    0x0200: "INTERFACE",
    0x0400: "ABSTRACT",
    0x1000: "SYNTHETIC",
    0x2000: "ANNOTATION",
    0x4000: "ENUM",
}


@TOOL_REGISTRY.register(
    name="re_java_analyze",
    description=(
        "Analyze a Java .class file. Extracts: class metadata, "
        "constant pool, fields, methods, and bytecode. "
        "Uses javap when available for full decompilation."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "class_path": {"type": "string", "description": "Path to .class file."},
            "verbose": {
                "type": "boolean",
                "default": False,
                "description": "Include bytecode disassembly.",
            },
        },
        "required": ["class_path"],
    },
    category="binary_formats",
)
async def handle_java_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze Java class file."""
    class_path = arguments["class_path"]
    verbose = arguments.get("verbose", False)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(class_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()

    if data[:4] != JAVA_CLASS_MAGIC:
        return error_result("Not a Java class file (missing CAFEBABE magic)")

    result: dict[str, Any] = {"class_file": str(file_path)}

    # Parse header
    minor = struct.unpack_from(">H", data, 4)[0]
    major = struct.unpack_from(">H", data, 6)[0]
    result["version"] = {"major": major, "minor": minor}

    # Java version mapping
    java_versions = {
        45: "Java 1.1", 46: "Java 1.2", 47: "Java 1.3", 48: "Java 1.4",
        49: "Java 5", 50: "Java 6", 51: "Java 7", 52: "Java 8",
        53: "Java 9", 54: "Java 10", 55: "Java 11", 56: "Java 12",
        57: "Java 13", 58: "Java 14", 59: "Java 15", 60: "Java 16",
        61: "Java 17", 62: "Java 18", 63: "Java 19", 64: "Java 20",
        65: "Java 21",
    }
    result["java_version"] = java_versions.get(major, f"Unknown ({major})")

    # Constant pool count
    cp_count = struct.unpack_from(">H", data, 8)[0]
    result["constant_pool_count"] = cp_count - 1

    # Try javap for detailed analysis
    cmd = ["javap", "-p"]  # -p shows all members
    if verbose:
        cmd.append("-c")  # Include bytecode
    cmd.append(str(file_path))

    javap_result = await safe_subprocess(cmd, timeout=30)

    if javap_result.success:
        result["javap_output"] = javap_result.stdout[:50000]

        # Parse javap output
        methods: list[str] = []
        fields: list[str] = []
        for line in javap_result.stdout.splitlines():
            line = line.strip()
            if "(" in line and ")" in line and not line.startswith("//"):
                methods.append(line.rstrip(";"))
            elif line and not line.startswith("{") and not line.startswith("}") and not line.startswith("//"):
                java_types = [
                    "int ", "String ", "boolean ", "long ",
                    "double ", "float ", "byte ", "char ", "short ", "Object ",
                ]
                if any(t in line for t in java_types):
                    fields.append(line.rstrip(";"))

        result["methods"] = methods
        result["fields"] = fields
    else:
        result["note"] = "Install JDK for detailed analysis (javap)"

    return text_result(result)


# ---------------------------------------------------------------------------
# WebAssembly Analysis
# ---------------------------------------------------------------------------


WASM_MAGIC = b"\x00asm"

WASM_SECTION_NAMES = {
    0: "Custom",
    1: "Type",
    2: "Import",
    3: "Function",
    4: "Table",
    5: "Memory",
    6: "Global",
    7: "Export",
    8: "Start",
    9: "Element",
    10: "Code",
    11: "Data",
    12: "DataCount",
}


def _read_leb128(data: bytes, offset: int) -> tuple[int, int]:
    """Read unsigned LEB128."""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            break
    return result, offset


@TOOL_REGISTRY.register(
    name="re_wasm_analyze",
    description=(
        "Analyze a WebAssembly (.wasm) binary. Extracts: sections, "
        "imports, exports, function signatures, memory layout, "
        "and custom sections."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "wasm_path": {"type": "string", "description": "Path to .wasm file."},
            "disassemble": {
                "type": "boolean",
                "default": False,
                "description": "Disassemble code section (uses wasm-tools/wabt).",
            },
        },
        "required": ["wasm_path"],
    },
    category="binary_formats",
)
async def handle_wasm_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze WASM binary."""
    wasm_path = arguments["wasm_path"]
    disassemble = arguments.get("disassemble", False)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(wasm_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()

    if data[:4] != WASM_MAGIC:
        return error_result("Not a WebAssembly file")

    version = struct.unpack_from("<I", data, 4)[0]
    result: dict[str, Any] = {
        "wasm_file": str(file_path),
        "version": version,
        "size": len(data),
    }

    # Parse sections
    sections: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    offset = 8

    while offset < len(data):
        section_id = data[offset]
        offset += 1

        section_size, offset = _read_leb128(data, offset)
        section_start = offset
        section_end = offset + section_size

        section_info: dict[str, Any] = {
            "id": section_id,
            "name": WASM_SECTION_NAMES.get(section_id, f"Unknown({section_id})"),
            "offset": section_start,
            "size": section_size,
        }

        # Parse specific sections
        if section_id == 2:  # Import section
            count, off = _read_leb128(data, section_start)
            for _ in range(count):
                if off >= section_end:
                    break
                # Module name
                name_len, off = _read_leb128(data, off)
                module_name = data[off:off + name_len].decode("utf-8", errors="replace")
                off += name_len
                # Field name
                name_len, off = _read_leb128(data, off)
                field_name = data[off:off + name_len].decode("utf-8", errors="replace")
                off += name_len
                # Import kind
                kind = data[off]
                off += 1
                kind_names = {0: "function", 1: "table", 2: "memory", 3: "global"}
                imports.append({
                    "module": module_name,
                    "field": field_name,
                    "kind": kind_names.get(kind, str(kind)),
                })
                # Skip type index
                _, off = _read_leb128(data, off)

            section_info["import_count"] = count

        elif section_id == 7:  # Export section
            count, off = _read_leb128(data, section_start)
            for _ in range(count):
                if off >= section_end:
                    break
                name_len, off = _read_leb128(data, off)
                export_name = data[off:off + name_len].decode("utf-8", errors="replace")
                off += name_len
                kind = data[off]
                off += 1
                kind_names = {0: "function", 1: "table", 2: "memory", 3: "global"}
                index, off = _read_leb128(data, off)
                exports.append({
                    "name": export_name,
                    "kind": kind_names.get(kind, str(kind)),
                    "index": index,
                })

            section_info["export_count"] = count

        elif section_id == 0:  # Custom section
            name_len, off = _read_leb128(data, section_start)
            custom_name = data[off:off + name_len].decode("utf-8", errors="replace")
            section_info["custom_name"] = custom_name

        sections.append(section_info)
        offset = section_end

    result["sections"] = sections
    result["imports"] = imports
    result["exports"] = exports

    # Try wasm-objdump for disassembly
    if disassemble:
        for tool in ["wasm-objdump", "wasm-tools"]:
            cmd = [tool, "-d", str(file_path)] if tool == "wasm-objdump" else [tool, "print", str(file_path)]
            dis_result = await safe_subprocess(cmd, timeout=30)
            if dis_result.success:
                result["disassembly"] = dis_result.stdout[:50000]
                result["disassembly_tool"] = tool
                break

    return text_result(result)
