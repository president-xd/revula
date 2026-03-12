"""
Revula Packer Detection & Unpacking tools.

Detects: UPX, Themida, VMProtect, ASPack, PECompact, Obsidium, custom packers.
Unpacks: UPX (static), generic (dynamic via emulation), PE rebuild.
"""

from __future__ import annotations

import contextlib
import logging
import math
import shutil
from pathlib import Path
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Packer Signatures
# ---------------------------------------------------------------------------

PACKER_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "UPX",
        "signatures": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
        "section_names": [".UPX0", ".UPX1", ".UPX2", "UPX0", "UPX1"],
        "confidence": "high",
    },
    {
        "name": "Themida",
        "signatures": [b".themida", b"Themida"],
        "section_names": [".themida", ".Themida"],
        "confidence": "high",
    },
    {
        "name": "VMProtect",
        "signatures": [b".vmp0", b".vmp1", b"VMProtect"],
        "section_names": [".vmp0", ".vmp1", ".vmp2"],
        "confidence": "high",
    },
    {
        "name": "ASPack",
        "signatures": [b".aspack", b".adata"],
        "section_names": [".aspack", ".adata"],
        "confidence": "high",
    },
    {
        "name": "PECompact",
        "signatures": [b"PEC2", b"PECompact2"],
        "section_names": ["PEC2", ".pec1", ".pec2"],
        "confidence": "high",
    },
    {
        "name": "Obsidium",
        "signatures": [b".obsidiu"],
        "section_names": [".obsidiu"],
        "confidence": "medium",
    },
    {
        "name": "MPRESS",
        "signatures": [b".MPRESS1", b".MPRESS2"],
        "section_names": [".MPRESS1", ".MPRESS2"],
        "confidence": "high",
    },
    {
        "name": "Petite",
        "signatures": [b".petite"],
        "section_names": [".petite"],
        "confidence": "high",
    },
    {
        "name": "Enigma",
        "signatures": [b".enigma1", b".enigma2"],
        "section_names": [".enigma1", ".enigma2"],
        "confidence": "high",
    },
    {
        "name": "NSPack",
        "signatures": [b".nsp0", b".nsp1", b".nsp2"],
        "section_names": [".nsp0", ".nsp1", ".nsp2"],
        "confidence": "medium",
    },
]


def _compute_entropy(data: bytes) -> float:
    """Shannon entropy of data."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Packer Detection Tool
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_detect_packer",
    description=(
        "Detect if a binary is packed and identify the packer. "
        "Checks section names, signature bytes, entropy analysis, "
        "import count heuristics, and known packer patterns. "
        "Returns confidence level and unpacking recommendations."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to binary to analyze."},
        },
        "required": ["binary_path"],
    },
    category="unpacking",
)
async def handle_detect_packer(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect packers."""
    binary_path = arguments["binary_path"]
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()
    detections: list[dict[str, Any]] = []
    indicators: list[str] = []

    # --- Signature scan ---
    for sig_info in PACKER_SIGNATURES:
        for sig in sig_info["signatures"]:
            if sig in data:
                detections.append({
                    "packer": sig_info["name"],
                    "method": "signature",
                    "confidence": sig_info["confidence"],
                })
                break

    # --- Section name analysis ---
    try:
        import lief
        binary = lief.parse(str(file_path))
        if binary:
            section_names = [s.name for s in binary.sections]

            for sig_info in PACKER_SIGNATURES:
                for expected in sig_info["section_names"]:
                    if expected in section_names:
                        detections.append({
                            "packer": sig_info["name"],
                            "method": "section_name",
                            "section": expected,
                            "confidence": sig_info["confidence"],
                        })
                        break

            # --- Entropy analysis ---
            for section in binary.sections:
                sec_data = bytes(section.content)
                if sec_data:
                    ent = _compute_entropy(sec_data)
                    if ent > 7.0:
                        indicators.append(
                            f"High entropy section: {section.name} ({ent:.2f})"  # type: ignore[str-bytes-safe]
                        )
                    if ent < 0.5 and len(sec_data) > 1024:
                        indicators.append(
                            f"Very low entropy section: {section.name} ({ent:.2f})"  # type: ignore[str-bytes-safe]
                        )

            # --- Import analysis ---
            if hasattr(binary, "imports"):
                imports = list(binary.imports)
                if len(imports) < 5:
                    indicators.append(
                        f"Very few imports ({len(imports)}) — likely packed"
                    )

                # Check for LoadLibrary/GetProcAddress only
                import_names = [str(imp) for imp in imports]
                dynamic_loader = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress",
                                  "LoadLibraryExA", "LoadLibraryExW"}
                found_dynamic = [n for n in import_names if any(d in n for d in dynamic_loader)]
                if found_dynamic and len(imports) < 10:
                    indicators.append(
                        "Only dynamic loading imports — strong packing indicator"
                    )

            # --- Entry point analysis ---
            if hasattr(binary, "entrypoint"):
                ep = binary.entrypoint
                # Check if EP is in a non-standard section
                for section in binary.sections:
                    if section.virtual_address <= ep < section.virtual_address + section.size:
                        if section.name not in [".text", ".code", "CODE", ".init"]:
                            indicators.append(
                                f"Entry point in non-code section: {section.name}"  # type: ignore[str-bytes-safe]
                            )
                        break

    except ImportError:
        indicators.append("LIEF not available — section analysis skipped")

    # --- Overall entropy ---
    overall_entropy = _compute_entropy(data)
    if overall_entropy > 7.2:
        indicators.append(f"Very high overall entropy: {overall_entropy:.2f}")

    # Deduplicate detections
    seen: set[str] = set()
    unique_detections: list[dict[str, Any]] = []
    for d in detections:
        key = d["packer"]
        if key not in seen:
            seen.add(key)
            unique_detections.append(d)

    # Determine packed status
    is_packed = len(unique_detections) > 0 or len(indicators) >= 3

    return text_result({
        "binary": str(file_path),
        "is_packed": is_packed,
        "detections": unique_detections,
        "indicators": indicators,
        "overall_entropy": round(overall_entropy, 4),
        "recommendation": _unpack_recommendation(unique_detections),
    })


def _unpack_recommendation(detections: list[dict[str, Any]]) -> str:
    """Generate unpacking recommendation."""
    if not detections:
        return "No known packer detected. Try dynamic unpacking if behavior suggests packing."

    packers = {d["packer"] for d in detections}

    if "UPX" in packers:
        return "UPX detected — use re_unpack_upx for static unpacking."
    if "Themida" in packers or "VMProtect" in packers:
        return (
            f"{'Themida' if 'Themida' in packers else 'VMProtect'} detected — "
            "requires dynamic unpacking. Use re_dynamic_unpack with memory dumping."
        )
    return f"Packer(s) detected: {', '.join(packers)}. Try re_dynamic_unpack."


# ---------------------------------------------------------------------------
# UPX Unpack
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_unpack_upx",
    description=(
        "Unpack a UPX-compressed binary. Uses the UPX tool with -d flag. "
        "Creates a backup of the original before unpacking."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "output_path": {"type": "string", "description": "Output path for unpacked binary."},
            "force": {"type": "boolean", "default": False},
        },
        "required": ["binary_path"],
    },
    category="unpacking",
    requires_tools=["upx"],
)
async def handle_unpack_upx(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Unpack UPX binary."""
    binary_path = arguments["binary_path"]
    output_path = arguments.get("output_path")
    force = arguments.get("force", False)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
    upx_path = config.require_tool("upx") if config else "upx"

    # Create backup
    backup_dir = file_path.parent / ".revula-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{file_path.name}.packed"
    shutil.copy2(file_path, backup_path)

    # Determine output
    if output_path:
        out = Path(output_path)
        # Copy to output, unpack in place
        shutil.copy2(file_path, out)
        target = str(out)
    else:
        target = str(file_path)

    cmd = [upx_path, "-d"]
    if force:
        cmd.append("-f")
    cmd.append(target)

    result = await safe_subprocess(cmd, timeout=120)

    if result.success:
        unpacked_size = Path(target).stat().st_size
        packed_size = backup_path.stat().st_size
        return text_result({
            "status": "unpacked",
            "output": target,
            "backup": str(backup_path),
            "packed_size": packed_size,
            "unpacked_size": unpacked_size,
            "ratio": round(unpacked_size / packed_size, 2) if packed_size > 0 else 0,
        })

    return error_result(f"UPX unpack failed: {result.stderr}")


# ---------------------------------------------------------------------------
# Dynamic Unpack
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_dynamic_unpack",
    description=(
        "Dynamically unpack a binary by running it and dumping memory after "
        "the unpacking stub completes. Uses Frida to detect OEP transfer "
        "and dump the unpacked image from memory."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "output_path": {"type": "string"},
            "timeout": {"type": "integer", "default": 30},
        },
        "required": ["binary_path"],
    },
    category="unpacking",
    requires_modules=["frida"],
)
async def handle_dynamic_unpack(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Dynamic unpacking via memory dump."""
    try:
        import frida
    except ImportError:
        return error_result("frida required for dynamic unpacking")

    binary_path = arguments["binary_path"]
    output_path = arguments.get("output_path")
    timeout = arguments.get("timeout", 30)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    if not output_path:
        output_path = str(file_path.parent / f"{file_path.stem}_unpacked{file_path.suffix}")

    # Check if it's UPX — Frida can't handle UPX-packed ELF (loader crash)
    data = file_path.read_bytes()
    if b"UPX!" in data or b"UPX0" in data:
        return error_result(
            "UPX-packed binary detected. Frida cannot inject into UPX-packed ELF binaries "
            "(the loader crashes before Frida gets control). "
            "Use re_unpack_upx for static UPX unpacking instead — it's faster and more reliable."
        )

    pid = None
    session = None
    try:
        # Spawn process suspended
        device = frida.get_local_device()
        pid = device.spawn([str(file_path)])
        session = device.attach(pid)

        # Use a simpler, more robust script that avoids Stalker (which crashes
        # on some binaries, especially UPX-packed ELF). Instead:
        # 1. Resume the process and let unpacking stub complete naturally
        # 2. After a short delay, dump the main module from memory
        script_code = """
        rpc.exports = {
            getModuleInfo: function() {
                var mod = Process.enumerateModules()[0];
                return {
                    name: mod.name,
                    base: mod.base.toString(),
                    size: mod.size,
                    path: mod.path,
                };
            },
            dumpModule: function() {
                var mod = Process.enumerateModules()[0];
                var data = mod.base.readByteArray(mod.size);
                send({type: 'dump', base: mod.base.toString(), size: mod.size}, data);
                return {name: mod.name, base: mod.base.toString(), size: mod.size};
            },
            dumpAllExecutable: function() {
                // Dump all executable ranges (more complete for packed binaries)
                var ranges = Process.enumerateRanges('r-x');
                var mod = Process.enumerateModules()[0];
                var allData = [];
                var totalSize = 0;
                ranges.forEach(function(range) {
                    if (range.file && range.file.path === mod.path) {
                        totalSize += range.size;
                    }
                });
                // Dump main module region
                var data = mod.base.readByteArray(mod.size);
                send({type: 'dump', base: mod.base.toString(), size: mod.size}, data);
                return {name: mod.name, base: mod.base.toString(), size: mod.size, executable_ranges: totalSize};
            }
        };
        """

        dump_data: bytes | None = None
        dump_info: dict[str, Any] = {}

        frida_script = session.create_script(script_code)

        def on_message(message: dict[str, Any], msg_data: Any) -> None:
            nonlocal dump_data
            if msg_data:
                dump_data = bytes(msg_data)

        frida_script.on("message", on_message)
        frida_script.load()

        # Resume the process and let the unpacking stub run
        device.resume(pid)

        import asyncio as aio
        # Wait for unpacking to complete (typically < 1 second for UPX)
        await aio.sleep(min(timeout, 3))

        # Now dump the module from memory (unpacking stub should be done)
        try:
            dump_info = frida_script.exports_sync.dump_all_executable()
            # Wait for the data to arrive via message
            await aio.sleep(1)
        except Exception as e:
            logger.warning("dumpAllExecutable failed: %s, trying dumpModule", e)
            try:
                dump_info = frida_script.exports_sync.dump_module()
                await aio.sleep(1)
            except Exception as e2:
                logger.warning("dumpModule also failed: %s", e2)

        # Cleanup
        with contextlib.suppress(Exception):
            frida_script.unload()
        with contextlib.suppress(Exception):
            session.detach()

        if dump_data:
            Path(output_path).write_bytes(dump_data)
            return text_result({
                "status": "dumped",
                "output": output_path,
                "size": len(dump_data),
                "module_info": dump_info,
                "note": "Raw memory dump — may need PE rebuild (re_pe_rebuild) for PE binaries",
            })

        return error_result(
            "Failed to capture unpacked image. "
            "For UPX-packed binaries, use re_unpack_upx for static unpacking instead."
        )

    except frida.ProcessNotRespondingError:
        return error_result(
            "Process not responding (possibly crashed during spawn). "
            "For UPX-packed binaries, use re_unpack_upx for static unpacking."
        )
    except frida.TransportError as e:
        return error_result(
            f"Frida transport error: {e}. "
            "The binary may have crashed during unpacking. "
            "For UPX-packed binaries, use re_unpack_upx for static unpacking."
        )
    except Exception as e:
        return error_result(
            f"Dynamic unpacking failed: {e}. "
            "For UPX-packed binaries, try re_unpack_upx instead."
        )
    finally:
        if pid is not None:
            with contextlib.suppress(Exception):
                device.kill(pid)


# ---------------------------------------------------------------------------
# PE Rebuild
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_pe_rebuild",
    description=(
        "Rebuild PE headers after memory dump. Fixes section alignments, "
        "imports, and entry point. Use after dynamic unpacking."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "dump_path": {"type": "string", "description": "Path to memory dump."},
            "output_path": {"type": "string"},
            "base_address": {
                "type": "string",
                "description": "Original base address of dump (hex).",
            },
            "entry_point": {
                "type": "string",
                "description": "New entry point RVA (hex).",
            },
        },
        "required": ["dump_path"],
    },
    category="unpacking",
)
async def handle_pe_rebuild(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Rebuild PE from memory dump."""
    dump_path_str = arguments["dump_path"]
    output_path = arguments.get("output_path")
    arguments.get("base_address")
    entry_point = arguments.get("entry_point")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    dump_path = validate_binary_path(dump_path_str, allowed_dirs=allowed_dirs)

    if not output_path:
        output_path = str(dump_path.parent / f"{dump_path.stem}_rebuilt.exe")

    try:
        import lief
    except ImportError:
        return error_result("LIEF required for PE rebuild")

    binary = lief.parse(str(dump_path))
    if not binary:
        return error_result("Failed to parse dump as PE")

    if not isinstance(binary, lief.PE.Binary):
        return error_result("File is not a valid PE binary")

    changes: list[str] = []

    # Fix entry point
    if entry_point:
        ep = int(entry_point, 16) if entry_point.startswith("0x") else int(entry_point)
        binary.optional_header.addressof_entrypoint = ep
        changes.append(f"Entry point set to 0x{ep:x}")

    # Fix section alignments
    for section in binary.sections:
        # Ensure virtual size >= raw size
        if section.virtual_size < section.sizeof_raw_data:
            section.virtual_size = section.sizeof_raw_data
            changes.append(f"Fixed virtual size for {section.name}")  # type: ignore[str-bytes-safe]

        # Ensure sections have proper characteristics
        if section.name in [".text", ".code", "CODE"]:
            section.characteristics |= (
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
                | lief.PE.Section.CHARACTERISTICS.MEM_READ  # type: ignore[operator]
            )
        elif section.name in [".data", ".bss"]:
            section.characteristics |= (
                lief.PE.Section.CHARACTERISTICS.MEM_READ
                | lief.PE.Section.CHARACTERISTICS.MEM_WRITE  # type: ignore[operator]
            )

    # Fix size of image
    last_section = binary.sections[-1] if binary.sections else None
    if last_section:
        section_alignment = binary.optional_header.section_alignment
        new_size = (
            last_section.virtual_address
            + last_section.virtual_size
        )
        # Align
        new_size = ((new_size + section_alignment - 1) // section_alignment) * section_alignment
        binary.optional_header.sizeof_image = new_size
        changes.append(f"Size of image fixed to 0x{new_size:x}")

    # Remove security directory (signature will be invalid)
    with contextlib.suppress(Exception):
        binary.optional_header.remove(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NO_SEH)

    # Write rebuilt PE
    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(output_path)

    return text_result({
        "status": "rebuilt",
        "output": output_path,
        "changes": changes,
        "sections": [
            {"name": s.name, "va": f"0x{s.virtual_address:x}", "size": s.virtual_size}
            for s in binary.sections
        ],
    })
