"""
Revula Symbol Resolution — DWARF, PDB, export/import symbols, stripped binary heuristics.

Extracts and resolves:
- DWARF debug info (via pyelftools)
- PDB symbols (via llvm-pdbutil or symchk)
- Export/import symbol tables (via LIEF)
- Stripped binary heuristics (function prologue scanning)
"""

from __future__ import annotations

import logging
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DWARF extraction
# ---------------------------------------------------------------------------


def _extract_dwarf_symbols(file_path: str) -> dict[str, Any]:
    """Extract DWARF debug information from ELF binary."""
    from elftools.elf.elffile import ELFFile

    result: dict[str, Any] = {
        "has_dwarf": False,
        "compilation_units": [],
        "functions": [],
        "variables": [],
    }

    with open(file_path, "rb") as f:
        elf = ELFFile(f)  # type: ignore[no-untyped-call]

        if not elf.has_dwarf_info():  # type: ignore[no-untyped-call]
            return result

        result["has_dwarf"] = True
        dwarf = elf.get_dwarf_info()  # type: ignore[no-untyped-call]

        for cu in dwarf.iter_CUs():
            top_die = cu.get_top_DIE()
            cu_info: dict[str, Any] = {
                "name": top_die.attributes.get("DW_AT_name", {}).value.decode("utf-8", errors="replace")
                if "DW_AT_name" in top_die.attributes
                else "unknown",
                "comp_dir": top_die.attributes.get("DW_AT_comp_dir", {}).value.decode("utf-8", errors="replace")
                if "DW_AT_comp_dir" in top_die.attributes
                else "",
                "language": str(top_die.attributes.get("DW_AT_language", {}).value)
                if "DW_AT_language" in top_die.attributes
                else "unknown",
            }
            result["compilation_units"].append(cu_info)

            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    func: dict[str, Any] = {}
                    if "DW_AT_name" in die.attributes:
                        func["name"] = die.attributes["DW_AT_name"].value.decode("utf-8", errors="replace")
                    if "DW_AT_low_pc" in die.attributes:
                        func["low_pc"] = die.attributes["DW_AT_low_pc"].value
                    if "DW_AT_high_pc" in die.attributes:
                        high_pc = die.attributes["DW_AT_high_pc"]
                        if high_pc.form.startswith("DW_FORM_addr"):
                            func["high_pc"] = high_pc.value
                        else:
                            func["high_pc"] = func.get("low_pc", 0) + high_pc.value
                    if "DW_AT_decl_file" in die.attributes:
                        func["decl_file_idx"] = die.attributes["DW_AT_decl_file"].value
                    if "DW_AT_decl_line" in die.attributes:
                        func["decl_line"] = die.attributes["DW_AT_decl_line"].value

                    if func.get("name"):
                        result["functions"].append(func)

                elif die.tag == "DW_TAG_variable":
                    var: dict[str, Any] = {}
                    if "DW_AT_name" in die.attributes:
                        var["name"] = die.attributes["DW_AT_name"].value.decode("utf-8", errors="replace")
                    if "DW_AT_type" in die.attributes:
                        var["type_offset"] = die.attributes["DW_AT_type"].value
                    if var.get("name"):
                        result["variables"].append(var)

    result["function_count"] = len(result["functions"])
    result["variable_count"] = len(result["variables"])

    return result


# ---------------------------------------------------------------------------
# LIEF-based symbol extraction (works for PE/ELF/Mach-O)
# ---------------------------------------------------------------------------


def _extract_lief_symbols(file_path: str) -> dict[str, Any]:
    """Extract symbols using LIEF (universal backend)."""
    import lief

    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Cannot parse: {file_path}")

    result: dict[str, Any] = {
        "format": "unknown",
        "imports": [],
        "exports": [],
        "symbols": [],
        "is_stripped": True,
    }

    if isinstance(binary, lief.PE.Binary):
        result["format"] = "PE"

        # Imports
        for imp in binary.imports:
            for entry in imp.entries:
                result["imports"].append(
                    {
                        "library": imp.name,
                        "name": entry.name if entry.name else f"ordinal_{entry.data}",
                        "iat_address": entry.iat_value,
                    }
                )

        # Exports
        if binary.has_exports:
            export = binary.get_export()
            for exp_entry in export.entries:
                result["exports"].append(
                    {
                        "name": exp_entry.name,
                        "ordinal": exp_entry.ordinal,
                        "address": exp_entry.address,
                    }
                )

        result["is_stripped"] = not binary.has_debug

    elif isinstance(binary, lief.ELF.Binary):
        result["format"] = "ELF"

        for sym in binary.dynamic_symbols:
            if sym.imported:
                result["imports"].append(
                    {
                        "name": sym.name,
                        "value": sym.value,
                        "type": str(sym.type).split(".")[-1],
                    }
                )
            elif sym.exported:
                result["exports"].append(
                    {
                        "name": sym.name,
                        "value": sym.value,
                        "type": str(sym.type).split(".")[-1],
                    }
                )

        for sym in binary.symtab_symbols:
            if sym.name:
                result["symbols"].append(
                    {
                        "name": sym.name,
                        "value": sym.value,
                        "size": sym.size,
                        "type": str(sym.type).split(".")[-1],
                        "binding": str(sym.binding).split(".")[-1],
                    }
                )

        result["is_stripped"] = len(list(binary.symtab_symbols)) == 0

    elif isinstance(binary, lief.MachO.Binary):
        result["format"] = "MachO"

        for macho_sym in binary.symbols:
            if macho_sym.name:
                sym_entry: dict[str, Any] = {
                    "name": macho_sym.name,
                    "value": macho_sym.value,
                    "type": macho_sym.type,
                }
                if macho_sym.has_export_info:
                    result["exports"].append(sym_entry)
                else:
                    result["symbols"].append(sym_entry)

    result["import_count"] = len(result["imports"])
    result["export_count"] = len(result["exports"])
    result["symbol_count"] = len(result["symbols"])

    return result


# ---------------------------------------------------------------------------
# Function prologue heuristic (for stripped binaries)
# ---------------------------------------------------------------------------


def _scan_function_prologues(
    data: bytes,
    arch: str = "x64",
    base_addr: int = 0,
) -> list[dict[str, Any]]:
    """
    Scan for function prologues in stripped binaries.

    Heuristic: look for common prologue patterns.
    """
    functions: list[dict[str, Any]] = []

    if arch in ("x86", "x64"):
        # Common x86/x64 prologues
        patterns = [
            (b"\x55\x48\x89\xe5", "push rbp; mov rbp, rsp"),  # x64
            (b"\x55\x89\xe5", "push ebp; mov ebp, esp"),  # x86
            (b"\x48\x83\xec", "sub rsp, imm8"),  # x64 leaf
            (b"\x48\x89\x5c\x24", "mov [rsp+xx], rbx"),  # x64 win
            (b"\x40\x53\x48\x83\xec", "push rbx; sub rsp, imm8"),  # x64 win
        ]

        for pattern, desc in patterns:
            offset = 0
            while offset < len(data):
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                functions.append(
                    {
                        "address": f"0x{base_addr + idx:x}",
                        "offset": idx,
                        "pattern": desc,
                        "confidence": "medium",
                    }
                )
                offset = idx + 1

    elif arch in ("arm", "arm64"):
        # ARM: STMDB SP!, {R4-R11, LR}  or  STP X29, X30, [SP, #-xx]!
        # Simplified: look for push {.*lr} patterns
        patterns = [
            (b"\xe9\x2d", "STMDB (ARM push)"),
            (b"\xb5", "PUSH (Thumb)"),
        ]

        for pattern, desc in patterns:
            offset = 0
            while offset < len(data):
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                functions.append(
                    {
                        "address": f"0x{base_addr + idx:x}",
                        "offset": idx,
                        "pattern": desc,
                        "confidence": "low",
                    }
                )
                offset = idx + 1

    # Deduplicate near-identical addresses (within 4 bytes)
    if functions:
        functions.sort(key=lambda f: f["offset"])
        deduped = [functions[0]]
        for f in functions[1:]:
            if f["offset"] - deduped[-1]["offset"] > 4:
                deduped.append(f)
        functions = deduped

    return functions


# ---------------------------------------------------------------------------
# PDB extraction via llvm-pdbutil
# ---------------------------------------------------------------------------


async def _extract_pdb_symbols(pdb_path: str) -> dict[str, Any]:
    """Extract symbols from PDB file using llvm-pdbutil."""
    from revula.config import get_config
    from revula.sandbox import safe_subprocess

    config = get_config()
    pdbutil = config.require_tool("pdbutil")

    result = await safe_subprocess(
        [pdbutil, "dump", "-all", pdb_path],
        timeout=60,
    )

    if not result.success:
        raise RuntimeError(f"llvm-pdbutil failed: {result.stderr[:500]}")

    # Parse output (simplified — full PDB parsing is complex)
    symbols: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if "S_GPROC32" in line or "S_LPROC32" in line:
            symbols.append({"raw": line, "type": "function"})
        elif "S_GDATA32" in line or "S_LDATA32" in line:
            symbols.append({"raw": line, "type": "data"})

    return {
        "pdb_path": pdb_path,
        "symbol_count": len(symbols),
        "symbols": symbols,
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_symbols",
    description=(
        "Extract and resolve symbols from binary files. "
        "Supports: DWARF debug info (ELF), PDB symbols (PE, via llvm-pdbutil), "
        "export/import tables (PE/ELF/Mach-O via LIEF), "
        "function prologue heuristics for stripped binaries. "
        "Can detect if a binary is stripped and attempt symbol recovery."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file.",
            },
            "pdb_path": {
                "type": "string",
                "description": "Path to PDB file (optional, for PE symbol resolution).",
            },
            "scan_prologues": {
                "type": "boolean",
                "description": "Scan for function prologues in stripped binaries. Default: false.",
                "default": False,
            },
            "arch": {
                "type": "string",
                "enum": ["x86", "x64", "arm", "arm64"],
                "description": "Architecture for prologue scanning. Default: x64.",
                "default": "x64",
            },
        },
        "required": ["binary_path"],
    },
    category="static",
    requires_modules=["lief"],
)
async def handle_symbols(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract symbols from a binary file."""
    binary_path_str = arguments["binary_path"]
    pdb_path = arguments.get("pdb_path")
    scan_prologues = arguments.get("scan_prologues", False)
    arch = arguments.get("arch", "x64")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    result: dict[str, Any] = {
        "file_path": str(file_path),
    }

    # LIEF symbols (always available)
    try:
        lief_result = _extract_lief_symbols(str(file_path))
        result.update(lief_result)
    except Exception as e:
        result["lief_error"] = str(e)

    # DWARF (for ELF)
    if result.get("format") == "ELF":
        try:
            dwarf_result = _extract_dwarf_symbols(str(file_path))
            result["dwarf"] = dwarf_result
        except ImportError:
            result["dwarf_error"] = "pyelftools not available"
        except Exception as e:
            result["dwarf_error"] = str(e)

    # PDB (for PE)
    if pdb_path:
        try:
            pdb_result = await _extract_pdb_symbols(pdb_path)
            result["pdb"] = pdb_result
        except Exception as e:
            result["pdb_error"] = str(e)

    # Function prologue scanning (for stripped binaries)
    if scan_prologues and result.get("is_stripped", False):
        try:
            data = file_path.read_bytes()
            prologues = _scan_function_prologues(data, arch=arch)
            result["detected_functions"] = prologues
            result["detected_function_count"] = len(prologues)
        except Exception as e:
            result["prologue_scan_error"] = str(e)

    return text_result(result)
