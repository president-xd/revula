"""
Revula PE/ELF/Mach-O Binary Parser.

Backends: LIEF (primary — unified PE/ELF/Mach-O), pefile (PE detail), pyelftools (ELF detail).
Extracts: sections, imports, exports, TLS callbacks, debug info, rich header,
load config, certificates, relocation tables. Computes file hashes and flags
suspicious characteristics.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, text_result

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------


def compute_file_hashes(data: bytes) -> dict[str, str]:
    """Compute standard + RE-relevant file hashes."""
    hashes: dict[str, str] = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }

    # TLSH — locality-sensitive hash, great for similarity
    try:
        import tlsh

        t = tlsh.hash(data)
        if t:
            hashes["tlsh"] = t
    except (ImportError, ValueError) as e:
        logger.debug("TLSH hash unavailable: %s", e)

    # ssdeep — fuzzy hash (or ppdeep pure-Python fallback)
    try:
        try:
            import ssdeep as _ssdeep
        except ImportError:
            import ppdeep as _ssdeep  # pure-Python fallback
        hashes["ssdeep"] = _ssdeep.hash(data)
    except ImportError as e:
        logger.debug("ssdeep/ppdeep hash unavailable: %s", e)

    return hashes


def compute_imphash(binary: Any) -> str | None:
    """Compute PE import hash via pefile."""
    try:
        import pefile as _pefile

        if isinstance(binary, _pefile.PE):
            return binary.get_imphash()  # type: ignore[no-any-return]
    except (ImportError, Exception) as e:
        logger.debug("Failed to compute imphash: %s", e)
    return None


# ---------------------------------------------------------------------------
# Suspicious indicator detection
# ---------------------------------------------------------------------------


SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualprotect", "writeprocessmemory",
    "createremotethread", "createthread", "ntcreatethreadex",
    "loadlibrarya", "loadlibraryw", "getprocaddress",
    "createprocessa", "createprocessw", "shellexecutea", "shellexecutew",
    "winexec", "urldownloadtofilea", "internetopena", "internetopenurla",
    "httpsendrequesta", "wsastartup", "connect", "send", "recv",
    "cryptencrypt", "cryptdecrypt", "ntunmapviewofsection",
    "rtldecompressbuffer", "isdebuggerpresent", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "adjusttokenprivileges",
    "lookupprivilegevaluea", "openprocesstoken",
    "regcreatekeyexa", "regsetkeyvalueexa", "regopenkeya",
    "createfilea", "createfilew", "writefile", "deletefilea",
    "movefileexa", "findfirstfilea", "gettemppatha",
}

SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2",  # UPX
    ".themida", ".vmp0", ".vmp1",  # VMProtect / Themida
    ".aspack", ".adata",  # ASPack
    ".nsp0", ".nsp1",  # NSPack
    ".packed", ".enigma1", ".enigma2",  # Enigma
    ".mpress1", ".mpress2",  # MPRESS
}


def _analyze_suspicious_pe(sections: list[dict[str, Any]], imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect suspicious characteristics in PE files."""
    indicators: list[dict[str, Any]] = []

    # Check section names
    for sec in sections:
        name = sec.get("name", "").lower().strip("\x00")
        if name in SUSPICIOUS_SECTION_NAMES:
            indicators.append({
                "type": "suspicious_section",
                "detail": f"Known packer section name: {name}",
                "severity": "high",
            })
        entropy = sec.get("entropy", 0)
        if entropy > 7.0:
            indicators.append({
                "type": "high_entropy_section",
                "detail": f"Section '{name}' has entropy {entropy:.2f} (likely packed/encrypted)",
                "severity": "medium",
            })
        if entropy < 1.0 and sec.get("virtual_size", 0) > 4096:
            indicators.append({
                "type": "low_entropy_section",
                "detail": f"Section '{name}' has entropy {entropy:.2f} (sparse/zero-padded)",
                "severity": "low",
            })

    # Check import combinations
    all_imports = set()
    for imp in imports:
        for func in imp.get("functions", []):
            all_imports.add(func.get("name", "").lower())

    injection_combo = {"virtualalloc", "writeprocessmemory", "createremotethread"}
    if injection_combo.issubset(all_imports):
        indicators.append({
            "type": "process_injection",
            "detail": "Imports suggest process injection: VirtualAlloc + WriteProcessMemory + CreateRemoteThread",
            "severity": "high",
        })

    download_combo = {"internetopena", "internetopenurla"}
    if download_combo.issubset(all_imports) or "urldownloadtofilea" in all_imports:
        indicators.append({
            "type": "network_download",
            "detail": "Imports suggest network download capability",
            "severity": "medium",
        })

    antidebug = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"}
    found_antidebug = antidebug.intersection(all_imports)
    if found_antidebug:
        indicators.append({
            "type": "anti_debug",
            "detail": f"Anti-debug imports detected: {', '.join(found_antidebug)}",
            "severity": "medium",
        })

    suspicious_count = len(all_imports.intersection(SUSPICIOUS_IMPORTS))
    if suspicious_count > 5:
        indicators.append({
            "type": "high_suspicious_import_count",
            "detail": f"{suspicious_count} suspicious API imports detected",
            "severity": "medium",
        })

    return indicators


# ---------------------------------------------------------------------------
# LIEF-based analysis (primary — PE/ELF/Mach-O unified)
# ---------------------------------------------------------------------------


def _parse_with_lief(file_path: Path, data: bytes) -> dict[str, Any]:
    """Parse binary with LIEF (supports PE, ELF, Mach-O uniformly)."""
    import lief

    binary = lief.parse(str(file_path))
    if binary is None:
        raise ValueError(f"LIEF could not parse: {file_path}")

    result: dict[str, Any] = {
        "format": "unknown",
        "name": getattr(binary, "name", str(file_path.name)),
        "entrypoint": binary.entrypoint if hasattr(binary, "entrypoint") else None,
    }

    # Detect format and extract format-specific data
    if isinstance(binary, lief.PE.Binary):
        result.update(_parse_pe_lief(binary, data))
    elif isinstance(binary, lief.ELF.Binary):
        result.update(_parse_elf_lief(binary))
    elif isinstance(binary, lief.MachO.Binary):
        result.update(_parse_macho_lief(binary))
    else:
        result["format"] = "unknown"

    return result


def _parse_pe_lief(binary: Any, data: bytes) -> dict[str, Any]:
    """Extract PE-specific information via LIEF."""
    import lief

    result: dict[str, Any] = {"format": "PE"}

    # Basic PE info
    header = binary.header
    opt_header = binary.optional_header

    result["machine"] = str(header.machine).split(".")[-1]
    result["characteristics"] = [str(c).split(".")[-1] for c in header.characteristics_list]
    result["is_64bit"] = opt_header.magic == lief.PE.PE_TYPE.PE32_PLUS
    result["subsystem"] = str(opt_header.subsystem).split(".")[-1]
    result["dll_characteristics"] = [str(c).split(".")[-1] for c in opt_header.dll_characteristics_list]
    result["image_base"] = opt_header.imagebase
    result["size_of_image"] = opt_header.sizeof_image
    result["timestamp"] = header.time_date_stamps

    # Sections
    sections = []
    for sec in binary.sections:

        entropy = sec.entropy
        sections.append({
            "name": sec.name,
            "virtual_address": sec.virtual_address,
            "virtual_size": sec.virtual_size,
            "raw_size": sec.size,
            "entropy": round(entropy, 4),
            "characteristics": [str(c).split(".")[-1] for c in sec.characteristics_list],
        })
    result["sections"] = sections

    # Imports
    imports = []
    for imp in binary.imports:
        funcs = []
        for entry in imp.entries:
            funcs.append({
                "name": entry.name if entry.name else f"ordinal_{entry.data}",
                "iat_address": entry.iat_value,
            })
        imports.append({
            "library": imp.name,
            "functions": funcs,
        })
    result["imports"] = imports

    # Exports
    if binary.has_exports:
        export = binary.get_export()
        entries = []
        for entry in export.entries:
            entries.append({
                "name": entry.name,
                "ordinal": entry.ordinal,
                "address": entry.address,
            })
        result["exports"] = {
            "name": export.name,
            "entries": entries,
        }

    # TLS
    if binary.has_tls:
        tls = binary.tls
        result["tls"] = {
            "addressof_callbacks": tls.addressof_callbacks,
            "callbacks": list(tls.callbacks),
            "sizeof_zero_fill": tls.sizeof_zero_fill,
        }

    # Debug info
    if binary.has_debug:
        debug_entries = []
        for dbg in binary.debug:
            debug_entries.append({
                "type": str(dbg.type).split(".")[-1] if hasattr(dbg, "type") else "unknown",
            })
        result["debug"] = debug_entries

    # Rich header
    if binary.has_rich_header:
        rh = binary.rich_header
        entries = []
        for entry in rh.entries:
            entries.append({
                "id": entry.id,
                "build_id": entry.build_id,
                "count": entry.count,
            })
        result["rich_header"] = {
            "key": rh.key,
            "entries": entries,
        }

    # Load config
    if binary.has_configuration:
        lc = binary.load_configuration
        result["load_config"] = {
            "security_cookie": getattr(lc, "security_cookie", None),
            "se_handler_table": getattr(lc, "se_handler_table", None),
            "guard_cf_function_table": getattr(lc, "guard_cf_function_table", None),
        }

    # Relocations
    if binary.has_relocations:
        relocs = []
        for reloc in binary.relocations:
            relocs.append({
                "virtual_address": reloc.virtual_address,
                "entry_count": len(list(reloc.entries)),
            })
        result["relocations_summary"] = {
            "count": len(relocs),
            "entries": relocs[:20],  # Cap at 20 for readability
        }

    # Signatures / certificates
    if binary.has_signatures:
        sigs = []
        for sig in binary.signatures:
            signer_info = []
            for si in sig.signers:
                signer_info.append({
                    "issuer": str(si.issuer) if hasattr(si, "issuer") else "unknown",
                    "serial": str(si.serial_number) if hasattr(si, "serial_number") else "unknown",
                })
            sigs.append({"signers": signer_info})
        result["signatures"] = sigs

    # Suspicious indicator analysis
    result["suspicious_indicators"] = _analyze_suspicious_pe(sections, imports)

    return result


def _parse_elf_lief(binary: Any) -> dict[str, Any]:
    """Extract ELF-specific information via LIEF."""

    result: dict[str, Any] = {"format": "ELF"}

    header = binary.header
    result["class"] = str(header.identity_class).split(".")[-1]
    result["data_encoding"] = str(header.identity_data).split(".")[-1]
    result["os_abi"] = str(header.identity_os_abi).split(".")[-1]
    result["machine"] = str(header.machine_type).split(".")[-1]
    result["type"] = str(header.file_type).split(".")[-1]
    result["entrypoint"] = binary.entrypoint

    # Sections
    sections = []
    for sec in binary.sections:
        sections.append({
            "name": sec.name,
            "type": str(sec.type).split(".")[-1],
            "virtual_address": sec.virtual_address,
            "size": sec.size,
            "entropy": round(sec.entropy, 4),
            "flags": [str(f).split(".")[-1] for f in sec.flags_list],
        })
    result["sections"] = sections

    # Segments
    segments = []
    for seg in binary.segments:
        segments.append({
            "type": str(seg.type).split(".")[-1],
            "virtual_address": seg.virtual_address,
            "virtual_size": seg.virtual_size,
            "physical_size": seg.physical_size,
            "flags": str(seg.flags).split(".")[-1] if hasattr(seg, "flags") else "",
        })
    result["segments"] = segments

    # Dynamic entries / shared libraries
    if hasattr(binary, "libraries"):
        libraries = list(binary.libraries)
        result["shared_libraries"] = libraries

    # Symbols (symtab_symbols in LIEF >= 0.16, static_symbols in older)
    static_syms = []
    symtab = getattr(binary, "symtab_symbols", None) or getattr(binary, "static_symbols", [])
    for sym in symtab:
        if sym.name:
            static_syms.append({
                "name": sym.name,
                "value": sym.value,
                "size": sym.size,
                "type": str(sym.type).split(".")[-1],
                "binding": str(sym.binding).split(".")[-1],
            })
    result["static_symbols_count"] = len(static_syms)
    result["static_symbols"] = static_syms[:100]  # Cap for readability

    dynamic_syms = []
    for sym in binary.dynamic_symbols:
        if sym.name:
            dynamic_syms.append({
                "name": sym.name,
                "value": sym.value,
                "type": str(sym.type).split(".")[-1],
                "binding": str(sym.binding).split(".")[-1],
            })
    result["dynamic_symbols_count"] = len(dynamic_syms)
    result["dynamic_symbols"] = dynamic_syms[:100]

    # Relocations
    relocs = list(binary.relocations)
    result["relocation_count"] = len(relocs)

    # Notes
    notes = []
    for note in binary.notes:
        notes.append({
            "name": note.name if hasattr(note, "name") else "",
            "type": str(note.type).split(".")[-1] if hasattr(note, "type") else "unknown",
        })
    result["notes"] = notes

    # Interpreter
    if binary.has_interpreter:
        result["interpreter"] = binary.interpreter

    return result


def _parse_macho_lief(binary: Any) -> dict[str, Any]:
    """Extract Mach-O specific information via LIEF."""
    result: dict[str, Any] = {"format": "MachO"}

    header = binary.header
    result["cpu_type"] = str(header.cpu_type).split(".")[-1]
    result["cpu_subtype"] = header.cpu_subtype
    result["file_type"] = str(header.file_type).split(".")[-1]
    result["flags"] = [str(f).split(".")[-1] for f in header.flags_list]

    # Sections
    sections = []
    for sec in binary.sections:
        sections.append({
            "name": sec.name,
            "segment_name": sec.segment_name if hasattr(sec, "segment_name") else "",
            "address": sec.address,
            "size": sec.size,
            "entropy": round(sec.entropy, 4),
        })
    result["sections"] = sections

    # Segments
    segments = []
    for seg in binary.segments:
        segments.append({
            "name": seg.name,
            "virtual_address": seg.virtual_address,
            "virtual_size": seg.virtual_size,
            "file_size": seg.file_size,
        })
    result["segments"] = segments

    # Libraries
    libraries = []
    for lib in binary.libraries:
        libraries.append({
            "name": lib.name,
            "current_version": str(lib.current_version) if hasattr(lib, "current_version") else "",
        })
    result["libraries"] = libraries

    # Symbols
    symbols = []
    for sym in binary.symbols:
        if sym.name:
            symbols.append({
                "name": sym.name,
                "value": sym.value,
                "type": sym.type,
            })
    result["symbols_count"] = len(symbols)
    result["symbols"] = symbols[:100]

    return result


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_parse_binary",
    description=(
        "Parse PE, ELF, or Mach-O binary files. Extracts sections, imports, exports, "
        "TLS callbacks, debug info, rich header, certificates, relocations. "
        "Computes file hashes (MD5, SHA256, TLSH, ssdeep, imphash). "
        "Flags suspicious characteristics: packer sections, injection imports, anti-debug. "
        "Backend: LIEF (primary, supports all formats), pefile (PE detail), pyelftools (ELF detail)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file to analyze.",
            },
            "include_symbols": {
                "type": "boolean",
                "description": "Include symbol table (can be large). Default: true.",
                "default": True,
            },
            "include_relocations": {
                "type": "boolean",
                "description": "Include relocation entries. Default: true.",
                "default": True,
            },
        },
        "required": ["binary_path"],
    },
    category="static",
    requires_modules=["lief"],
)
async def handle_parse_binary(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a PE/ELF/Mach-O binary and return comprehensive metadata."""
    binary_path_str = arguments["binary_path"]

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    # Read raw data for hashing
    data = file_path.read_bytes()
    file_size = len(data)

    # Compute hashes
    hashes = compute_file_hashes(data)

    # Parse with LIEF
    parsed = _parse_with_lief(file_path, data)

    # Try imphash via pefile for PE
    if parsed.get("format") == "PE":
        try:
            import pefile as _pefile

            pe = _pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            ih = pe.get_imphash()
            if ih:
                hashes["imphash"] = ih
            pe.close()
        except Exception as e:
            logger.debug("pefile imphash extraction failed: %s", e)

    # Filter based on flags
    if not arguments.get("include_symbols", True):
        parsed.pop("static_symbols", None)
        parsed.pop("dynamic_symbols", None)
        parsed.pop("symbols", None)

    if not arguments.get("include_relocations", True):
        parsed.pop("relocations_summary", None)

    result = {
        "file_path": str(file_path),
        "file_size": file_size,
        "hashes": hashes,
        **parsed,
    }

    return text_result(result)
