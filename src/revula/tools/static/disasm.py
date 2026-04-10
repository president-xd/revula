"""
Revula Disassembler — multi-backend disassembly with structured output.

Backends:
- Capstone (always available) — primary, handles all architectures
- r2pipe (if radare2/rizin installed) — uses pDj JSON output
- objdump (fallback) — parsed structured output

Supports: x86, x64, ARM (with auto thumb detection), ARM64, MIPS, RISC-V, PPC.
"""

from __future__ import annotations

import logging
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Architecture mapping
# ---------------------------------------------------------------------------

CAPSTONE_ARCH_MAP: dict[str, tuple[int, int]] = {}  # Populated at import time


def _init_capstone_map() -> None:
    """Initialize Capstone arch/mode mapping."""
    global CAPSTONE_ARCH_MAP
    try:
        import capstone as cs

        CAPSTONE_ARCH_MAP = {
            "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
            "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
            "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
            "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
            "arm_thumb": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
            **({
                "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
                "aarch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
            } if hasattr(cs, "CS_ARCH_ARM64") else {}),
            "mips": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN),
            "mips32": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
            "mips64": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64),
            "riscv32": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV32) if hasattr(cs, "CS_ARCH_RISCV") else (0, 0),
            "riscv64": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64) if hasattr(cs, "CS_ARCH_RISCV") else (0, 0),
            "ppc": (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN),
            "ppc64": (cs.CS_ARCH_PPC, cs.CS_MODE_64 | cs.CS_MODE_BIG_ENDIAN),
        }
    except ImportError as e:
        logger.debug("Capstone initialization skipped: %s", e)


_init_capstone_map()


# ---------------------------------------------------------------------------
# Auto-detect ARM Thumb mode
# ---------------------------------------------------------------------------


def _detect_arm_thumb(code: bytes, base_addr: int) -> bool:
    """
    Heuristic: detect if ARM code is Thumb mode.

    - If base address has LSB set, it's Thumb
    - Check for common Thumb instruction patterns (2-byte aligned)
    - Check for BX/BLX instructions that switch mode
    """
    # LSB of address indicates Thumb
    if base_addr & 1:
        return True

    if len(code) < 4:
        return False

    # Check first instruction patterns
    # Thumb instructions are 16-bit, ARM are 32-bit
    # Common Thumb prologues: PUSH {r4-r7, lr} = 0xB5xx
    first_halfword = int.from_bytes(code[0:2], "little")
    if (first_halfword & 0xFF00) == 0xB500:  # PUSH with LR
        return True
    if (first_halfword & 0xF800) == 0x4800:  # LDR Rd, [PC, #imm]
        return True
    if (first_halfword & 0xFF00) == 0xB000:  # ADD/SUB SP
        return True

    return False


# ---------------------------------------------------------------------------
# Capstone backend
# ---------------------------------------------------------------------------


def _disasm_capstone(
    code: bytes,
    arch: str,
    base_addr: int = 0,
    count: int = 0,
    syntax: str = "intel",
) -> list[dict[str, Any]]:
    """Disassemble using Capstone."""
    import capstone as cs

    # Auto-detect thumb for ARM
    effective_arch = arch.lower()
    if effective_arch == "arm" and _detect_arm_thumb(code, base_addr):
        effective_arch = "arm_thumb"
        logger.info("Auto-detected ARM Thumb mode")

    if effective_arch not in CAPSTONE_ARCH_MAP:
        raise ValueError(
            f"Unsupported architecture: {arch}. "
            f"Supported: {', '.join(sorted(CAPSTONE_ARCH_MAP.keys()))}"
        )

    cs_arch, cs_mode = CAPSTONE_ARCH_MAP[effective_arch]
    if cs_arch == 0:
        raise ValueError(f"Architecture {arch} not supported in this Capstone version")

    md = cs.Cs(cs_arch, cs_mode)

    # Set syntax for x86
    if effective_arch in ("x86", "x64", "x86_64"):
        if syntax.lower() == "att":
            md.syntax = cs.CS_OPT_SYNTAX_ATT
        else:
            md.syntax = cs.CS_OPT_SYNTAX_INTEL

    md.detail = True

    instructions: list[dict[str, Any]] = []
    disasm_iter = md.disasm(code, base_addr)

    for i, insn in enumerate(disasm_iter):
        if count > 0 and i >= count:
            break

        inst_bytes = code[insn.address - base_addr:insn.address - base_addr + insn.size]

        entry: dict[str, Any] = {
            "address": f"0x{insn.address:x}",
            "address_int": insn.address,
            "bytes": inst_bytes.hex(),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "size": insn.size,
        }

        # Add groups info if available (Capstone 6+ exposes directly on insn)
        try:
            groups = []
            for g in insn.groups:
                try:
                    groups.append(insn.group_name(g))
                except Exception:
                    groups.append(str(g))
            if groups:
                entry["groups"] = groups

            # Detect branches/calls for annotation
            if cs.CS_GRP_CALL in insn.groups:
                entry["comment"] = "CALL"
            elif cs.CS_GRP_RET in insn.groups:
                entry["comment"] = "RETURN"
            elif cs.CS_GRP_JUMP in insn.groups:
                entry["comment"] = "JUMP"
            elif cs.CS_GRP_INT in insn.groups:
                entry["comment"] = "INTERRUPT"
        except AttributeError as e:
            logger.debug("Instruction group metadata unavailable for %s: %s", insn.mnemonic, e)

        instructions.append(entry)

    return instructions


# ---------------------------------------------------------------------------
# r2pipe backend
# ---------------------------------------------------------------------------


async def _disasm_r2(
    binary_path: str,
    offset: int = 0,
    count: int = 50,
    arch: str = "",
) -> list[dict[str, Any]]:
    """Disassemble using radare2 via r2pipe (uses pdj for JSON output)."""
    import asyncio

    import r2pipe

    loop = asyncio.get_running_loop()

    # Map our arch names to r2 asm.arch + asm.bits
    arch_map: dict[str, tuple[str, int]] = {
        "x86": ("x86", 32),
        "x64": ("x86", 64),
        "arm": ("arm", 32),
        "arm64": ("arm", 64),
        "mips": ("mips", 32),
        "mips32": ("mips", 32),
        "mips64": ("mips", 64),
        "riscv32": ("riscv", 32),
        "riscv64": ("riscv", 64),
        "ppc": ("ppc", 32),
        "ppc64": ("ppc", 64),
    }

    def _do_r2() -> list[dict[str, Any]]:
        r2 = r2pipe.open(binary_path, flags=["-2"])  # -2: disable stderr
        try:
            r2.cmd("aaa")  # Analyze all

            # Map arch names to r2 format (e.g. "x64" -> arch=x86, bits=64)
            if arch and arch in arch_map:
                r2_arch, r2_bits = arch_map[arch]
                r2.cmd(f"e asm.arch={r2_arch}")
                r2.cmd(f"e asm.bits={r2_bits}")
            elif arch:
                # Unknown arch — pass through and hope r2 understands
                r2.cmd(f"e asm.arch={arch}")

            if offset:
                r2.cmd(f"s {offset}")
            else:
                # Seek to entry point; without this we stay at 0x0 (ELF header)
                r2.cmd("s entry0")

            # pdj = disassemble N instructions as JSON (not pDj which is N bytes)
            result = r2.cmdj(f"pdj {count}")
            if not result:
                return []

            instructions = []
            for insn in result:
                # r2 JSON fields: addr, opcode, disasm, bytes, size, type
                disasm = insn.get("disasm") or insn.get("opcode") or ""
                disasm_parts = disasm.split(None, 1)
                mnemonic = disasm_parts[0] if disasm_parts else insn.get("type", "")
                op_str = disasm_parts[1] if len(disasm_parts) > 1 else ""

                entry = {
                    "address": f"0x{insn.get('addr', 0):x}",
                    "address_int": insn.get("addr", 0),
                    "bytes": insn.get("bytes", ""),
                    "mnemonic": mnemonic,
                    "op_str": op_str,
                    "size": insn.get("size", 0),
                }

                if insn.get("comment"):
                    entry["comment"] = insn["comment"]
                if insn.get("xrefs"):
                    entry["xrefs"] = insn["xrefs"]
                if insn.get("flags"):
                    entry["flags"] = insn["flags"]

                instructions.append(entry)

            return instructions
        finally:
            r2.quit()

    return await loop.run_in_executor(None, _do_r2)


# ---------------------------------------------------------------------------
# objdump backend
# ---------------------------------------------------------------------------


async def _disasm_objdump(
    binary_path: str,
    offset: int = 0,
    count: int = 50,
    syntax: str = "intel",
) -> list[dict[str, Any]]:
    """Disassemble using objdump (fallback)."""
    from revula.config import get_config
    from revula.sandbox import safe_subprocess

    config = get_config()
    objdump_path = config.require_tool("objdump")

    cmd = [objdump_path, "-d"]
    if syntax.lower() == "intel":
        cmd.append("-M")
        cmd.append("intel")

    if offset:
        cmd.extend(["--start-address", str(offset)])
    if count and offset:
        # Approximate: assume avg instruction ~4 bytes
        cmd.extend(["--stop-address", str(offset + count * 8)])

    cmd.append(binary_path)

    result = await safe_subprocess(cmd, timeout=30)
    result.raise_on_error("objdump disassembly")

    instructions: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        if line.startswith("Disassembly") or line.startswith("..."):
            continue

        # Parse objdump format: "  400080:  48 89 e5     mov rbp, rsp"
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue

        try:
            addr_str = parts[0].strip()
            addr = int(addr_str, 16)
        except ValueError:
            continue

        rest = parts[1].strip()
        # Split bytes from mnemonic
        tokens = rest.split("\t")
        if len(tokens) >= 2:
            bytes_str = tokens[0].strip().replace(" ", "")
            disasm = "\t".join(tokens[1:]).strip()
            disasm_parts = disasm.split(None, 1)
            mnemonic = disasm_parts[0] if disasm_parts else ""
            op_str = disasm_parts[1] if len(disasm_parts) > 1 else ""

            instructions.append({
                "address": f"0x{addr:x}",
                "address_int": addr,
                "bytes": bytes_str,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "size": len(bytes_str) // 2,
            })

    return instructions[:count] if count else instructions


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_disassemble",
    description=(
        "Disassemble binary code. Supports x86, x64, ARM (auto thumb detection), ARM64, "
        "MIPS, RISC-V, PPC. "
        "Backends: Capstone (always available, primary), r2pipe (if radare2 installed — uses pDj JSON), "
        "objdump (fallback). "
        "Can disassemble from a file at an offset or from raw hex bytes directly."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to binary file. Mutually exclusive with hex_bytes.",
            },
            "hex_bytes": {
                "type": "string",
                "description": "Raw hex string to disassemble (e.g., '554889e5'). Mutually exclusive with binary_path.",
            },
            "arch": {
                "type": "string",
                "enum": [
                    "x86", "x64", "arm", "arm64", "mips", "mips32",
                    "mips64", "riscv32", "riscv64", "ppc", "ppc64",
                ],
                "description": "Target architecture. Default: x64.",
                "default": "x64",
            },
            "offset": {
                "type": "integer",
                "description": "Start offset/address to disassemble from. Default: 0.",
                "default": 0,
            },
            "count": {
                "type": "integer",
                "description": "Number of instructions to disassemble. Default: 50. 0 = all.",
                "default": 50,
            },
            "syntax": {
                "type": "string",
                "enum": ["intel", "att"],
                "description": "Assembly syntax for x86/x64. Default: intel.",
                "default": "intel",
            },
            "backend": {
                "type": "string",
                "enum": ["capstone", "r2", "objdump", "auto"],
                "description": "Disassembly backend. 'auto' selects best available. Default: auto.",
                "default": "auto",
            },
        },
        "oneOf": [
            {"required": ["binary_path"]},
            {"required": ["hex_bytes"]},
        ],
    },
    category="static",
    requires_modules=["capstone"],
)
async def handle_disassemble(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Disassemble binary code from file or raw hex bytes."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")
    arch = arguments.get("arch", "x64")
    offset = arguments.get("offset", 0)
    count = arguments.get("count", 50)
    syntax = arguments.get("syntax", "intel")
    backend = arguments.get("backend", "auto")

    if not binary_path and not hex_bytes:
        return error_result("Either 'binary_path' or 'hex_bytes' must be provided.")

    # --- Disassemble from raw hex bytes (Capstone only) ---
    if hex_bytes:
        try:
            code = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
        except ValueError as e:
            return error_result(f"Invalid hex string: {e}")

        instructions = _disasm_capstone(code, arch, base_addr=offset, count=count, syntax=syntax)
        return text_result({
            "source": "hex_bytes",
            "arch": arch,
            "syntax": syntax,
            "backend": "capstone",
            "base_address": f"0x{offset:x}",
            "instruction_count": len(instructions),
            "instructions": instructions,
        })

    # --- Disassemble from binary file ---
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    assert binary_path is not None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    # Select backend
    if backend == "auto":
        # Prefer r2 if available (better analysis), fall back to capstone
        try:
            import r2pipe  # noqa: F401
            backend = "r2"
        except ImportError:
            backend = "capstone"

    if backend == "r2":
        try:
            instructions = await _disasm_r2(str(file_path), offset=offset, count=count, arch=arch)
            return text_result({
                "source": str(file_path),
                "arch": arch,
                "syntax": syntax,
                "backend": "r2",
                "offset": f"0x{offset:x}",
                "instruction_count": len(instructions),
                "instructions": instructions,
            })
        except Exception as e:
            logger.warning("r2 backend failed, falling back to capstone: %s", e)
            backend = "capstone"

    if backend == "objdump":
        try:
            instructions = await _disasm_objdump(
                str(file_path), offset=offset, count=count, syntax=syntax
            )
            return text_result({
                "source": str(file_path),
                "arch": arch,
                "syntax": syntax,
                "backend": "objdump",
                "offset": f"0x{offset:x}",
                "instruction_count": len(instructions),
                "instructions": instructions,
            })
        except Exception as e:
            logger.warning("objdump backend failed, falling back to capstone: %s", e)
            backend = "capstone"

    # Capstone (always available)
    data = file_path.read_bytes()
    if offset > 0:
        # For file offsets, we need to read from that position
        code = data[offset:offset + (count * 16 if count else len(data))]
        base_addr = offset
    else:
        code = data
        base_addr = 0

    instructions = _disasm_capstone(code, arch, base_addr=base_addr, count=count, syntax=syntax)

    return text_result({
        "source": str(file_path),
        "arch": arch,
        "syntax": syntax,
        "backend": "capstone",
        "offset": f"0x{offset:x}",
        "instruction_count": len(instructions),
        "instructions": instructions,
    })
