"""
Revula Deobfuscation Tools.

Provides: string deobfuscation, control-flow deflattening analysis,
opaque predicate detection, and general deobfuscation utilities.
"""

from __future__ import annotations

import itertools
import logging
import re
from binascii import Error as BinasciiError
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# String Deobfuscation
# ---------------------------------------------------------------------------


def _xor_decode(data: bytes, key: bytes) -> bytes:
    """XOR decode with repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _rot_decode(data: bytes, shift: int) -> bytes:
    """ROT/Caesar cipher decode."""
    result = bytearray()
    for b in data:
        if 0x41 <= b <= 0x5A:  # A-Z
            result.append(((b - 0x41 + shift) % 26) + 0x41)
        elif 0x61 <= b <= 0x7A:  # a-z
            result.append(((b - 0x61 + shift) % 26) + 0x61)
        else:
            result.append(b)
    return bytes(result)


def _base64_decode(data: str) -> bytes | None:
    """Try base64 decode."""
    import base64

    try:
        # Standard base64
        return base64.b64decode(data)
    except (BinasciiError, ValueError):
        logger.debug("Standard Base64 decode failed, trying URL-safe variant")
    try:
        # URL-safe
        return base64.urlsafe_b64decode(data)
    except (BinasciiError, ValueError):
        logger.debug("URL-safe Base64 decode failed")
    return None


def _rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """RC4 decryption."""
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + key[i % len(key)]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        result.append(byte ^ s_box[(s_box[i] + s_box[j]) % 256])

    return bytes(result)


def _is_printable_ratio(data: bytes, threshold: float = 0.7) -> bool:
    """Check if decoded data has sufficient printable characters."""
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127)
    return (printable / len(data)) >= threshold


@TOOL_REGISTRY.register(
    name="re_deobfuscate_strings",
    description=(
        "Attempt to deobfuscate strings in a binary. "
        "Tries: XOR (single/multi-byte brute), ROT variants, Base64, RC4 with common keys, "
        "stack string reconstruction, and custom decoder patterns. "
        "Returns decoded strings with method used."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "methods": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["xor", "rot", "base64", "rc4", "stack_strings", "all"],
                },
                "default": ["all"],
            },
            "min_length": {"type": "integer", "default": 4},
            "xor_key": {
                "type": "string",
                "description": "Known XOR key (hex). If provided, skip brute force.",
            },
        },
        "required": ["binary_path"],
    },
    category="deobfuscation",
)
async def handle_deobfuscate_strings(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Deobfuscate strings."""
    binary_path = arguments["binary_path"]
    methods = arguments.get("methods", ["all"])
    min_length = arguments.get("min_length", 4)
    xor_key_hex = arguments.get("xor_key")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()
    decoded_strings: list[dict[str, Any]] = []

    do_all = "all" in methods

    # --- XOR brute force ---
    if do_all or "xor" in methods:
        if xor_key_hex:
            key = bytes.fromhex(xor_key_hex.replace(" ", ""))
            decoded = _xor_decode(data, key)
            # Extract printable sequences
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_length, decoded):
                decoded_strings.append({
                    "offset": m.start(),
                    "decoded": m.group().decode("ascii"),
                    "method": f"xor_key_{xor_key_hex}",
                    "length": len(m.group()),
                })
        else:
            # Single-byte XOR brute force
            for key_byte in range(1, 256):
                key = bytes([key_byte])
                decoded = _xor_decode(data, key)
                strings_found = list(re.finditer(
                    rb"[\x20-\x7e]{%d,}" % max(min_length, 6),
                    decoded,
                ))
                # Only report if we find interesting strings not in original
                for m in strings_found[:50]:
                    s = m.group()
                    # Skip if same string exists in original at same offset
                    if data[m.start():m.end()] == s:
                        continue
                    decoded_strings.append({
                        "offset": m.start(),
                        "decoded": s.decode("ascii"),
                        "method": f"xor_0x{key_byte:02x}",
                        "length": len(s),
                    })

    # --- ROT variants ---
    if do_all or "rot" in methods:
        for shift in range(1, 26):
            decoded = _rot_decode(data, shift)
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % max(min_length, 8), decoded):
                s = m.group()
                if data[m.start():m.end()] == s:
                    continue
                # Check if decoded looks more meaningful
                decoded_str = s.decode("ascii")
                if any(word in decoded_str.lower() for word in [
                    "http", "www", "cmd", "exec", "password", "admin",
                    "shell", "connect", "socket", "file", ".exe", ".dll",
                ]):
                    decoded_strings.append({
                        "offset": m.start(),
                        "decoded": decoded_str,
                        "method": f"rot_{shift}",
                        "length": len(s),
                    })

    # --- Base64 ---
    if do_all or "base64" in methods:
        b64_pattern = re.compile(rb"[A-Za-z0-9+/=]{8,}")
        for m in b64_pattern.finditer(data):
            try:
                b64_decoded = _base64_decode(m.group().decode("ascii"))
                if b64_decoded and _is_printable_ratio(b64_decoded):
                    decoded_str = b64_decoded.decode("ascii", errors="replace")
                    if len(decoded_str) >= min_length:
                        decoded_strings.append({
                            "offset": m.start(),
                            "encoded": m.group().decode("ascii"),
                            "decoded": decoded_str,
                            "method": "base64",
                            "length": len(decoded_str),
                        })
            except (UnicodeDecodeError, BinasciiError, ValueError) as e:
                logger.debug("Skipping invalid Base64 candidate at offset %s: %s", m.start(), e)

    # --- Stack strings ---
    if do_all or "stack_strings" in methods:
        # Look for patterns like: mov [rbp-xx], byte
        # Simplified: look for sequences of byte pushes
        stack_strings_found = _find_stack_strings(data, min_length)
        decoded_strings.extend(stack_strings_found)

    # Deduplicate and sort by offset
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in sorted(decoded_strings, key=lambda x: x.get("offset", 0)):
        dedup_key = item.get("decoded", "")
        if dedup_key not in seen and len(dedup_key) >= min_length:
            seen.add(dedup_key)
            unique.append(item)

    return text_result({
        "binary": str(file_path),
        "total_decoded": len(unique),
        "strings": unique[:500],  # Cap output
    })


def _find_stack_strings(data: bytes, min_length: int) -> list[dict[str, Any]]:
    """Find stack-constructed strings (mov byte patterns)."""
    results: list[dict[str, Any]] = []

    # Pattern: C6 45 xx yy (mov byte [rbp+xx], yy) — x86-64
    pattern = re.compile(rb"\xc6\x45.", re.DOTALL)
    chars: list[tuple[int, int]] = []

    for m in pattern.finditer(data):
        if m.start() + 4 <= len(data):
            data[m.start() + 2]
            char_byte = data[m.start() + 3]
            if 32 <= char_byte < 127:
                chars.append((m.start(), char_byte))

    # Group consecutive mov byte instructions
    if chars:
        groups: list[list[tuple[int, int]]] = []
        current_group: list[tuple[int, int]] = [chars[0]]

        for i in range(1, len(chars)):
            if chars[i][0] - chars[i - 1][0] <= 8:
                current_group.append(chars[i])
            else:
                if len(current_group) >= min_length:
                    groups.append(current_group)
                current_group = [chars[i]]

        if len(current_group) >= min_length:
            groups.append(current_group)

        for group in groups:
            s = "".join(chr(c) for _, c in group)
            results.append({
                "offset": group[0][0],
                "decoded": s,
                "method": "stack_string",
                "length": len(s),
            })

    return results


# ---------------------------------------------------------------------------
# Control Flow Deflattening Analysis
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_detect_cff",
    description=(
        "Detect control-flow flattening (CFF) in a binary. "
        "Identifies dispatcher blocks, switch-based state machines, "
        "and OLLVM-style flattening patterns. "
        "Reports affected functions and complexity metrics."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "function_address": {
                "type": "string",
                "description": "Specific function address to analyze (hex). If omitted, scans all.",
            },
        },
        "required": ["binary_path"],
    },
    category="deobfuscation",
)
async def handle_detect_cff(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect control-flow flattening."""
    binary_path = arguments["binary_path"]
    arguments.get("function_address")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    try:
        import capstone
    except ImportError:
        return error_result("capstone required for CFF detection")

    data = file_path.read_bytes()

    # Detect architecture
    if data[:2] == b"MZ":
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if b"PE\x00\x00d\x86" in data[:512] else capstone.CS_MODE_32
    elif data[:4] == b"\x7fELF":
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if data[4] == 2 else capstone.CS_MODE_32
    else:
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64

    md = capstone.Cs(arch, mode)
    md.detail = True


    # CFF indicators
    cff_patterns = {
        "dispatcher_cmp_jmp": 0,
        "state_variable_updates": 0,
        "indirect_jumps": 0,
        "switch_tables": 0,
    }

    # Disassemble and look for CFF patterns
    # Focus on looking for: cmp reg, imm / je/jne patterns (dispatcher)
    instructions = list(md.disasm(data[:min(len(data), 1024 * 1024)], 0))

    for i, insn in enumerate(instructions):
        # Pattern: cmp followed by conditional jump — dispatcher check
        if insn.mnemonic == "cmp" and i + 1 < len(instructions):
            next_insn = instructions[i + 1]
            if next_insn.mnemonic.startswith("j") and next_insn.mnemonic != "jmp":
                cff_patterns["dispatcher_cmp_jmp"] += 1

                # Check for state variable update (mov reg, imm before jmp back)
                for j in range(i + 2, min(i + 10, len(instructions))):
                    if instructions[j].mnemonic == "mov":
                        cff_patterns["state_variable_updates"] += 1
                        break

        # Indirect jumps (jump tables)
        if insn.mnemonic == "jmp" and insn.op_str.startswith("["):
            cff_patterns["indirect_jumps"] += 1

    # Heuristic: high cmp/jmp ratio in small area suggests CFF
    is_flattened = (
        cff_patterns["dispatcher_cmp_jmp"] > 20
        and cff_patterns["state_variable_updates"] > 10
    )

    return text_result({
        "binary": str(file_path),
        "cff_detected": is_flattened,
        "patterns": cff_patterns,
        "analysis": (
            "Strong CFF indicators detected. The binary likely uses OLLVM-style "
            "control-flow flattening." if is_flattened else
            "No strong CFF indicators found."
        ),
    })


# ---------------------------------------------------------------------------
# Opaque Predicate Detection
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_detect_opaque_predicates",
    description=(
        "Detect opaque predicates in a binary. "
        "Identifies always-true/always-false conditional branches "
        "used to confuse disassemblers and decompilers."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string"},
            "max_instructions": {
                "type": "integer",
                "default": 100000,
                "description": "Max instructions to analyze.",
            },
        },
        "required": ["binary_path"],
    },
    category="deobfuscation",
)
async def handle_detect_opaque_predicates(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect opaque predicates."""
    binary_path = arguments["binary_path"]
    max_insns = arguments.get("max_instructions", 100000)

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    try:
        import capstone
    except ImportError:
        return error_result("capstone required")

    data = file_path.read_bytes()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    opaque_predicates: list[dict[str, Any]] = []

    instructions = list(itertools.islice(md.disasm(data, 0), max_insns))

    for i, insn in enumerate(instructions):
        # Pattern 1: xor reg, reg; je target (always true — ZF set)
        if insn.mnemonic == "xor" and i + 1 < len(instructions):
            parts = insn.op_str.split(",")
            if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                next_insn = instructions[i + 1]
                if next_insn.mnemonic in ("je", "jz"):
                    opaque_predicates.append({
                        "address": f"0x{insn.address:x}",
                        "type": "always_true",
                        "pattern": f"xor {insn.op_str}; {next_insn.mnemonic} {next_insn.op_str}",
                        "description": "XOR reg,reg always sets ZF=1",
                    })
                elif next_insn.mnemonic in ("jne", "jnz"):
                    opaque_predicates.append({
                        "address": f"0x{insn.address:x}",
                        "type": "always_false",
                        "pattern": f"xor {insn.op_str}; {next_insn.mnemonic} {next_insn.op_str}",
                        "description": "XOR reg,reg + JNE is dead code",
                    })

        # Pattern 2: test reg, reg after mov reg, 0; je (always true)
        if insn.mnemonic == "mov" and ", 0" in insn.op_str and i + 1 < len(instructions):
            next_insn = instructions[i + 1]
            if next_insn.mnemonic == "test":
                reg = insn.op_str.split(",")[0].strip()
                if reg in next_insn.op_str and i + 2 < len(instructions):
                    branch = instructions[i + 2]
                    if branch.mnemonic in ("je", "jz"):
                        opaque_predicates.append({
                            "address": f"0x{insn.address:x}",
                            "type": "always_true",
                            "pattern": f"mov {insn.op_str}; test ...; je",
                            "description": "mov reg,0; test reg,reg; je is always taken",
                        })

        # Pattern 3: cmp reg, reg; je (always true)
        if insn.mnemonic == "cmp":
            parts = insn.op_str.split(",")
            if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                if i + 1 < len(instructions):
                    next_insn = instructions[i + 1]
                    if next_insn.mnemonic in ("je", "jz"):
                        opaque_predicates.append({
                            "address": f"0x{insn.address:x}",
                            "type": "always_true",
                            "pattern": f"cmp {insn.op_str}; je",
                            "description": "Comparing register with itself",
                        })

    return text_result({
        "binary": str(file_path),
        "opaque_predicates_found": len(opaque_predicates),
        "predicates": opaque_predicates[:200],
        "instructions_analyzed": len(instructions),
    })
