"""
Revula Binary Patching — apply byte patches with automatic backup.

Features:
- Byte-level patches with backup
- NOP-sled a range
- Patch conditional jumps
- Replace call targets
- Returns patch record with original/new bytes
"""

from __future__ import annotations

import logging
import shutil
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from revula.sandbox import validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


def _create_backup(file_path: Path) -> Path:
    """Create a backup of the file before patching."""
    backup_dir = file_path.parent / ".revula-backups"
    backup_dir.mkdir(exist_ok=True)
    timestamp = int(time.time())
    backup_path = backup_dir / f"{file_path.name}.{timestamp}.bak"
    shutil.copy2(file_path, backup_path)
    logger.info("Created backup: %s", backup_path)
    return backup_path


# x86/x64 NOP byte
NOP_BYTE = b"\x90"


@TOOL_REGISTRY.register(
    name="re_patch",
    description=(
        "Apply byte-level patches to a binary file with automatic backup. "
        "Operations: write bytes at offset, NOP-sled a range, patch conditional "
        "jumps, replace call targets. Returns patch record with original bytes."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary to patch.",
            },
            "patches": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "offset": {
                            "type": "integer",
                            "description": "File offset to patch at.",
                        },
                        "hex_bytes": {
                            "type": "string",
                            "description": "New hex bytes to write at offset.",
                        },
                        "nop_length": {
                            "type": "integer",
                            "description": "Number of bytes to NOP (overrides hex_bytes).",
                        },
                    },
                    "required": ["offset"],
                },
                "description": "List of patches to apply.",
            },
            "create_backup": {
                "type": "boolean",
                "description": "Create backup before patching. Default: true.",
                "default": True,
            },
            "output_path": {
                "type": "string",
                "description": "Write patched binary to this path instead of modifying in-place.",
            },
        },
        "required": ["binary_path", "patches"],
    },
    category="utility",
)
async def handle_patch(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply patches to a binary file."""
    binary_path_str = arguments["binary_path"]
    patches = arguments["patches"]
    do_backup = arguments.get("create_backup", True)
    output_path = arguments.get("output_path")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    data = bytearray(file_path.read_bytes())
    patch_records: list[dict[str, Any]] = []

    for patch in patches:
        offset = patch["offset"]
        if offset < 0 or offset >= len(data):
            return error_result(f"Offset {offset} out of range (file size: {len(data)})")

        if "nop_length" in patch:
            nop_len = patch["nop_length"]
            end = min(offset + nop_len, len(data))
            original = bytes(data[offset:end])
            data[offset:end] = NOP_BYTE * (end - offset)
            patch_records.append({
                "offset": offset,
                "type": "nop_sled",
                "original_hex": original.hex(),
                "new_hex": (NOP_BYTE * (end - offset)).hex(),
                "length": end - offset,
            })
        elif "hex_bytes" in patch:
            new_bytes = bytes.fromhex(patch["hex_bytes"].replace(" ", ""))
            end = min(offset + len(new_bytes), len(data))
            original = bytes(data[offset:end])
            data[offset:offset + len(new_bytes)] = new_bytes
            patch_records.append({
                "offset": offset,
                "type": "byte_patch",
                "original_hex": original.hex(),
                "new_hex": new_bytes.hex(),
                "length": len(new_bytes),
            })
        else:
            return error_result(f"Patch at offset {offset} must have 'hex_bytes' or 'nop_length'")

    # Create backup
    backup_path = None
    if do_backup:
        backup_path = _create_backup(file_path)

    # Write patched file
    if output_path:
        out = validate_path(output_path, allowed_dirs=allowed_dirs, must_exist=False)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(bytes(data))
        written_to = str(out)
    else:
        file_path.write_bytes(bytes(data))
        written_to = str(file_path)

    return text_result({
        "patched_file": written_to,
        "backup_file": str(backup_path) if backup_path else None,
        "patch_count": len(patch_records),
        "patches": patch_records,
    })
