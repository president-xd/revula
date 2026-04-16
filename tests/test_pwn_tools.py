"""
Revula Test Suite — pwntools integration tests.

Covers the five tools registered by revula.tools.exploit.pwn_tools:
    re_exploit_cyclic, re_exploit_asm, re_exploit_disasm,
    re_exploit_shellcraft, re_exploit_elf_info.

Every test skips cleanly if pwnlib is not installed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

pwnlib = pytest.importorskip("pwnlib", reason="pwntools not installed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def real_elf(tmp_path: Path) -> Path:
    """Copy a real system ELF into tmp_path so the sandbox accepts it."""
    for candidate in ("/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/cat"):
        src = Path(candidate)
        if src.is_file():
            dest = tmp_path / "sample.elf"
            shutil.copy(src, dest)
            return dest
    pytest.skip("No system ELF available for fixture")


# ---------------------------------------------------------------------------
# re_exploit_cyclic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cyclic_generate_default_n():
    from revula.tools.exploit.pwn_tools import handle_cyclic

    result = await handle_cyclic({"action": "generate", "length": 64, "arch": "amd64"})
    assert len(result) == 1
    data = json.loads(result[0]["text"])
    assert data["length"] == 64
    assert data["n"] == 8  # amd64 default
    pattern = bytes.fromhex(data["pattern_hex"])
    assert len(pattern) == 64


@pytest.mark.asyncio
async def test_cyclic_generate_i386_n_is_4():
    from revula.tools.exploit.pwn_tools import handle_cyclic

    result = await handle_cyclic({"action": "generate", "length": 40, "arch": "i386"})
    data = json.loads(result[0]["text"])
    assert data["n"] == 4


@pytest.mark.asyncio
async def test_cyclic_lookup_roundtrip_hex():
    from revula.tools.exploit.pwn_tools import handle_cyclic

    gen = await handle_cyclic({"action": "generate", "length": 256, "arch": "amd64"})
    pattern = bytes.fromhex(json.loads(gen[0]["text"])["pattern_hex"])
    needle = pattern[40:48]  # 8-byte window at offset 40

    lookup = await handle_cyclic(
        {"action": "lookup", "lookup": needle.hex(), "arch": "amd64"}
    )
    data = json.loads(lookup[0]["text"])
    assert data["offset"] == 40


@pytest.mark.asyncio
async def test_cyclic_lookup_roundtrip_ascii():
    from revula.tools.exploit.pwn_tools import handle_cyclic

    # Use a needle with a non-hex char ('g') so the heuristic in
    # _decode_lookup doesn't interpret it as hex.
    from pwnlib.util import cyclic as pwn_cyclic

    needle = "ghij"
    expected_offset = pwn_cyclic.cyclic_find(needle.encode(), n=4)

    lookup = await handle_cyclic(
        {"action": "lookup", "lookup": needle, "arch": "i386"}
    )
    data = json.loads(lookup[0]["text"])
    assert data["offset"] == expected_offset


@pytest.mark.asyncio
async def test_cyclic_lookup_missing_needle():
    from revula.tools.exploit.pwn_tools import handle_cyclic

    # ZZZZ will not appear in a cyclic pattern over the lowercase alphabet.
    result = await handle_cyclic(
        {"action": "lookup", "lookup": "ZZZZ", "arch": "i386"}
    )
    data = json.loads(result[0]["text"])
    assert data.get("error") or data.get("code") == "cyclic_not_found"


@pytest.mark.asyncio
async def test_cyclic_generate_requires_length():
    from revula.tools.exploit.pwn_tools import handle_cyclic

    result = await handle_cyclic({"action": "generate", "arch": "amd64"})
    assert "error" in json.loads(result[0]["text"])


# ---------------------------------------------------------------------------
# re_exploit_asm / re_exploit_disasm
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_asm_amd64_xor_ret():
    from revula.tools.exploit.pwn_tools import handle_asm

    result = await handle_asm({"source": "xor eax, eax\nret", "arch": "amd64"})
    data = json.loads(result[0]["text"])
    if "error" in data:
        pytest.skip(f"amd64 assembler unavailable: {data.get('message')}")
    assert data["hex"].startswith("31c0")  # xor eax, eax
    assert data["hex"].endswith("c3")       # ret
    assert data["length"] == len(bytes.fromhex(data["hex"]))


@pytest.mark.asyncio
async def test_disasm_amd64_xor_ret():
    from revula.tools.exploit.pwn_tools import handle_disasm

    result = await handle_disasm(
        {"hex_bytes": "4831c0c3", "arch": "amd64", "address": "0x400000"}
    )
    data = json.loads(result[0]["text"])
    if "error" in data:
        pytest.skip(f"amd64 disassembler unavailable: {data.get('message')}")
    listing = data["listing"].lower()
    assert "xor" in listing
    assert "ret" in listing
    assert data["byte_count"] == 4


@pytest.mark.asyncio
async def test_disasm_tolerates_escaped_hex():
    from revula.tools.exploit.pwn_tools import handle_disasm

    result = await handle_disasm(
        {"hex_bytes": "\\x48\\x31\\xc0\\xc3", "arch": "amd64"}
    )
    data = json.loads(result[0]["text"])
    if "error" in data:
        pytest.skip(f"amd64 disassembler unavailable: {data.get('message')}")
    assert data["byte_count"] == 4


@pytest.mark.asyncio
async def test_asm_rejects_oversize_source():
    from revula.tools.exploit.pwn_tools import handle_asm

    result = await handle_asm({"source": "nop\n" * 20000, "arch": "amd64"})
    data = json.loads(result[0]["text"])
    assert "error" in data


@pytest.mark.asyncio
async def test_disasm_rejects_invalid_hex():
    from revula.tools.exploit.pwn_tools import handle_disasm

    result = await handle_disasm({"hex_bytes": "zzzz", "arch": "amd64"})
    data = json.loads(result[0]["text"])
    assert "error" in data


# ---------------------------------------------------------------------------
# re_exploit_shellcraft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shellcraft_dotted_path_amd64_sh():
    from revula.tools.exploit.pwn_tools import handle_shellcraft

    result = await handle_shellcraft(
        {"template": "amd64.linux.sh", "assemble": False}
    )
    data = json.loads(result[0]["text"])
    if "error" in data:
        pytest.skip(f"shellcraft unavailable: {data.get('message')}")
    assert data["arch"] == "amd64"
    assert data["os"] == "linux"
    assert "source" in data and len(data["source"]) > 0


@pytest.mark.asyncio
async def test_shellcraft_short_name_requires_arch():
    from revula.tools.exploit.pwn_tools import handle_shellcraft

    result = await handle_shellcraft({"template": "sh", "assemble": False})
    data = json.loads(result[0]["text"])
    assert "error" in data


@pytest.mark.asyncio
async def test_shellcraft_unknown_template():
    from revula.tools.exploit.pwn_tools import handle_shellcraft

    result = await handle_shellcraft(
        {"template": "amd64.linux.totally_not_real", "assemble": False}
    )
    data = json.loads(result[0]["text"])
    assert "error" in data


# ---------------------------------------------------------------------------
# re_exploit_elf_info
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_elf_info_basics(real_elf: Path):
    from revula.tools.exploit.pwn_tools import handle_elf_info

    result = await handle_elf_info({"binary_path": str(real_elf)})
    data = json.loads(result[0]["text"])
    if "error" in data:
        pytest.skip(f"pwnlib ELF load failed: {data.get('message')}")
    assert data["arch"] in {
        "i386", "amd64", "arm", "aarch64", "mips", "mips64",
        "powerpc", "powerpc64", "sparc", "sparc64", "riscv32", "riscv64",
    }
    assert data["bits"] in {32, 64}
    assert "mitigations" in data
    mit = data["mitigations"]
    for key in ("nx", "pie", "relro", "canary", "fortify"):
        assert key in mit


@pytest.mark.asyncio
async def test_elf_info_symbols_capped(real_elf: Path):
    from revula.tools.exploit.pwn_tools import handle_elf_info

    result = await handle_elf_info(
        {
            "binary_path": str(real_elf),
            "include_symbols": True,
            "symbol_limit": 5,
        }
    )
    data = json.loads(result[0]["text"])
    if "error" in data:
        pytest.skip(f"pwnlib ELF load failed: {data.get('message')}")
    # Not every stripped binary has symbols — only assert when present.
    if "symbols" in data:
        assert data["symbol_count_returned"] <= 5
        assert len(data["symbols"]) <= 5


@pytest.mark.asyncio
async def test_elf_info_rejects_missing_path(tmp_path: Path):
    from revula.tools.exploit.pwn_tools import handle_elf_info

    result = await handle_elf_info(
        {"binary_path": str(tmp_path / "does_not_exist.elf")}
    )
    data = json.loads(result[0]["text"])
    assert "error" in data


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_pwn_tools_register_into_registry():
    """Importing the module must register all five tools under 'exploit'."""
    import revula.tools.exploit.pwn_tools  # noqa: F401 — triggers registration
    from revula.tools import TOOL_REGISTRY

    registered = set(TOOL_REGISTRY.names())
    for name in (
        "re_exploit_cyclic",
        "re_exploit_asm",
        "re_exploit_disasm",
        "re_exploit_shellcraft",
        "re_exploit_elf_info",
    ):
        assert name in registered, f"{name} missing from TOOL_REGISTRY"
