"""
Revula Test Suite — Tool module tests (pure Python logic, no external tools).

Tests: constants, tool registration, pure helper functions from various modules.
"""

from __future__ import annotations

from typing import Any

from revula.server import _register_all_tools
from revula.tools import TOOL_REGISTRY

_register_all_tools()


# ---------------------------------------------------------------------------
# Anti-analysis module tests
# ---------------------------------------------------------------------------


class TestAntiAnalysisConstants:
    """Verify anti-analysis pattern dictionaries are populated."""

    def test_anti_debug_apis_non_empty(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _ANTI_DEBUG_APIS

        assert isinstance(_ANTI_DEBUG_APIS, dict)
        assert len(_ANTI_DEBUG_APIS) > 0

    def test_anti_debug_apis_have_required_keys(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _ANTI_DEBUG_APIS

        for api, info in _ANTI_DEBUG_APIS.items():
            assert "os" in info, f"{api} missing 'os'"
            assert "category" in info, f"{api} missing 'category'"
            assert "severity" in info, f"{api} missing 'severity'"

    def test_vm_signatures_non_empty(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _VM_SIGNATURES

        assert isinstance(_VM_SIGNATURES, dict)
        assert len(_VM_SIGNATURES) > 0

    def test_tamper_patterns_non_empty(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _TAMPER_PATTERNS

        assert isinstance(_TAMPER_PATTERNS, list)
        assert len(_TAMPER_PATTERNS) > 0
        for pat in _TAMPER_PATTERNS:
            assert "pattern" in pat
            assert "category" in pat

    def test_calc_risk_no_findings(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _calc_risk

        assert _calc_risk([]) == "none"

    def test_calc_risk_low(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _calc_risk

        findings: list[dict[str, Any]] = [{"severity": "low"}]
        assert _calc_risk(findings) == "low"

    def test_calc_risk_medium(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _calc_risk

        findings: list[dict[str, Any]] = [{"severity": "medium"}]
        assert _calc_risk(findings) == "medium"

    def test_calc_risk_high_from_multiple_medium(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _calc_risk

        findings: list[dict[str, Any]] = [
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "medium"},
        ]
        assert _calc_risk(findings) == "high"

    def test_calc_risk_critical(self) -> None:
        from revula.tools.antianalysis.detect_bypass import _calc_risk

        findings: list[dict[str, Any]] = [
            {"severity": "high"},
            {"severity": "high"},
        ]
        assert _calc_risk(findings) == "critical"


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestToolRegistration:
    """Verify tools are registered in TOOL_REGISTRY after import."""

    def test_antianalysis_detect_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_antianalysis_detect") is not None

    def test_antianalysis_bypass_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_antianalysis_bypass") is not None

    def test_shellcode_tool_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_shellcode_generate") is not None

    def test_fmtstr_tool_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_exploit_fmtstr") is not None

    def test_malware_triage_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_malware_triage") is not None

    def test_malware_sandbox_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_malware_sandbox") is not None

    def test_malware_yara_gen_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_malware_yara_gen") is not None

    def test_firmware_extract_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_firmware_extract") is not None

    def test_firmware_vuln_scan_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_firmware_vuln_scan") is not None

    def test_protocol_pcap_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_protocol_pcap") is not None

    def test_protocol_dissect_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_protocol_dissect") is not None

    def test_protocol_fuzz_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_protocol_fuzz") is not None

    def test_admin_status_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_admin_status") is not None

    def test_tool_definitions_have_handler(self) -> None:
        for name in TOOL_REGISTRY.names():
            defn = TOOL_REGISTRY.get(name)
            assert defn is not None
            assert callable(defn.handler), f"{name} handler not callable"


# ---------------------------------------------------------------------------
# Malware triage pure helpers
# ---------------------------------------------------------------------------


class TestMalwareTriageHelpers:
    """Test pure helper functions from malware.triage."""

    def test_extract_iocs_urls(self) -> None:
        from revula.tools.malware.triage import _extract_iocs

        data = b"GET http://evil.example.com/malware HTTP/1.1\r\n"
        iocs = _extract_iocs(data)
        assert "urls" in iocs
        assert any("evil.example.com" in u for u in iocs["urls"])

    def test_extract_iocs_ips(self) -> None:
        from revula.tools.malware.triage import _extract_iocs

        data = b"connect to 203.0.113.42 on port 443"
        iocs = _extract_iocs(data)
        assert "ips" in iocs
        assert "203.0.113.42" in iocs["ips"]

    def test_extract_iocs_filters_loopback(self) -> None:
        from revula.tools.malware.triage import _extract_iocs

        data = b"connect to 127.0.0.1 and 192.168.1.1"
        iocs = _extract_iocs(data)
        ips = iocs.get("ips", [])
        assert "127.0.0.1" not in ips

    def test_check_suspicious_imports(self) -> None:
        from revula.tools.malware.triage import _check_suspicious_imports

        text = "0000 VirtualAlloc\n0004 CreateRemoteThread\n0008 printf"
        result = _check_suspicious_imports(text)
        names = [r["api"] for r in result]
        assert "VirtualAlloc" in names
        assert "CreateRemoteThread" in names

    def test_check_suspicious_strings(self) -> None:
        from revula.tools.malware.triage import _check_suspicious_strings

        text = "cmd.exe /c whoami\npowershell -enc AAAA"
        result = _check_suspicious_strings(text)
        assert len(result) > 0

    def test_calculate_risk_score_zero(self) -> None:
        from revula.tools.malware.triage import _calculate_risk_score

        score = _calculate_risk_score([], [], {})
        assert score == 0

    def test_calculate_risk_score_with_imports(self) -> None:
        from revula.tools.malware.triage import _calculate_risk_score

        imports: list[dict[str, str]] = [
            {"api": "CreateRemoteThread", "category": "process_injection"},
        ]
        score = _calculate_risk_score(imports, [], {})
        assert score >= 15

    def test_calculate_risk_score_capped_at_100(self) -> None:
        from revula.tools.malware.triage import _calculate_risk_score

        imports: list[dict[str, str]] = [
            {"api": f"api{i}", "category": "process_injection"} for i in range(20)
        ]
        strings = ["cmd.exe"] * 50
        iocs: dict[str, list[str]] = {
            "urls": ["http://x.com"],
            "ips": ["1.2.3.4"],
            "bitcoin": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        }
        score = _calculate_risk_score(imports, strings, iocs)
        assert score == 100


# ---------------------------------------------------------------------------
# Protocol dissection pure helpers
# ---------------------------------------------------------------------------


class TestProtocolHelpers:
    """Test pure protocol analysis helpers."""

    def test_analyze_packet(self) -> None:
        from revula.tools.protocol.protocol import _analyze_packet

        data = b"\x00\x0a" + b"hello" + b"\x00" * 3
        result = _analyze_packet(data)
        assert result["length"] == 10
        assert "first_2_bytes" in result

    def test_find_length_fields(self) -> None:
        from revula.tools.protocol.protocol import _find_length_fields

        # Build a packet where byte at offset 0 = total length
        pkt = bytes([10]) + b"\x00" * 9  # length 10, first byte = 10
        candidates = _find_length_fields(pkt)
        assert len(candidates) > 0

    def test_detect_structure_string(self) -> None:
        from revula.tools.protocol.protocol import _detect_structure

        data = b"HELLO\x00\x00\xff"
        fields = _detect_structure(data)
        assert any(f["type"] == "string" for f in fields)

    def test_compare_packets(self) -> None:
        from revula.tools.protocol.protocol import _compare_packets

        p1 = b"\x01\x02\x03\x04"
        p2 = b"\x01\x02\xFF\x04"
        result = _compare_packets([p1, p2])
        assert result["packet_count"] == 2
        assert 2 in result["variable_byte_positions"]
        assert 0 in result["static_byte_positions"]

    def test_boundary_values_1byte(self) -> None:
        from revula.tools.protocol.protocol import _boundary_values

        vals = _boundary_values(1)
        assert len(vals) > 0
        hex_vals = [v["value"] for v in vals]
        assert "0x00" in hex_vals
        assert "0xff" in hex_vals

    def test_boundary_values_2byte(self) -> None:
        from revula.tools.protocol.protocol import _boundary_values

        vals = _boundary_values(2)
        assert len(vals) > 0
        hex_vals = [v["value"] for v in vals]
        assert "0x0000" in hex_vals
        assert "0xffff" in hex_vals


# ---------------------------------------------------------------------------
# Firmware helpers
# ---------------------------------------------------------------------------


class TestFirmwareHelpers:
    """Test pure firmware analysis helpers."""

    def test_parse_binwalk_typical(self) -> None:
        from revula.tools.firmware.firmware import _parse_binwalk

        output = (
            "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            "---\n"
            "0             0x0             U-Boot image header\n"
            "64            0x40            LZMA compressed data\n"
        )
        components = _parse_binwalk(output)
        assert len(components) == 2
        assert components[0]["description"] == "U-Boot image header"

    def test_detect_firmware_signatures_uboot(self) -> None:
        from revula.tools.firmware.firmware import _detect_firmware_signatures

        data = b"\x00" * 10 + b"\x27\x05\x19\x56" + b"\x00" * 10
        sigs = _detect_firmware_signatures(data)
        assert any("U-Boot" in s for s in sigs)

    def test_detect_firmware_signatures_squashfs(self) -> None:
        from revula.tools.firmware.firmware import _detect_firmware_signatures

        data = b"hsqs" + b"\x00" * 100
        sigs = _detect_firmware_signatures(data)
        assert any("SquashFS" in s for s in sigs)

    def test_check_unsafe_functions(self) -> None:
        from revula.tools.firmware.firmware import _check_unsafe_functions

        text = "strcpy sprintf gets safe_func"
        result = _check_unsafe_functions(text)
        names = [r["function"] for r in result]
        assert "strcpy" in names
        assert "gets" in names

    def test_detect_services(self) -> None:
        from revula.tools.firmware.firmware import _detect_services

        text = "telnetd sshd httpd"
        result = _detect_services(text)
        svc_names = [s["service"] for s in result]
        assert "telnetd" in svc_names
        assert "sshd" in svc_names


# ---------------------------------------------------------------------------
# Shellcode helpers
# ---------------------------------------------------------------------------


class TestShellcodeHelpers:
    """Test pure helpers from shellcode module."""

    def test_msf_arch_mapping(self) -> None:
        from revula.tools.exploit.shellcode import _msf_arch

        assert _msf_arch("x86") == "x86"
        assert _msf_arch("x64") == "x64"
        assert _msf_arch("arm") == "armle"
        assert _msf_arch("aarch64") == "aarch64"
        assert _msf_arch("unknown") == "unknown"


# ---------------------------------------------------------------------------
# Format string helpers
# ---------------------------------------------------------------------------


class TestFormatStringHelpers:
    """Test format string write-what-where helper."""

    def test_fmtstr_write_returns_dict(self) -> None:
        from revula.tools.exploit.format_string import _fmtstr_write

        result = _fmtstr_write(addr=0x601020, value=0x4141, offset=6, is_64bit=True)
        assert "hex" in result
        assert "python" in result
        assert "technique" in result

    def test_fmtstr_write_uses_hhn(self) -> None:
        from revula.tools.exploit.format_string import _fmtstr_write

        result = _fmtstr_write(addr=0x601020, value=0x42, offset=6, is_64bit=True)
        assert "hhn" in result["technique"]

    def test_fmtstr_write_32bit(self) -> None:
        from revula.tools.exploit.format_string import _fmtstr_write

        result = _fmtstr_write(addr=0x804A000, value=0xDEAD, offset=4, is_64bit=False)
        assert "hex" in result
        # 32-bit packing should produce 4-byte addresses
        assert len(result["hex"]) > 0


# ---------------------------------------------------------------------------
# Utils module tests
# ---------------------------------------------------------------------------


class TestCryptoUtils:
    """Test crypto utility helpers."""

    def test_crypto_constants_populated(self) -> None:
        from revula.tools.utils.crypto import CRYPTO_CONSTANTS

        assert len(CRYPTO_CONSTANTS) > 0
        for name, pattern, algo in CRYPTO_CONSTANTS:
            assert isinstance(name, str)
            assert isinstance(pattern, bytes)
            assert isinstance(algo, str)

    def test_scan_crypto_constants_aes_sbox(self) -> None:
        from revula.tools.utils.crypto import scan_crypto_constants

        # Include AES S-box start bytes
        data = b"\x00" * 100 + bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                                       0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])
        result = scan_crypto_constants(data)
        assert any("AES" in r["algorithm"] for r in result)

    def test_scan_crypto_constants_salsa(self) -> None:
        from revula.tools.utils.crypto import scan_crypto_constants

        data = b"expand 32-byte k" + b"\x00" * 50
        result = scan_crypto_constants(data)
        assert any("Salsa" in r["algorithm"] or "ChaCha" in r["algorithm"] for r in result)


class TestHexUtils:
    """Test hex utility helpers."""

    def test_hexdump_basic(self) -> None:
        from revula.tools.utils.hex import hexdump

        data = b"Hello, World!"
        output = hexdump(data)
        assert "48 65 6c 6c 6f" in output  # "Hello"
        assert "|Hello" in output

    def test_hexdump_with_offset(self) -> None:
        from revula.tools.utils.hex import hexdump

        data = b"AAAA" + b"Hello"
        output = hexdump(data, offset=4)
        assert "Hello" in output
        assert "AAAA" not in output

    def test_pattern_to_regex_basic(self) -> None:
        from revula.tools.utils.hex import pattern_to_regex

        regex = pattern_to_regex("55 8B EC")
        assert regex is not None

    def test_pattern_to_regex_wildcard(self) -> None:
        from revula.tools.utils.hex import pattern_to_regex

        regex = pattern_to_regex("55 ?? EC")
        # Should create a regex with wildcard
        assert regex is not None

    def test_search_pattern_finds_match(self) -> None:
        from revula.tools.utils.hex import search_pattern

        data = b"\x00\x00\x55\x8B\xEC\x00\x00"
        results = search_pattern(data, "55 8B EC")
        assert len(results) > 0
        assert results[0]["offset"] == 2

    def test_search_pattern_wildcard_match(self) -> None:
        from revula.tools.utils.hex import search_pattern

        data = b"\x00\x55\xAA\xEC\x00"
        results = search_pattern(data, "55 ?? EC")
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Deobfuscation module tests
# ---------------------------------------------------------------------------


class TestDeobfuscationHelpers:
    """Test deobfuscation helper functions."""

    def test_xor_decode_single_byte(self) -> None:
        from revula.tools.deobfuscation.deobfuscate import _xor_decode

        data = bytes([0x41 ^ 0x55, 0x42 ^ 0x55])  # XOR "AB" with 0x55
        result = _xor_decode(data, bytes([0x55]))
        assert result == b"AB"

    def test_xor_decode_multi_byte(self) -> None:
        from revula.tools.deobfuscation.deobfuscate import _xor_decode

        key = b"KEY"
        plaintext = b"HELLO!"
        encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))
        result = _xor_decode(encoded, key)
        assert result == plaintext

    def test_rot_decode_basic(self) -> None:
        from revula.tools.deobfuscation.deobfuscate import _rot_decode

        # ROT13
        data = b"URYYB"  # "HELLO" with ROT13
        result = _rot_decode(data, 13)
        assert result == b"HELLO"

    def test_rc4_decrypt_roundtrip(self) -> None:
        from revula.tools.deobfuscation.deobfuscate import _rc4_decrypt

        key = b"secret"
        plaintext = b"Hello, World!"
        # RC4 is symmetric, so encrypt = decrypt
        encrypted = _rc4_decrypt(plaintext, key)
        decrypted = _rc4_decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_is_printable_ratio(self) -> None:
        from revula.tools.deobfuscation.deobfuscate import _is_printable_ratio

        printable_data = b"Hello World"
        assert _is_printable_ratio(printable_data)

        binary_data = bytes(range(256))
        assert not _is_printable_ratio(binary_data)

    def test_base64_decode(self) -> None:
        from revula.tools.deobfuscation.deobfuscate import _base64_decode

        result = _base64_decode("SGVsbG8gV29ybGQ=")
        assert result == b"Hello World"


# ---------------------------------------------------------------------------
# Unpacking module tests
# ---------------------------------------------------------------------------


class TestUnpackingHelpers:
    """Test unpacking helper functions."""

    def test_packer_signatures_populated(self) -> None:
        from revula.tools.unpacking.unpack import PACKER_SIGNATURES

        assert len(PACKER_SIGNATURES) > 0
        for sig in PACKER_SIGNATURES:
            assert "name" in sig
            assert "signatures" in sig
            assert "confidence" in sig

    def test_compute_entropy_zeros(self) -> None:
        from revula.tools.unpacking.unpack import _compute_entropy

        data = bytes(256)  # All zeros
        entropy = _compute_entropy(data)
        assert entropy == 0.0

    def test_compute_entropy_random(self) -> None:
        from revula.tools.unpacking.unpack import _compute_entropy

        # High entropy data (all different bytes)
        data = bytes(range(256))
        entropy = _compute_entropy(data)
        assert entropy > 7.0  # Should be close to 8 (max)

    def test_compute_entropy_text(self) -> None:
        from revula.tools.unpacking.unpack import _compute_entropy

        data = b"The quick brown fox jumps over the lazy dog"
        entropy = _compute_entropy(data)
        assert 3.0 < entropy < 5.0  # English text entropy range


# ---------------------------------------------------------------------------
# Binary formats module tests
# ---------------------------------------------------------------------------


class TestBinaryFormatsRegistration:
    """Test binary format tools registration."""

    def test_parse_binary_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_parse_binary") is not None

    def test_dotnet_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_dotnet_analyze") is not None

    def test_java_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_java_analyze") is not None

    def test_wasm_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_wasm_analyze") is not None


# ---------------------------------------------------------------------------
# Symbolic execution module tests
# ---------------------------------------------------------------------------


class TestSymbolicRegistration:
    """Test symbolic execution tools registration."""

    def test_angr_explore_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_angr_explore") is not None

    def test_angr_cfg_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_angr_cfg") is not None

    def test_angr_vuln_scan_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_angr_vuln_scan") is not None

    def test_triton_dse_registered(self) -> None:
        try:
            from triton import ARCH, TritonContext  # noqa: F401
        except Exception:
            assert TOOL_REGISTRY.get("re_triton_dse") is None
        else:
            assert TOOL_REGISTRY.get("re_triton_dse") is not None


# ---------------------------------------------------------------------------
# Dynamic tools registration tests
# ---------------------------------------------------------------------------


class TestDynamicToolsRegistration:
    """Test dynamic analysis tools registration."""

    def test_debugger_launch_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_debugger_launch") is not None

    def test_debugger_attach_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_debugger_attach") is not None

    def test_bp_set_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_bp_set") is not None

    def test_bp_list_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_bp_list") is not None

    def test_bp_delete_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_bp_delete") is not None

    def test_step_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_step") is not None

    def test_stepi_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_stepi") is not None

    def test_continue_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_continue") is not None

    def test_registers_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_registers") is not None

    def test_backtrace_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_backtrace") is not None

    def test_memory_read_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_memory_read") is not None

    def test_memory_write_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_memory_write") is not None

    def test_coverage_collect_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_coverage_collect") is not None

    def test_coverage_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_coverage_analyze") is not None

    def test_frida_spawn_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_frida_spawn") is not None

    def test_frida_attach_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_frida_attach") is not None

    def test_frida_script_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_frida_script") is not None

    def test_frida_intercept_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_frida_intercept") is not None

    def test_frida_memory_scan_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_frida_memory_scan") is not None


# ---------------------------------------------------------------------------
# Static tools registration tests
# ---------------------------------------------------------------------------


class TestStaticToolsRegistration:
    """Test static analysis tools registration."""

    def test_disassemble_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_disassemble") is not None

    def test_decompile_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_decompile") is not None

    def test_symbols_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_symbols") is not None

    def test_extract_strings_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_extract_strings") is not None

    def test_yara_scan_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_yara_scan") is not None

    def test_capa_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_capa") is not None

    def test_entropy_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_entropy") is not None


# ---------------------------------------------------------------------------
# Platform tools registration tests
# ---------------------------------------------------------------------------


class TestPlatformToolsRegistration:
    """Test platform-specific tools registration."""

    def test_rizin_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_rizin_analyze") is not None

    def test_rizin_diff_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_rizin_diff") is not None

    def test_gdb_heap_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_gdb_heap") is not None

    def test_gdb_rop_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_gdb_rop") is not None

    def test_qemu_run_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_qemu_run") is not None

    def test_qemu_system_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_qemu_system") is not None


# ---------------------------------------------------------------------------
# Android tools registration tests
# ---------------------------------------------------------------------------


class TestAndroidToolsRegistration:
    """Test Android tools registration."""

    def test_apk_parse_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_apk_parse") is not None

    def test_dex_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_dex_analyze") is not None

    def test_android_decompile_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_decompile") is not None

    def test_android_device_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_device") is not None

    def test_smali_disasm_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_smali_disasm") is not None

    def test_smali_assemble_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_smali_assemble") is not None

    def test_android_repack_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_repack") is not None

    def test_android_frida_attach_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_frida_attach") is not None

    def test_android_hook_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_hook") is not None

    def test_android_traffic_intercept_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_traffic_intercept") is not None


# ---------------------------------------------------------------------------
# Utils tools registration tests
# ---------------------------------------------------------------------------


class TestUtilsToolsRegistration:
    """Test utility tools registration."""

    def test_hash_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_hash") is not None

    def test_xor_analysis_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_xor_analysis") is not None

    def test_crypto_constants_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_crypto_constants") is not None

    def test_hexdump_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_hexdump") is not None

    def test_pattern_search_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_pattern_search") is not None

    def test_patch_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_patch") is not None

    def test_pcap_analyze_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_pcap_analyze") is not None


# ---------------------------------------------------------------------------
# Unpacking tools registration tests
# ---------------------------------------------------------------------------


class TestUnpackingToolsRegistration:
    """Test unpacking tools registration."""

    def test_detect_packer_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_detect_packer") is not None

    def test_unpack_upx_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_unpack_upx") is not None

    def test_dynamic_unpack_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_dynamic_unpack") is not None

    def test_pe_rebuild_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_pe_rebuild") is not None


# ---------------------------------------------------------------------------
# Deobfuscation tools registration tests
# ---------------------------------------------------------------------------


class TestDeobfuscationToolsRegistration:
    """Test deobfuscation tools registration."""

    def test_deobfuscate_strings_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_deobfuscate_strings") is not None

    def test_detect_cff_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_detect_cff") is not None

    def test_detect_opaque_predicates_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_detect_opaque_predicates") is not None


# ---------------------------------------------------------------------------
# Tool definition quality tests
# ---------------------------------------------------------------------------


class TestToolDefinitionQuality:
    """Test that all tool definitions are well-formed."""

    def test_all_tools_have_description(self) -> None:
        for name in TOOL_REGISTRY.names():
            defn = TOOL_REGISTRY.get(name)
            assert defn is not None
            assert defn.description, f"{name} has no description"
            assert len(defn.description) > 10, f"{name} description too short"

    def test_all_tools_have_input_schema(self) -> None:
        for name in TOOL_REGISTRY.names():
            defn = TOOL_REGISTRY.get(name)
            assert defn is not None
            assert isinstance(defn.input_schema, dict), f"{name} missing input_schema"
            assert "type" in defn.input_schema, f"{name} input_schema missing type"

    def test_all_tools_have_category(self) -> None:
        for name in TOOL_REGISTRY.names():
            defn = TOOL_REGISTRY.get(name)
            assert defn is not None
            assert defn.category, f"{name} has no category"

    def test_tool_names_follow_convention(self) -> None:
        for name in TOOL_REGISTRY.names():
            assert name.startswith("re_"), f"{name} doesn't follow re_ prefix convention"
            assert name == name.lower(), f"{name} should be lowercase"

    def test_tool_count_is_expected(self) -> None:
        count = TOOL_REGISTRY.count()
        assert count >= 100, f"Expected at least 100 tools, got {count}"
        assert count <= 150, f"Unexpected tool count: {count}"


# ---------------------------------------------------------------------------
# Admin tools tests
# ---------------------------------------------------------------------------


class TestAdminTools:
    """Test admin tools."""

    def test_admin_status_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_admin_status") is not None

    def test_admin_cache_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_admin_cache") is not None
