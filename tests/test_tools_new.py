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
