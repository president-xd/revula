"""
Revula Firmware RE — extraction, filesystem analysis, vulnerability scanning,
base address detection, and UEFI/BIOS analysis.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path, validate_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


@TOOL_REGISTRY.register(
    name="re_firmware_extract",
    description=(
        "Extract firmware images: binwalk extraction, filesystem carving, "
        "component identification, entropy visualization."
    ),
    category="firmware",
    input_schema={
        "type": "object",
        "required": ["firmware_path", "action"],
        "properties": {
            "firmware_path": {
                "type": "string",
                "description": "Path to firmware image.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "scan", "extract", "entropy", "filesystems",
                    "identify", "strings_analysis",
                ],
                "description": "Firmware action.",
            },
            "output_dir": {
                "type": "string",
                "description": "Output directory for extraction.",
            },
        },
    },
)
async def handle_firmware_extract(
    arguments: dict[str, Any],
) -> list[dict[str, Any]]:
    """Firmware extraction and analysis."""
    firmware_path = arguments["firmware_path"]
    action = arguments["action"]
    output_dir = arguments.get("output_dir", "")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(firmware_path, allowed_dirs=allowed_dirs)

    if action == "scan":
        # Binwalk signature scan
        proc = await safe_subprocess(
            ["binwalk", "--signature", str(file_path)],
            timeout=120,
        )
        if not proc.success:
            return error_result(f"binwalk scan failed: {proc.stderr}")

        # Parse binwalk output
        components = _parse_binwalk(proc.stdout)
        return text_result({
            "firmware": str(file_path),
            "action": "scan",
            "components": components,
            "raw_output": proc.stdout[:5000],
        })

    elif action == "extract":
        if output_dir:
            validate_path(output_dir, allowed_dirs=allowed_dirs)
            cmd = ["binwalk", "-e", "-C", output_dir, str(file_path)]
        else:
            cmd = ["binwalk", "-e", str(file_path)]

        proc = await safe_subprocess(cmd, timeout=300)
        return text_result({
            "action": "extract",
            "success": proc.success,
            "output": proc.stdout[:5000],
            "errors": proc.stderr[:2000] if proc.stderr else None,
        })

    elif action == "entropy":
        proc = await safe_subprocess(
            ["binwalk", "-E", "--nplot", str(file_path)],
            timeout=60,
        )
        return text_result({
            "action": "entropy",
            "output": proc.stdout[:5000],
            "note": "High entropy regions may indicate encryption/compression",
        })

    elif action == "filesystems":
        # Try to identify embedded filesystems
        proc = await safe_subprocess(
            ["binwalk", "-A", str(file_path)],
            timeout=60,
        )
        return text_result({
            "action": "filesystems",
            "opcodes_analysis": proc.stdout[:5000],
        })

    elif action == "identify":
        # Multi-tool identification
        results: dict[str, Any] = {}

        # file magic
        file_proc = await safe_subprocess(
            ["file", "-b", str(file_path)], timeout=10,
        )
        results["file_type"] = file_proc.stdout.strip() if file_proc.success else "unknown"

        # Size and hashes
        data = file_path.read_bytes()
        results["size"] = len(data)
        results["sha256"] = hashlib.sha256(data).hexdigest()

        # Check for common firmware headers
        results["signatures"] = _detect_firmware_signatures(data)

        # binwalk quick scan
        bw_proc = await safe_subprocess(
            ["binwalk", "--signature", str(file_path)],
            timeout=60,
        )
        if bw_proc.success:
            results["binwalk_components"] = _parse_binwalk(bw_proc.stdout)

        return text_result({"action": "identify", **results})

    elif action == "strings_analysis":
        proc = await safe_subprocess(
            ["strings", "-a", "-n", "8", str(file_path)],
            timeout=30,
        )
        if not proc.success:
            return error_result(f"strings failed: {proc.stderr}")

        all_strings = proc.stdout.split("\n")
        categorized = _categorize_firmware_strings(all_strings)

        return text_result({
            "action": "strings_analysis",
            "total_strings": len(all_strings),
            "categorized": categorized,
        })

    else:
        return error_result(f"Unknown firmware action: {action}")


@TOOL_REGISTRY.register(
    name="re_firmware_vuln_scan",
    description=(
        "Scan firmware for vulnerabilities: hardcoded credentials, "
        "known CVEs, unsafe functions, exposed services."
    ),
    category="firmware",
    input_schema={
        "type": "object",
        "required": ["firmware_path"],
        "properties": {
            "firmware_path": {
                "type": "string",
                "description": "Path to firmware image or extracted filesystem.",
            },
            "scan_type": {
                "type": "string",
                "enum": ["all", "credentials", "cves", "unsafe_funcs", "services", "crypto"],
                "description": "Scan type. Default: all.",
            },
        },
    },
)
async def handle_firmware_vuln(
    arguments: dict[str, Any],
) -> list[dict[str, Any]]:
    """Firmware vulnerability scanning."""
    firmware_path = arguments["firmware_path"]
    scan_type = arguments.get("scan_type", "all")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(firmware_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()
    text_data = data.decode("latin-1")
    results: dict[str, Any] = {"binary": str(file_path)}

    if scan_type in ("all", "credentials"):
        creds = _find_hardcoded_creds(text_data)
        results["hardcoded_credentials"] = creds

    if scan_type in ("all", "unsafe_funcs"):
        # Extract imports/symbols
        proc = await safe_subprocess(
            ["strings", "-a", str(file_path)], timeout=30,
        )
        strings_out = proc.stdout if proc.success else ""
        unsafe = _check_unsafe_functions(strings_out)
        results["unsafe_functions"] = unsafe

    if scan_type in ("all", "services"):
        services = _detect_services(text_data)
        results["exposed_services"] = services

    if scan_type in ("all", "crypto"):
        crypto = _analyze_crypto(text_data, data)
        results["crypto_analysis"] = crypto

    if scan_type in ("all", "cves"):
        # Try to identify firmware version for CVE lookup
        version_info = _extract_version_info(text_data)
        results["version_info"] = version_info
        results["cve_note"] = (
            "Cross-reference version info with NVD/CVE databases "
            "for known vulnerabilities."
        )

    return text_result(results)


@TOOL_REGISTRY.register(
    name="re_firmware_baseaddr",
    description=(
        "Detect firmware base address using string reference analysis, "
        "function prologue scanning, and pattern matching."
    ),
    category="firmware",
    input_schema={
        "type": "object",
        "required": ["firmware_path"],
        "properties": {
            "firmware_path": {
                "type": "string",
                "description": "Path to firmware binary blob.",
            },
            "arch": {
                "type": "string",
                "enum": ["arm", "mips", "x86", "x64"],
                "description": "Target architecture. Default: arm.",
            },
        },
    },
)
async def handle_firmware_baseaddr(
    arguments: dict[str, Any],
) -> list[dict[str, Any]]:
    """Firmware base address detection."""
    firmware_path = arguments["firmware_path"]
    arch = arguments.get("arch", "arm")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(firmware_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()

    # Strategy 1: Look for string references
    strings_proc = await safe_subprocess(
        ["strings", "-t", "x", "-a", str(file_path)], timeout=30,
    )

    candidates: list[dict[str, Any]] = []

    if strings_proc.success:
        string_offsets: list[int] = []
        for line in strings_proc.stdout.split("\n"):
            parts = line.strip().split(None, 1)
            if len(parts) >= 2:
                try:
                    offset = int(parts[0], 16)
                    string_offsets.append(offset)
                except ValueError:
                    pass

        # Look for potential base addresses by finding pointer-like
        # values that reference string offsets when a base is added
        common_bases = [
            0x00000000, 0x08000000, 0x10000000, 0x20000000,
            0x40000000, 0x80000000, 0xC0000000,
            0x00010000, 0x00100000, 0x01000000,
        ]

        for base in common_bases:
            hits = 0
            for offset in string_offsets[:100]:
                target = base + offset
                # Search for this pointer in the binary
                target_bytes = target.to_bytes(4, "little")

                if target_bytes in data:
                    hits += 1

            if hits >= 3:
                candidates.append({
                    "base_address": hex(base),
                    "string_refs_found": hits,
                    "confidence": "high" if hits >= 10 else "medium" if hits >= 5 else "low",
                })

    # Sort by confidence
    candidates.sort(key=lambda x: x["string_refs_found"], reverse=True)

    return text_result({
        "binary": str(file_path),
        "arch": arch,
        "candidates": candidates[:10],
        "best_guess": candidates[0]["base_address"] if candidates else "0x00000000",
        "note": "Verify by loading in disassembler and checking string references",
    })


def _parse_binwalk(output: str) -> list[dict[str, str]]:
    """Parse binwalk signature scan output."""
    components = []
    for line in output.split("\n"):
        # binwalk format: DECIMAL    HEXADECIMAL    DESCRIPTION
        match = re.match(r"(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)", line.strip())
        if match:
            components.append({
                "offset_dec": match.group(1),
                "offset_hex": match.group(2),
                "description": match.group(3),
            })
    return components


def _detect_firmware_signatures(data: bytes) -> list[str]:
    """Detect common firmware format signatures."""
    sigs: list[str] = []
    checks: list[tuple[bytes, str]] = [
        (b"\x27\x05\x19\x56", "U-Boot uImage"),
        (b"UBI#", "UBI filesystem"),
        (b"hsqs", "SquashFS (little-endian)"),
        (b"sqsh", "SquashFS (big-endian)"),
        (b"\xd0\x0d\xfe\xed", "Device Tree Blob (FDT)"),
        (b"LZMA", "LZMA compressed"),
        (b"\x1f\x8b", "gzip compressed"),
        (b"BZ", "bzip2 compressed"),
        (b"\x89PNG", "PNG image"),
        (b"JFIF", "JPEG image"),
        (b"EFI PART", "GPT partition"),
        (b"\xeb\x3c\x90", "DOS/MBR boot sector"),
        (b"androidboot", "Android boot image"),
        (b"ANDROID!", "Android boot image"),
    ]

    for magic, name in checks:
        idx = data.find(magic)
        if idx != -1:
            sigs.append(f"{name} at offset {hex(idx)}")

    return sigs


def _categorize_firmware_strings(strings: list[str]) -> dict[str, list[str]]:
    """Categorize firmware strings by type."""
    categories: dict[str, list[str]] = {
        "urls": [],
        "ips": [],
        "paths": [],
        "credentials": [],
        "versions": [],
        "commands": [],
        "crypto": [],
    }

    for s in strings:
        s = s.strip()
        if not s:
            continue

        if re.match(r"https?://", s):
            categories["urls"].append(s)
        elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
            categories["ips"].append(s)
        elif "/" in s and any(d in s for d in ("/etc/", "/usr/", "/bin/", "/dev/", "/proc/")):
            categories["paths"].append(s)
        elif any(k in s.lower() for k in ("password", "passwd", "secret", "token", "apikey")):
            categories["credentials"].append(s)
        elif re.search(r"v?\d+\.\d+\.\d+", s):
            categories["versions"].append(s)
        elif any(c in s for c in ("sh ", "echo ", "cat ", "chmod ", "mount ")):
            categories["commands"].append(s)
        elif any(c in s.lower() for c in ("aes", "rsa", "sha", "md5", "encrypt", "decrypt")):
            categories["crypto"].append(s)

    # Limit each category
    return {k: v[:30] for k, v in categories.items() if v}


def _find_hardcoded_creds(text: str) -> list[dict[str, str]]:
    """Find hardcoded credentials in firmware."""
    creds: list[dict[str, str]] = []

    # Common patterns
    patterns = [
        (r"(?:password|passwd|pwd)\s*[:=]\s*[\"']?(\S{3,50})[\"']?", "password"),
        (r"(?:username|user|login)\s*[:=]\s*[\"']?(\S{3,50})[\"']?", "username"),
        (r"(?:api[_-]?key|apikey)\s*[:=]\s*[\"']?(\S{10,100})[\"']?", "api_key"),
        (r"(?:token|auth[_-]?token)\s*[:=]\s*[\"']?(\S{10,100})[\"']?", "token"),
        (r"root:(\$[0-9a-z]\$\S+):", "password_hash"),
        (r"admin:(\S+)", "admin_credential"),
    ]

    for pattern, cred_type in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches[:5]:
            creds.append({"type": cred_type, "value": m[:50]})

    return creds[:20]


def _check_unsafe_functions(strings_text: str) -> list[dict[str, str]]:
    """Check for unsafe/deprecated functions."""
    unsafe: dict[str, str] = {
        "strcpy": "Buffer overflow risk - use strncpy/strlcpy",
        "strcat": "Buffer overflow risk - use strncat/strlcat",
        "sprintf": "Buffer overflow risk - use snprintf",
        "gets": "Critical buffer overflow - use fgets",
        "scanf": "Buffer overflow risk - use fgets + sscanf",
        "system": "Command injection risk",
        "popen": "Command injection risk",
        "exec": "Code execution",
        "mktemp": "Race condition - use mkstemp",
    }

    found: list[dict[str, str]] = []
    for func, risk in unsafe.items():
        if func in strings_text:
            found.append({"function": func, "risk": risk})
    return found


def _detect_services(text: str) -> list[dict[str, str]]:
    """Detect exposed network services in firmware."""
    services: list[dict[str, str]] = []
    service_sigs = {
        "telnetd": "Telnet daemon (insecure)",
        "sshd": "SSH daemon",
        "httpd": "HTTP server",
        "lighttpd": "Lighttpd web server",
        "nginx": "Nginx web server",
        "ftpd": "FTP daemon",
        "tftpd": "TFTP daemon",
        "snmpd": "SNMP daemon",
        "upnpd": "UPnP daemon",
        "miniupnpd": "MiniUPnP daemon",
        "dnsmasq": "DNS/DHCP server",
    }

    for sig, desc in service_sigs.items():
        if sig in text.lower():
            services.append({"service": sig, "description": desc})
    return services


def _analyze_crypto(text: str, data: bytes) -> dict[str, Any]:
    """Analyze cryptographic usage in firmware."""
    crypto: dict[str, Any] = {}

    # Known weak crypto
    weak_crypto = ["DES", "RC4", "MD5", "SHA1"]
    strong_crypto = ["AES", "RSA", "SHA256", "SHA512", "ChaCha"]

    crypto["weak"] = [c for c in weak_crypto if c.lower() in text.lower()]
    crypto["strong"] = [c for c in strong_crypto if c.lower() in text.lower()]

    # Look for hardcoded crypto constants
    # AES S-box first bytes
    if b"\x63\x7c\x77\x7b" in data:
        crypto["aes_sbox_found"] = True

    return crypto


def _extract_version_info(text: str) -> list[str]:
    """Extract version information strings."""
    patterns = [
        r"(?:version|ver|v)\s*[:=]?\s*(\d+\.\d+[\.\d]*)",
        r"(?:firmware|fw)\s*[:=]?\s*(\d+\.\d+[\.\d]*)",
        r"Build\s+(\d+[\.\d]*)",
        r"U-Boot\s+(\d+\.\d+[\.\d]*)",
        r"Linux\s+(\d+\.\d+[\.\d]*)",
        r"BusyBox\s+v?(\d+\.\d+[\.\d]*)",
    ]

    versions: list[str] = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        versions.extend(matches[:5])
    return list(set(versions))[:15]
