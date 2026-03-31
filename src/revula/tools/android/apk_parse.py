"""
Revula Android APK Parser — Full APK static analysis via androguard + apktool.

Parses manifest, permissions, components, certificates, native libs, DEX files,
resources, and produces automated security findings.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import zipfile
from collections import Counter
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
}


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            freq = count / length
            entropy -= freq * math.log2(freq)
    return entropy


def _parse_with_androguard(apk_path: str) -> dict[str, Any]:
    """Parse APK using androguard Python library."""
    from androguard.core.apk import APK

    a = APK(apk_path)
    result: dict[str, Any] = {}

    # Manifest basics
    result["manifest"] = {
        "package_name": a.get_package(),
        "version_code": a.get_androidversion_code(),
        "version_name": a.get_androidversion_name(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "effective_target_sdk": a.get_effective_target_sdk_version(),
        "debuggable": a.get_attribute_value("application", "debuggable") == "true",
        "allow_backup": a.get_attribute_value("application", "allowBackup") != "false",
        "network_security_config": a.get_attribute_value(
            "application", "networkSecurityConfig"
        ) is not None,
        "uses_cleartext_traffic": a.get_attribute_value(
            "application", "usesCleartextTraffic"
        ) == "true",
    }

    # Permissions
    used_permissions = a.get_permissions()
    declared_permissions = a.get_declared_permissions()
    result["permissions"] = {
        "used": [
            {
                "name": p,
                "dangerous": p in DANGEROUS_PERMISSIONS,
            }
            for p in used_permissions
        ],
        "declared": [{"name": p} for p in declared_permissions],
        "custom": [
            {"name": p}
            for p in declared_permissions
            if not p.startswith("android.permission.")
        ],
    }

    # Components
    result["components"] = {
        "activities": [
            {
                "name": act,
                "exported": _is_exported(a, "activity", act),
                "intent_filters": _get_intent_filters(a, "activity", act),
            }
            for act in a.get_activities()
        ],
        "services": [
            {
                "name": svc,
                "exported": _is_exported(a, "service", svc),
                "intent_filters": _get_intent_filters(a, "service", svc),
            }
            for svc in a.get_services()
        ],
        "receivers": [
            {
                "name": rcv,
                "exported": _is_exported(a, "receiver", rcv),
                "intent_filters": _get_intent_filters(a, "receiver", rcv),
            }
            for rcv in a.get_receivers()
        ],
        "providers": [
            {
                "name": prov,
                "exported": _is_exported(a, "provider", prov),
                "authorities": a.get_attribute_value("provider", "authorities", name=prov),
                "grant_uri_permissions": a.get_attribute_value(
                    "provider", "grantUriPermissions", name=prov
                ) == "true",
            }
            for prov in a.get_providers()
        ],
    }

    # Certificates
    certs = []
    for cert in a.get_certificates():
        cert_info: dict[str, Any] = {
            "subject": str(cert.subject),
            "issuer": str(cert.issuer),
            "serial": str(cert.serial_number),
            "fingerprint_sha256": cert.sha256_fingerprint if hasattr(cert, "sha256_fingerprint") else "",
            "is_self_signed": cert.subject == cert.issuer,
        }
        certs.append(cert_info)
    result["certificates"] = certs

    # DEX files
    dex_files = []
    for dex_name in a.get_dex_names():
        dex_data = a.get_file(dex_name)
        if dex_data:
            dex_files.append({
                "name": dex_name,
                "size": len(dex_data),
                "sha256": hashlib.sha256(dex_data).hexdigest(),
            })
    result["dex_files"] = dex_files

    return result


def _is_exported(apk: Any, component_type: str, name: str) -> bool:
    """Check if a component is exported."""
    val = apk.get_attribute_value(component_type, "exported", name=name)
    if val is not None:
        return bool(val == "true")
    # If no explicit exported flag, components with intent-filters are exported by default
    filters = _get_intent_filters(apk, component_type, name)
    return bool(len(filters) > 0)


def _get_intent_filters(apk: Any, component_type: str, name: str) -> list[dict[str, Any]]:
    """Get intent filters for a component."""
    try:
        filters = apk.get_intent_filters(component_type, name)
        if filters:
            result = []
            if isinstance(filters, dict):
                for action in filters.get("action", []):
                    result.append({"action": action})
                for category in filters.get("category", []):
                    result.append({"category": category})
            return result
    except Exception:
        pass
    return []


def _analyze_native_libs(apk_path: str) -> list[dict[str, Any]]:
    """Analyze native .so libraries inside APK."""
    native_libs = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for entry in zf.namelist():
                if entry.startswith("lib/") and entry.endswith(".so"):
                    parts = entry.split("/")
                    arch = parts[1] if len(parts) > 2 else "unknown"
                    info = zf.getinfo(entry)
                    data = zf.read(entry)
                    entropy = _shannon_entropy(data)

                    # Check for suspicious strings in the .so
                    suspicious: list[str] = []
                    try:
                        text = data.decode("ascii", errors="ignore")
                        for pattern in [
                            "frida", "xposed", "substrate", "ptrace",
                            "/proc/self/status", "TracerPid",
                            "su", "/system/bin/su", "magisk",
                        ]:
                            if pattern in text.lower():
                                suspicious.append(pattern)
                    except Exception:
                        pass

                    native_libs.append({
                        "name": os.path.basename(entry),
                        "path": entry,
                        "arch": arch,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "entropy": round(entropy, 4),
                        "packed": entropy > 7.0,
                        "suspicious_strings": suspicious,
                    })
    except Exception as e:
        logger.warning("Failed to analyze native libs: %s", e)
    return native_libs


def _generate_security_flags(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate automated security findings."""
    flags: list[dict[str, Any]] = []
    manifest = result.get("manifest", {})

    if manifest.get("debuggable"):
        flags.append({
            "severity": "HIGH",
            "finding": "Application is debuggable",
            "location": "AndroidManifest.xml",
        })

    if manifest.get("allow_backup"):
        flags.append({
            "severity": "MEDIUM",
            "finding": "Application allows backup (data extraction risk)",
            "location": "AndroidManifest.xml",
        })

    if manifest.get("uses_cleartext_traffic"):
        flags.append({
            "severity": "MEDIUM",
            "finding": "Application allows cleartext traffic",
            "location": "AndroidManifest.xml",
        })

    if not manifest.get("network_security_config"):
        flags.append({
            "severity": "LOW",
            "finding": "No network security config defined",
            "location": "AndroidManifest.xml",
        })

    min_sdk = manifest.get("min_sdk")
    if min_sdk and int(min_sdk) < 21:
        flags.append({
            "severity": "MEDIUM",
            "finding": f"minSdkVersion is {min_sdk} (< 21), exposing to older vulnerabilities",
            "location": "AndroidManifest.xml",
        })

    # Check exported components without permissions
    for comp_type in ["activities", "services", "receivers", "providers"]:
        for comp in result.get("components", {}).get(comp_type, []):
            if comp.get("exported"):
                flags.append({
                    "severity": "MEDIUM",
                    "finding": f"Exported {comp_type[:-1]}: {comp['name']}",
                    "location": "AndroidManifest.xml",
                })

    # Dangerous permissions
    for perm in result.get("permissions", {}).get("used", []):
        if perm.get("dangerous"):
            flags.append({
                "severity": "LOW",
                "finding": f"Uses dangerous permission: {perm['name']}",
                "location": "AndroidManifest.xml",
            })

    return flags


# ---------------------------------------------------------------------------
# ZIP-based fallback parser (no androguard needed)
# ---------------------------------------------------------------------------


def _parse_with_zipfile(apk_path: str) -> dict[str, Any]:
    """Basic APK parsing using only zipfile + DEX header parsing."""
    result: dict[str, Any] = {"manifest": {}, "permissions": {}, "components": {}}

    with zipfile.ZipFile(apk_path, "r") as zf:
        # DEX files
        dex_files = []
        for name in zf.namelist():
            if name.endswith(".dex"):
                data = zf.read(name)
                dex_info: dict[str, Any] = {
                    "name": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                # Parse DEX header for basic stats
                if len(data) >= 112 and data[:4] == b"dex\n":
                    import struct

                    string_count = struct.unpack_from("<I", data, 56)[0]
                    type_count = struct.unpack_from("<I", data, 64)[0]
                    method_count = struct.unpack_from("<I", data, 88)[0]
                    class_count = struct.unpack_from("<I", data, 96)[0]
                    dex_info["string_count"] = string_count
                    dex_info["type_count"] = type_count
                    dex_info["method_count"] = method_count
                    dex_info["class_count"] = class_count
                dex_files.append(dex_info)
        result["dex_files"] = dex_files

        # File listing for resources/assets
        result["file_list"] = [
            {
                "name": info.filename,
                "size": info.file_size,
                "compressed": info.compress_size,
            }
            for info in zf.infolist()
            if not info.is_dir()
        ]

    return result


# ---------------------------------------------------------------------------
# Tool: re_android_apk_parse
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_apk_parse",
    description=(
        "Parse Android APK: manifest, permissions, components, certificates, "
        "native libraries, DEX files, and security findings. "
        "Uses androguard (primary) or ZIP-based fallback."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to APK file.",
            },
            "components": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Which components to analyze. Options: manifest, permissions, "
                    "activities, services, receivers, providers, certificates, "
                    "native_libs, dex_files, security_flags. Default: all."
                ),
            },
        },
    },
)
async def handle_apk_parse(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse an Android APK."""
    apk_path = arguments["apk_path"]
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    if not zipfile.is_zipfile(str(file_path)):
        return error_result(f"Not a valid ZIP/APK file: {apk_path}")

    # Try androguard first, fall back to ZIP parser
    try:
        result = _parse_with_androguard(str(file_path))
        result["parser"] = "androguard"
    except ImportError:
        logger.info("androguard not available, using ZIP-based fallback parser")
        result = _parse_with_zipfile(str(file_path))
        result["parser"] = "zipfile"
    except Exception as e:
        logger.warning("androguard failed, falling back to ZIP parser: %s", e)
        result = _parse_with_zipfile(str(file_path))
        result["parser"] = "zipfile"

    # Native libs (always available via zipfile)
    result["native_libs"] = _analyze_native_libs(str(file_path))

    # APK-level metadata
    apk_data = file_path.read_bytes()
    result["apk_info"] = {
        "path": str(file_path),
        "size": len(apk_data),
        "md5": hashlib.md5(apk_data).hexdigest(),
        "sha256": hashlib.sha256(apk_data).hexdigest(),
    }

    # Security flags
    result["security_flags"] = _generate_security_flags(result)

    return text_result(result)


# ---------------------------------------------------------------------------
# Tool: re_android_manifest_vulns
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_manifest_vulns",
    description=(
        "Scan AndroidManifest.xml for security vulnerabilities: exported components, "
        "debuggable flag, backup enabled, cleartext traffic, weak minSdk, etc."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to APK file.",
            },
        },
    },
)
async def handle_manifest_vulns(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Dedicated manifest vulnerability scanner."""
    apk_path = arguments["apk_path"]
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    vulns: list[dict[str, Any]] = []

    try:
        from androguard.core.apk import APK

        a = APK(str(file_path))

        # Debuggable
        if a.get_attribute_value("application", "debuggable") == "true":
            vulns.append({
                "vuln_id": "MANIFEST-001",
                "severity": "HIGH",
                "component": "application",
                "description": "Application is debuggable — allows arbitrary code execution via debugger attachment",
                "recommendation": "Set android:debuggable=\"false\" in release builds",
                "cwe_id": "CWE-489",
            })

        # Allow backup
        if a.get_attribute_value("application", "allowBackup") != "false":
            vulns.append({
                "vuln_id": "MANIFEST-002",
                "severity": "MEDIUM",
                "component": "application",
                "description": "Application allows backup — sensitive data can be extracted via adb backup",
                "recommendation": "Set android:allowBackup=\"false\"",
                "cwe_id": "CWE-530",
            })

        # Cleartext traffic
        if a.get_attribute_value("application", "usesCleartextTraffic") == "true":
            vulns.append({
                "vuln_id": "MANIFEST-003",
                "severity": "MEDIUM",
                "component": "application",
                "description": "Application allows cleartext (HTTP) traffic",
                "recommendation": "Set android:usesCleartextTraffic=\"false\" and use networkSecurityConfig",
                "cwe_id": "CWE-319",
            })

        # No network security config
        if not a.get_attribute_value("application", "networkSecurityConfig"):
            vulns.append({
                "vuln_id": "MANIFEST-004",
                "severity": "LOW",
                "component": "application",
                "description": "No networkSecurityConfig defined — relies on platform defaults",
                "recommendation": "Define a network_security_config.xml with certificate pinning",
                "cwe_id": "CWE-295",
            })

        # minSdkVersion < 21
        min_sdk = a.get_min_sdk_version()
        if min_sdk and int(min_sdk) < 21:
            vulns.append({
                "vuln_id": "MANIFEST-005",
                "severity": "MEDIUM",
                "component": "uses-sdk",
                "description": f"minSdkVersion={min_sdk} (< 21) exposes app to pre-Lollipop vulnerabilities",
                "recommendation": "Raise minSdkVersion to at least 21 (Android 5.0)",
                "cwe_id": "CWE-693",
            })

        # Exported components without explicit permissions
        for comp_type, getter in [
            ("activity", a.get_activities),
            ("service", a.get_services),
            ("receiver", a.get_receivers),
            ("provider", a.get_providers),
        ]:
            for name in getter():
                exported_val = a.get_attribute_value(comp_type, "exported", name=name)
                has_intent_filter = bool(_get_intent_filters(a, comp_type, name))

                is_exported = exported_val == "true" or (exported_val is None and has_intent_filter)
                if is_exported:
                    # Check for permission protection
                    perm = a.get_attribute_value(comp_type, "permission", name=name)
                    if not perm:
                        vulns.append({
                            "vuln_id": f"MANIFEST-EXPORTED-{comp_type.upper()}",
                            "severity": "HIGH" if comp_type == "provider" else "MEDIUM",
                            "component": f"{comp_type}/{name}",
                            "description": (
                                f"Exported {comp_type} '{name}' without permission protection"
                            ),
                            "recommendation": f"Add android:permission to the {comp_type} or set exported=false",
                            "cwe_id": "CWE-926",
                        })

                    # Provider-specific: grantUriPermissions
                    if comp_type == "provider":
                        if a.get_attribute_value("provider", "grantUriPermissions", name=name) == "true":
                            vulns.append({
                                "vuln_id": "MANIFEST-PROVIDER-GRANT-URI",
                                "severity": "HIGH",
                                "component": f"provider/{name}",
                                "description": "Exported provider with grantUriPermissions=true",
                                "recommendation": "Remove grantUriPermissions or restrict via path-permission",
                                "cwe_id": "CWE-284",
                            })

        # Custom permissions with normal protection level
        for perm_name in a.get_declared_permissions():
            details = a.get_declared_permissions_details()
            if perm_name in details:
                pl = details[perm_name].get("protectionLevel", "normal")
                if pl == "0x00000000" or pl == "normal":
                    vulns.append({
                        "vuln_id": "MANIFEST-PERM-NORMAL",
                        "severity": "LOW",
                        "component": f"permission/{perm_name}",
                        "description": f"Custom permission '{perm_name}' with protectionLevel=normal",
                        "recommendation": "Use signature or dangerous protection level for sensitive permissions",
                        "cwe_id": "CWE-732",
                    })

    except ImportError:
        return error_result(
            "androguard is required for manifest vulnerability scanning. "
            "Install: pip install androguard"
        )
    except Exception as e:
        return error_result(f"Manifest analysis failed: {e}")

    return text_result({
        "apk": str(file_path),
        "total_vulnerabilities": len(vulns),
        "by_severity": {
            "HIGH": sum(1 for v in vulns if v["severity"] == "HIGH"),
            "MEDIUM": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "LOW": sum(1 for v in vulns if v["severity"] == "LOW"),
        },
        "vulnerabilities": vulns,
    })


# ---------------------------------------------------------------------------
# Tool: re_android_resources
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_resources",
    description=(
        "Extract and analyze APK resources: string tables, raw files, assets, "
        "embedded APKs/DEX (dropper detection), and high-entropy files."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to APK file.",
            },
            "resource_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Types to extract: strings, raw, assets, all. Default: all.",
            },
        },
    },
)
async def handle_resources(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze APK resources."""
    apk_path = arguments["apk_path"]
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    result: dict[str, Any] = {}
    embedded_apks: list[str] = []
    embedded_dex: list[str] = []
    encrypted_files: list[dict[str, Any]] = []

    with zipfile.ZipFile(str(file_path), "r") as zf:
        raw_files: list[dict[str, Any]] = []
        assets: list[dict[str, Any]] = []

        for entry in zf.namelist():
            info = zf.getinfo(entry)
            if info.is_dir():
                continue

            data = zf.read(entry)
            entropy = _shannon_entropy(data)

            file_info = {
                "name": entry,
                "size": info.file_size,
                "entropy": round(entropy, 4),
            }

            # Classify
            if entry.startswith("res/raw/"):
                raw_files.append(file_info)
            elif entry.startswith("assets/"):
                assets.append(file_info)

            # Detect embedded APKs
            if entry.endswith(".apk") or (
                len(data) > 4 and data[:2] == b"PK" and b"AndroidManifest" in data[:10000]
            ):
                if entry != "":
                    embedded_apks.append(entry)

            # Detect hidden DEX files
            if data[:4] == b"dex\n" and not entry.endswith(".dex"):
                embedded_dex.append(entry)

            # High entropy files (potentially encrypted)
            if entropy > 7.2 and info.file_size > 1024:
                encrypted_files.append(file_info)

        result["raw_files"] = raw_files
        result["assets"] = assets

    result["embedded_apks"] = embedded_apks
    result["embedded_dex"] = embedded_dex
    result["encrypted_files"] = encrypted_files

    # Try to get string resources via androguard
    try:
        from androguard.core.apk import APK

        a = APK(str(file_path))
        string_resources = []
        # androguard string resource extraction
        try:
            res = a.get_android_resources()
            if res:
                for pkg_name in res.get_packages_names():
                    for locale in res.get_locales(pkg_name):
                        types = res.get_types(pkg_name, locale)
                        for res_type in types:
                            if res_type == "string":
                                for entry_config in res.get_resolved_res_configs(0):
                                    string_resources.append({
                                        "name": str(entry_config),
                                        "lang": locale or "default",
                                    })
        except Exception:
            pass
        result["strings"] = string_resources[:1000]  # Cap at 1000
    except ImportError:
        result["strings"] = []
        result["_note"] = "Install androguard for string resource extraction"

    return text_result(result)
