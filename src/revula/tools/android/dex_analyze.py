"""
Revula Android DEX Analyzer — Deep Dalvik bytecode analysis.

Extracts classes, methods, strings, detects crypto usage, reflection calls,
native bridges, obfuscation indicators, and computes obfuscation scores.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import struct
import zipfile
from collections import Counter
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, text_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRYPTO_CLASSES: set[str] = {
    "Ljavax/crypto/Cipher;",
    "Ljavax/crypto/SecretKey;",
    "Ljavax/crypto/KeyGenerator;",
    "Ljavax/crypto/Mac;",
    "Ljavax/crypto/spec/SecretKeySpec;",
    "Ljavax/crypto/spec/IvParameterSpec;",
    "Ljava/security/MessageDigest;",
    "Ljava/security/KeyPairGenerator;",
    "Ljava/security/Signature;",
    "Ljava/security/KeyStore;",
    "Ljavax/net/ssl/SSLContext;",
    "Ljavax/net/ssl/TrustManager;",
    "Ljavax/net/ssl/X509TrustManager;",
    "Landroid/security/keystore/KeyGenParameterSpec;",
}

REFLECTION_METHODS: set[str] = {
    "Ljava/lang/Class;->forName",
    "Ljava/lang/Class;->getMethod",
    "Ljava/lang/Class;->getDeclaredMethod",
    "Ljava/lang/Class;->getField",
    "Ljava/lang/Class;->getDeclaredField",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/reflect/Constructor;->newInstance",
}

OBFUSCATION_KEYWORDS: list[str] = [
    "Lcom/tencent/mm/sdk/",
    "Lcom/qihoo/util/",
    "Lcom/bangcle/",
    "Lcom/secneo/",
    "Lcom/secshell/",
    "Lcom/ijiami/",
    "Lcom/nqshield/",
    "Lcom/payegis/",
    "Lcom/baidu/protect/",
    "Lcom/alibaba/mobisecenhance/",
]

DYNAMIC_LOADING_METHODS: set[str] = {
    "Ljava/lang/ClassLoader;->loadClass",
    "Ldalvik/system/DexClassLoader;-><init>",
    "Ldalvik/system/PathClassLoader;-><init>",
    "Ldalvik/system/InMemoryDexClassLoader;-><init>",
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/Runtime;->load",
    "Ljava/lang/Runtime;->loadLibrary",
    "Ljava/lang/System;->load",
    "Ljava/lang/System;->loadLibrary",
}


# ---------------------------------------------------------------------------
# DEX Header Parser (no deps)
# ---------------------------------------------------------------------------


def _parse_dex_header(data: bytes) -> dict[str, Any]:
    """Parse DEX file header."""
    if len(data) < 112 or data[:4] != b"dex\n":
        return {"error": "Not a valid DEX file"}

    version = data[4:7].decode("ascii", errors="replace")
    checksum = struct.unpack_from("<I", data, 8)[0]
    sha1 = data[12:32].hex()
    file_size = struct.unpack_from("<I", data, 32)[0]
    header_size = struct.unpack_from("<I", data, 36)[0]

    return {
        "version": version,
        "checksum": f"0x{checksum:08x}",
        "sha1": sha1,
        "file_size": file_size,
        "header_size": header_size,
        "string_ids_size": struct.unpack_from("<I", data, 56)[0],
        "type_ids_size": struct.unpack_from("<I", data, 64)[0],
        "proto_ids_size": struct.unpack_from("<I", data, 72)[0],
        "field_ids_size": struct.unpack_from("<I", data, 80)[0],
        "method_ids_size": struct.unpack_from("<I", data, 88)[0],
        "class_defs_size": struct.unpack_from("<I", data, 96)[0],
        "data_size": struct.unpack_from("<I", data, 104)[0],
    }


def _extract_dex_strings(data: bytes) -> list[str]:
    """Extract strings from DEX string table."""
    if len(data) < 112 or data[:4] != b"dex\n":
        return []

    string_count = struct.unpack_from("<I", data, 56)[0]
    string_off = struct.unpack_from("<I", data, 60)[0]

    strings: list[str] = []
    for i in range(min(string_count, 50000)):  # Cap at 50k
        off_pos = string_off + i * 4
        if off_pos + 4 > len(data):
            break
        str_data_off = struct.unpack_from("<I", data, off_pos)[0]
        if str_data_off >= len(data):
            break

        # MUTF-8 length prefix (ULEB128)
        pos = str_data_off
        utf16_size = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            utf16_size |= (b & 0x7F) << shift
            if b & 0x80 == 0:
                break
            shift += 7

        # Read null-terminated MUTF-8 string
        end = data.find(b"\x00", pos)
        if end == -1:
            end = min(pos + utf16_size * 3, len(data))
        try:
            s = data[pos:end].decode("utf-8", errors="replace")
            strings.append(s)
        except Exception:
            pass

    return strings


def _compute_obfuscation_score(
    class_names: list[str],
    method_names: list[str],
    field_names: list[str],
    strings: list[str],
) -> dict[str, Any]:
    """Compute obfuscation indicators and a score 0-100."""
    score = 0
    indicators: list[str] = []

    # Short class names (a, b, c, etc.)
    total_classes = len(class_names)
    if total_classes > 0:
        short_names = [n for n in class_names if len(n.split("/")[-1].rstrip(";")) <= 2]
        short_ratio = len(short_names) / total_classes
        if short_ratio > 0.5:
            score += 30
            indicators.append(f"High short-class-name ratio: {short_ratio:.1%}")
        elif short_ratio > 0.2:
            score += 15
            indicators.append(f"Moderate short-class-name ratio: {short_ratio:.1%}")

    # Short method names
    total_methods = len(method_names)
    if total_methods > 0:
        short_methods = [n for n in method_names if len(n) <= 2 and not n.startswith("<")]
        short_method_ratio = len(short_methods) / total_methods
        if short_method_ratio > 0.3:
            score += 20
            indicators.append(f"High short-method-name ratio: {short_method_ratio:.1%}")

    # String encryption indicator: low string-to-method ratio
    if total_methods > 100:
        str_count = len(strings)
        ratio = str_count / total_methods
        if ratio < 0.5:
            score += 15
            indicators.append(f"Low string/method ratio: {ratio:.2f} (possible string encryption)")

    # Class name entropy
    if class_names:
        all_chars = "".join(n.split("/")[-1].rstrip(";") for n in class_names)
        if all_chars:
            char_counts = Counter(all_chars)
            total_chars = len(all_chars)
            entropy = -sum(
                (c / total_chars) * math.log2(c / total_chars)
                for c in char_counts.values()
                if c > 0
            )
            if entropy > 4.0:
                score += 15
                indicators.append(f"High class-name entropy: {entropy:.2f}")

    # Known packer signatures in strings
    for keyword in OBFUSCATION_KEYWORDS:
        if any(keyword in s for s in strings[:5000]):
            score += 10
            indicators.append(f"Known packer signature: {keyword}")
            break

    # Excessive number of synthetic/bridge methods in names
    synthetic_count = sum(1 for n in method_names if n.startswith("access$"))
    if total_methods > 0 and synthetic_count / total_methods > 0.1:
        score += 10
        indicators.append(f"High synthetic method ratio: {synthetic_count}/{total_methods}")

    return {
        "score": min(score, 100),
        "level": (
            "none" if score < 10
            else "low" if score < 30
            else "moderate" if score < 60
            else "high"
        ),
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# Androguard-based deep analysis
# ---------------------------------------------------------------------------


def _analyze_with_androguard(apk_path: str) -> dict[str, Any]:
    """Deep DEX analysis using androguard."""
    from androguard.core.apk import APK  # type: ignore[import-not-found]
    from androguard.core.dex import DEX  # type: ignore[import-not-found]

    a = APK(apk_path)
    result: dict[str, Any] = {
        "classes": [],
        "crypto_usage": [],
        "reflection_usage": [],
        "dynamic_loading": [],
        "native_methods": [],
        "url_strings": [],
        "ip_strings": [],
    }

    class_names: list[str] = []
    method_names: list[str] = []
    field_names: list[str] = []
    all_strings: list[str] = []

    for dex_name in a.get_dex_names():
        dex_data = a.get_file(dex_name)
        if not dex_data:
            continue

        d = DEX(dex_data)

        for cls in d.get_classes():
            cls_name = cls.get_name()
            class_names.append(cls_name)

            class_info: dict[str, Any] = {
                "name": cls_name,
                "access_flags": cls.get_access_flags_string(),
                "super": cls.get_superclassname(),
                "methods": [],
            }

            for method in cls.get_methods():
                m_name = method.get_name()
                method_names.append(m_name)

                m_info: dict[str, Any] = {
                    "name": m_name,
                    "descriptor": method.get_descriptor(),
                    "access_flags": method.get_access_flags_string(),
                }

                # Check if native
                if "native" in method.get_access_flags_string():
                    result["native_methods"].append(f"{cls_name}->{m_name}")

                class_info["methods"].append(m_info)

            for field in cls.get_fields():
                field_names.append(field.get_name())

            # Only include first 500 classes to avoid huge output
            if len(result["classes"]) < 500:
                result["classes"].append(class_info)

            # Check for crypto references
            if cls_name in CRYPTO_CLASSES:
                result["crypto_usage"].append({
                    "class": cls_name,
                    "type": "crypto_api",
                })

        # Extract strings
        for s in d.get_strings():
            all_strings.append(s)

            # URL detection
            if re.match(r"https?://", s):
                result["url_strings"].append(s)

            # IP detection
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
                result["ip_strings"].append(s)

            # Reflection detection
            for ref in REFLECTION_METHODS:
                if ref in s:
                    result["reflection_usage"].append({"string": s, "api": ref})

            # Dynamic loading
            for dl in DYNAMIC_LOADING_METHODS:
                if dl in s:
                    result["dynamic_loading"].append({"string": s, "api": dl})

    result["statistics"] = {
        "total_classes": len(class_names),
        "total_methods": len(method_names),
        "total_fields": len(field_names),
        "total_strings": len(all_strings),
        "native_method_count": len(result["native_methods"]),
        "crypto_references": len(result["crypto_usage"]),
        "reflection_references": len(result["reflection_usage"]),
        "dynamic_loading_references": len(result["dynamic_loading"]),
    }

    result["obfuscation"] = _compute_obfuscation_score(
        class_names, method_names, field_names, all_strings
    )

    return result


# ---------------------------------------------------------------------------
# Fallback DEX analysis (no androguard)
# ---------------------------------------------------------------------------


def _analyze_dex_fallback(apk_path: str) -> dict[str, Any]:
    """Analyze DEX using only stdlib."""
    result: dict[str, Any] = {"dex_files": []}

    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith(".dex"):
                data = zf.read(name)
                header = _parse_dex_header(data)
                strings = _extract_dex_strings(data)

                dex_info: dict[str, Any] = {
                    "name": name,
                    "header": header,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "url_strings": [s for s in strings if re.match(r"https?://", s)],
                    "ip_strings": [
                        s for s in strings
                        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s)
                    ],
                    "crypto_strings": [
                        s for s in strings
                        if any(c.strip("L").strip(";").split("/")[-1] in s for c in CRYPTO_CLASSES)
                    ],
                }

                # Obfuscation heuristic based on string analysis
                class_strings = [s for s in strings if s.startswith("L") and s.endswith(";")]
                method_strings = [
                    s for s in strings
                    if len(s) <= 2 and s.isalpha() and s.islower()
                ]
                dex_info["obfuscation"] = _compute_obfuscation_score(
                    class_strings, method_strings, [], strings
                )

                result["dex_files"].append(dex_info)

    return result


# ---------------------------------------------------------------------------
# Tool: re_android_dex_analyze
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_dex_analyze",
    description=(
        "Deep DEX bytecode analysis: classes, methods, strings, crypto usage, "
        "reflection, native bridges, dynamic class loading, URL/IP extraction, "
        "and obfuscation scoring. Uses androguard or pure-Python fallback."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Absolute path to APK or DEX file.",
            },
            "include_classes": {
                "type": "boolean",
                "description": "Include full class listing (can be large). Default: false.",
            },
            "string_filter": {
                "type": "string",
                "description": "Regex filter for extracted strings.",
            },
        },
    },
)
async def handle_dex_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze DEX bytecode in APK."""
    apk_path = arguments["apk_path"]
    include_classes = arguments.get("include_classes", False)
    string_filter = arguments.get("string_filter")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    try:
        result = _analyze_with_androguard(str(file_path))
        result["analyzer"] = "androguard"
    except ImportError:
        logger.info("androguard not available, using fallback DEX parser")
        result = _analyze_dex_fallback(str(file_path))
        result["analyzer"] = "fallback"
    except Exception as e:
        logger.warning("androguard failed: %s, using fallback", e)
        result = _analyze_dex_fallback(str(file_path))
        result["analyzer"] = "fallback"

    # Apply string filter
    if string_filter:
        pattern = re.compile(string_filter, re.IGNORECASE)
        for key in ["url_strings", "ip_strings"]:
            if key in result:
                result[key] = [s for s in result[key] if pattern.search(s)]

    # Remove classes if not requested (large output)
    if not include_classes and "classes" in result:
        result["class_count"] = len(result["classes"])
        del result["classes"]

    return text_result(result)
