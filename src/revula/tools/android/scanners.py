"""
Revula Android Static Analysis Tooling — Semgrep, Quark Engine, MobSF integration.

Provides wrappers for specialized Android static analysis tools:
- Semgrep: pattern-based vulnerability scanning on decompiled sources
- Quark Engine: Android malware scoring
- MobSF: Mobile Security Framework REST API integration
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool: re_android_semgrep
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_semgrep",
    description=(
        "Run Semgrep security rules against decompiled Android source code. "
        "Supports custom rules, OWASP Mobile rulesets, and pattern matching."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["target_dir"],
        "properties": {
            "target_dir": {
                "type": "string",
                "description": "Directory containing decompiled Java/Kotlin source.",
            },
            "ruleset": {
                "type": "string",
                "description": (
                    "Semgrep ruleset to use. Options: 'auto', 'p/java', "
                    "'p/owasp-mobile', or path to custom rule file. Default: auto."
                ),
            },
            "severity_filter": {
                "type": "string",
                "enum": ["ERROR", "WARNING", "INFO"],
                "description": "Minimum severity to report. Default: all.",
            },
            "max_findings": {
                "type": "integer",
                "description": "Maximum findings to return. Default: 100.",
            },
        },
    },
)
async def handle_semgrep(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Run Semgrep on decompiled Android source."""
    target_dir = arguments["target_dir"]
    ruleset = arguments.get("ruleset", "auto")
    severity_filter = arguments.get("severity_filter")
    max_findings = arguments.get("max_findings", 100)

    semgrep = shutil.which("semgrep")
    if not semgrep:
        return error_result(
            "semgrep not found. Install: pip install semgrep"
        )

    if not os.path.isdir(target_dir):
        return error_result(f"Directory not found: {target_dir}")

    # Build command
    cmd = [
        semgrep,
        "--json",
        "--config", ruleset,
        target_dir,
    ]

    if severity_filter:
        cmd.extend(["--severity", severity_filter])

    proc = await safe_subprocess(cmd, timeout=300)

    try:
        results = json.loads(proc.stdout) if proc.stdout else {}
    except json.JSONDecodeError:
        return error_result(f"Failed to parse semgrep output: {proc.stdout[:2000]}")

    findings = results.get("results", [])

    # Simplify output
    simplified: list[dict[str, Any]] = []
    for f in findings[:max_findings]:
        simplified.append({
            "rule_id": f.get("check_id", ""),
            "severity": f.get("extra", {}).get("severity", ""),
            "message": f.get("extra", {}).get("message", ""),
            "file": f.get("path", ""),
            "line_start": f.get("start", {}).get("line"),
            "line_end": f.get("end", {}).get("line"),
            "code_snippet": f.get("extra", {}).get("lines", "")[:500],
            "metadata": {
                "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", []),
                "owasp": f.get("extra", {}).get("metadata", {}).get("owasp", []),
                "confidence": f.get("extra", {}).get("metadata", {}).get("confidence", ""),
            },
        })

    return text_result({
        "target": target_dir,
        "ruleset": ruleset,
        "total_findings": len(findings),
        "returned_findings": len(simplified),
        "by_severity": {
            "ERROR": sum(1 for f in simplified if f["severity"] == "ERROR"),
            "WARNING": sum(1 for f in simplified if f["severity"] == "WARNING"),
            "INFO": sum(1 for f in simplified if f["severity"] == "INFO"),
        },
        "findings": simplified,
        "errors": results.get("errors", [])[:10],
    })


# ---------------------------------------------------------------------------
# Tool: re_android_quark
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_quark",
    description=(
        "Run Quark Engine malware scoring on an APK. Detects suspicious "
        "behaviors, generates threat level scores, and maps to MITRE ATT&CK."
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
            "threshold": {
                "type": "integer",
                "description": "Minimum threat level (0-100) to report. Default: 0.",
            },
        },
    },
)
async def handle_quark(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Run Quark Engine analysis."""
    apk_path = arguments["apk_path"]
    threshold = arguments.get("threshold", 0)
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

    # Try Python API first
    try:
        from quark.report import Report  # type: ignore[import-not-found]

        report = Report()
        report.analysis(str(file_path))
        json_report = report.get_report("json")

        if isinstance(json_report, str):
            json_report = json.loads(json_report)

        # Filter by threshold
        crimes = json_report.get("crimes", [])
        filtered = [c for c in crimes if c.get("confidence", 0) >= threshold]

        return text_result({
            "apk": str(file_path),
            "analyzer": "quark_python",
            "threat_level": json_report.get("threat_level", "unknown"),
            "total_behaviors": len(crimes),
            "above_threshold": len(filtered),
            "behaviors": filtered[:100],
        })

    except ImportError:
        pass

    # Fall back to CLI
    quark = shutil.which("quark")
    if not quark:
        return error_result(
            "quark not found. Install: pip install quark-engine"
        )

    # Use NamedTemporaryFile (secure) instead of mktemp (TOCTOU race)
    with tempfile.NamedTemporaryFile(suffix=".json", prefix="revula_quark_", delete=False) as tmp:
        output_file = tmp.name
    cmd = [quark, "-a", str(file_path), "-o", output_file, "-j"]
    proc = await safe_subprocess(cmd, timeout=300)

    if proc.returncode != 0:
        return error_result(f"quark failed: {proc.stderr}")

    try:
        result = json.loads(Path(output_file).read_text())
    except Exception as e:
        return error_result(f"Failed to parse quark output: {e}")
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)

    return text_result({
        "apk": str(file_path),
        "analyzer": "quark_cli",
        "report": result,
    })


# ---------------------------------------------------------------------------
# Tool: re_android_mobsf_scan
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_mobsf_scan",
    description=(
        "Submit APK to MobSF (Mobile Security Framework) for comprehensive "
        "security analysis. Requires a running MobSF instance."
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
            "mobsf_url": {
                "type": "string",
                "description": "MobSF server URL. Default: http://localhost:8000.",
            },
            "api_key": {
                "type": "string",
                "description": "MobSF REST API key.",
            },
            "scan_type": {
                "type": "string",
                "enum": ["upload_scan", "report", "scorecard"],
                "description": "Action: upload_scan (default), report, scorecard.",
            },
            "hash": {
                "type": "string",
                "description": "File hash for report/scorecard (from previous upload).",
            },
        },
    },
)
async def handle_mobsf(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Interact with MobSF."""
    apk_path = arguments["apk_path"]
    mobsf_url = arguments.get("mobsf_url", "http://localhost:8000")
    api_key = arguments.get("api_key", "")
    scan_type = arguments.get("scan_type", "upload_scan")
    file_hash = arguments.get("hash")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    try:
        import urllib.parse
        import urllib.request
    except ImportError:
        return error_result("urllib required (stdlib)")

    mobsf_url = mobsf_url.rstrip("/")

    if scan_type == "upload_scan":
        file_path = validate_binary_path(apk_path, allowed_dirs=allowed_dirs)

        # Upload

        boundary = "----REVULA_BOUNDARY"
        file_data = file_path.read_bytes()
        filename = file_path.name

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        body += file_data
        body += f"\r\n--{boundary}--\r\n".encode()

        req = urllib.request.Request(
            f"{mobsf_url}/api/v1/upload",
            data=body,
            headers={
                "Authorization": api_key,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )

        try:
            resp = urllib.request.urlopen(req, timeout=120)
            upload_result = json.loads(resp.read().decode())
        except Exception as e:
            return error_result(f"MobSF upload failed: {e}")

        # Trigger scan
        scan_hash = upload_result.get("hash", "")
        scan_data = urllib.parse.urlencode({"hash": scan_hash}).encode()
        scan_req = urllib.request.Request(
            f"{mobsf_url}/api/v1/scan",
            data=scan_data,
            headers={"Authorization": api_key},
        )

        try:
            resp = urllib.request.urlopen(scan_req, timeout=600)
            scan_result = json.loads(resp.read().decode())
        except Exception as e:
            return error_result(f"MobSF scan failed: {e}")

        return text_result({
            "action": "upload_scan",
            "hash": scan_hash,
            "result": scan_result,
        })

    elif scan_type == "report":
        if not file_hash:
            return error_result("hash required for report")

        data = urllib.parse.urlencode({"hash": file_hash}).encode()
        req = urllib.request.Request(
            f"{mobsf_url}/api/v1/report_json",
            data=data,
            headers={"Authorization": api_key},
        )

        try:
            resp = urllib.request.urlopen(req, timeout=60)
            report = json.loads(resp.read().decode())
        except Exception as e:
            return error_result(f"MobSF report failed: {e}")

        return text_result({"action": "report", "hash": file_hash, "report": report})

    elif scan_type == "scorecard":
        if not file_hash:
            return error_result("hash required for scorecard")

        data = urllib.parse.urlencode({"hash": file_hash}).encode()
        req = urllib.request.Request(
            f"{mobsf_url}/api/v1/scorecard",
            data=data,
            headers={"Authorization": api_key},
        )

        try:
            resp = urllib.request.urlopen(req, timeout=60)
            scorecard = json.loads(resp.read().decode())
        except Exception as e:
            return error_result(f"MobSF scorecard failed: {e}")

        return text_result({"action": "scorecard", "hash": file_hash, "scorecard": scorecard})

    return error_result(f"Unknown scan_type: {scan_type}")
