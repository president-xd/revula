#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="${1:-revula:audit}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUDIT_ROOT="${REPO_ROOT}/workspace/docker-audit"
BIN_DIR="${AUDIT_ROOT}/binaries"
OUT_DIR="${AUDIT_ROOT}/output"
REPORT_DIR="${AUDIT_ROOT}/reports"
HOST_UID="${HOST_UID:-$(id -u)}"
HOST_GID="${HOST_GID:-$(id -g)}"

mkdir -p "${BIN_DIR}" "${OUT_DIR}" "${REPORT_DIR}"

BUILD_LOG="${REPORT_DIR}/docker-build.log"
VALIDATE_LOG="${REPORT_DIR}/validate-install.txt"
SUMMARY_TXT="${REPORT_DIR}/summary.txt"

echo "[INFO] Repo root: ${REPO_ROOT}"
echo "[INFO] Audit root: ${AUDIT_ROOT}"
echo "[INFO] Image tag: ${IMAGE_TAG}"
echo "[INFO] Audit container user: ${HOST_UID}:${HOST_GID}"

if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] docker CLI is not available on PATH"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] docker daemon is not reachable from this shell"
    echo "[ERROR] Check /var/run/docker.sock permissions or run with a user in docker group."
    exit 1
fi

echo "[INFO] Building image..."
docker build -t "${IMAGE_TAG}" "${REPO_ROOT}" 2>&1 | tee "${BUILD_LOG}"

echo "[INFO] Creating sample binaries..."
docker run --rm \
    --entrypoint /bin/bash \
    --user "${HOST_UID}:${HOST_GID}" \
    -v "${AUDIT_ROOT}:/workspace/audit" \
    "${IMAGE_TAG}" \
    -c '
set -euo pipefail
mkdir -p /workspace/audit/binaries /workspace/audit/output /workspace/audit/reports

cp /bin/true /workspace/audit/binaries/true_elf || true
cp /bin/ls /workspace/audit/binaries/ls_elf || true
cp /usr/bin/file /workspace/audit/binaries/file_elf || true
cp /usr/bin/printf /workspace/audit/binaries/printf_elf || true

if command -v strip >/dev/null 2>&1; then
    cp /bin/ls /workspace/audit/binaries/ls_elf_stripped || true
    strip /workspace/audit/binaries/ls_elf_stripped 2>/dev/null || true
fi

python - <<'"'"'PY'"'"'
from pathlib import Path
import struct
import time
import zipfile
import subprocess

root = Path("/workspace/audit/binaries")
root.mkdir(parents=True, exist_ok=True)

# Random blob
(root / "random.bin").write_bytes(b"A" * 1024 + b"\x00" * 1024)

# Minimal pcap (global header + one packet)
pcap = root / "sample.pcap"
hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
payload = b"\x00" * 60
ts = int(time.time())
pkt = struct.pack("<IIII", ts, 0, len(payload), len(payload)) + payload
pcap.write_bytes(hdr + pkt)

# Minimal fake APK
apk = root / "sample.apk"
with zipfile.ZipFile(apk, "w") as z:
    z.writestr("AndroidManifest.xml", "<manifest package=\"com.example.app\" />")
    z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)

# Simple yara rule
(root / "sample_rule.yar").write_text(
    "rule sample_rule { strings: $a = \"ABC\" condition: $a }\n",
    encoding="utf-8",
)

# Minimal smali tree
smali_dir = root / "smali"
smali_dir.mkdir(exist_ok=True)
(smali_dir / "Main.smali").write_text(
    ".class public LMain;\n"
    ".super Ljava/lang/Object;\n"
    ".method public static main([Ljava/lang/String;)V\n"
    "    .locals 0\n"
    "    return-void\n"
    ".end method\n",
    encoding="utf-8",
)

# Minimal WASM (if wat2wasm exists)
wat = root / "sample.wat"
wasm = root / "sample.wasm"
wat.write_text(
    "(module (func (export \"main\") (result i32) i32.const 7))\n",
    encoding="utf-8",
)
try:
    subprocess.run(["wat2wasm", str(wat), "-o", str(wasm)], check=True)
except Exception:
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
PY
'

echo "[INFO] Running install validator..."
docker run --rm \
    --entrypoint /bin/bash \
    --user "${HOST_UID}:${HOST_GID}" \
    -v "${REPO_ROOT}:/repo" \
    -v "${AUDIT_ROOT}:/workspace/audit" \
    "${IMAGE_TAG}" \
    -c 'python /repo/scripts/test/validate_install.py > /workspace/audit/reports/validate-install.txt 2>&1 || true'

echo "[INFO] Capturing tool and module inventory..."
docker run --rm \
    -i \
    --entrypoint /opt/venv/bin/python \
    --user "${HOST_UID}:${HOST_GID}" \
    -e REVULA_ALLOWED_DIRS="/workspace/audit:/home/revula:/tmp" \
    -v "${AUDIT_ROOT}:/workspace/audit" \
    "${IMAGE_TAG}" \
    - <<'PY'
from pathlib import Path
import json
from revula.config import get_config

cfg = get_config()
report = {
    "available_tools": sorted([k for k, v in cfg.tools.items() if v.available]),
    "missing_tools": sorted([k for k, v in cfg.tools.items() if not v.available]),
    "available_python_modules": sorted([k for k, v in cfg.python_modules.items() if v]),
    "missing_python_modules": sorted([k for k, v in cfg.python_modules.items() if not v]),
    "security": {
        "allowed_dirs": cfg.security.allowed_dirs,
        "max_memory_mb": cfg.security.max_memory_mb,
        "default_timeout": cfg.security.default_timeout,
        "max_timeout": cfg.security.max_timeout,
    },
}
Path("/workspace/audit/reports/tool-inventory.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)
PY

echo "[INFO] Running full MCP tool smoke audit..."
docker run --rm \
    -i \
    --entrypoint /opt/venv/bin/python \
    --user "${HOST_UID}:${HOST_GID}" \
    -e REVULA_ALLOWED_DIRS="/workspace/audit:/home/revula:/tmp" \
    -v "${AUDIT_ROOT}:/workspace/audit" \
    "${IMAGE_TAG}" \
    - <<'PY'
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Any

from revula.config import get_config
from revula.server import _register_all_tools
from revula.tools import TOOL_REGISTRY

cfg = get_config()
_register_all_tools()

bins = {
    "binary": "/workspace/audit/binaries/true_elf",
    "elf": "/workspace/audit/binaries/true_elf",
    "file": "/workspace/audit/binaries/true_elf",
    "pcap": "/workspace/audit/binaries/sample.pcap",
    "apk": "/workspace/audit/binaries/sample.apk",
    "wasm": "/workspace/audit/binaries/sample.wasm",
    "rules": "/workspace/audit/binaries/sample_rule.yar",
    "smali_dir": "/workspace/audit/binaries/smali",
    "output_dir": "/workspace/audit/output",
}

def sample_str(key: str) -> str:
    lk = key.lower()
    if "apk" in lk:
        return bins["apk"]
    if "pcap" in lk:
        return bins["pcap"]
    if "wasm" in lk:
        return bins["wasm"]
    if "rules" in lk:
        return bins["rules"]
    if "smali_dir" in lk:
        return bins["smali_dir"]
    if "output_dir" in lk:
        return bins["output_dir"]
    if "output" in lk:
        return f"/workspace/audit/output/{lk}.out"
    if "hex" in lk:
        return "41424344"
    return bins["binary"]

def sample_value(prop_name: str, prop_spec: dict[str, Any]) -> Any:
    if "enum" in prop_spec and prop_spec["enum"]:
        return prop_spec["enum"][0]
    t = prop_spec.get("type")
    if t == "string":
        return sample_str(prop_name)
    if t == "integer":
        return int(prop_spec.get("default", 5))
    if t == "number":
        return float(prop_spec.get("default", 1.0))
    if t == "boolean":
        return bool(prop_spec.get("default", False))
    if t == "array":
        return []
    if t == "object":
        return {}
    return None

async def run_one(name: str, schema: dict[str, Any]) -> dict[str, Any]:
    props = schema.get("properties", {})
    required = schema.get("required", [])
    args: dict[str, Any] = {}

    for req in required:
        spec = props.get(req, {"type": "string"})
        args[req] = sample_value(req, spec)

    for key, spec in props.items():
        if key not in args and "default" in spec:
            args[key] = spec["default"]

    if "timeout" in props and "timeout" not in args:
        args["timeout"] = 5
    if "timeout" in args:
        try:
            args["timeout"] = min(int(args["timeout"]), 10)
        except Exception:
            args["timeout"] = 5

    try:
        result = await asyncio.wait_for(TOOL_REGISTRY.execute(name, args), timeout=20)
        payload: dict[str, Any] = {"raw": result}
        first_text = None
        if result and isinstance(result[0], dict):
            first_text = result[0].get("text")
        if isinstance(first_text, str):
            try:
                parsed = json.loads(first_text)
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                pass
        is_error = bool(payload.get("error")) if isinstance(payload, dict) else False
        return {
            "tool": name,
            "status": "error" if is_error else "ok",
            "args": args,
            "message": payload.get("message", "") if isinstance(payload, dict) else "",
        }
    except asyncio.TimeoutError:
        return {"tool": name, "status": "timeout", "args": args, "message": "tool execution timeout"}
    except Exception as e:
        return {"tool": name, "status": "exception", "args": args, "message": f"{type(e).__name__}: {e}"}

async def main() -> None:
    readiness: list[dict[str, Any]] = []
    smoke: list[dict[str, Any]] = []

    for tool in sorted(TOOL_REGISTRY.all(), key=lambda t: t.name):
        missing_tools = [t for t in tool.requires_tools if not cfg.tools.get(t) or not cfg.tools[t].available]
        missing_mods = [m for m in tool.requires_modules if not cfg.python_modules.get(m)]
        readiness.append({
            "tool": tool.name,
            "category": tool.category,
            "requires_tools": tool.requires_tools,
            "requires_modules": tool.requires_modules,
            "ready": not missing_tools and not missing_mods,
            "missing_tools": missing_tools,
            "missing_modules": missing_mods,
        })

    for tool in sorted(TOOL_REGISTRY.all(), key=lambda t: t.name):
        smoke.append(await run_one(tool.name, tool.input_schema))

    out = Path("/workspace/audit/reports")
    out.mkdir(parents=True, exist_ok=True)
    (out / "tool-readiness.json").write_text(json.dumps(readiness, indent=2), encoding="utf-8")
    (out / "tool-smoke.json").write_text(json.dumps(smoke, indent=2), encoding="utf-8")

asyncio.run(main())
PY

echo "[INFO] Generating text summary..."
REPO_ROOT="${REPO_ROOT}" python3 - <<'PY'
from pathlib import Path
import json
import os

repo = Path(os.environ["REPO_ROOT"])
report_dir = repo / "workspace" / "docker-audit" / "reports"

inventory = json.loads((report_dir / "tool-inventory.json").read_text(encoding="utf-8"))
readiness = json.loads((report_dir / "tool-readiness.json").read_text(encoding="utf-8"))
smoke = json.loads((report_dir / "tool-smoke.json").read_text(encoding="utf-8"))

ready = [r for r in readiness if r["ready"]]
not_ready = [r for r in readiness if not r["ready"]]
ok = [s for s in smoke if s["status"] == "ok"]
err = [s for s in smoke if s["status"] != "ok"]

lines = []
lines.append("Docker Audit Summary")
lines.append("===================")
lines.append(f"Available external tools: {len(inventory['available_tools'])}")
lines.append(f"Missing external tools: {len(inventory['missing_tools'])}")
lines.append(f"Available python modules: {len(inventory['available_python_modules'])}")
lines.append(f"Missing python modules: {len(inventory['missing_python_modules'])}")
lines.append("")
lines.append(f"MCP tools ready by dependency: {len(ready)} / {len(readiness)}")
lines.append(f"MCP smoke results (ok): {len(ok)} / {len(smoke)}")
lines.append(f"MCP smoke results (non-ok): {len(err)}")
lines.append("")
lines.append("Missing external tools:")
for t in inventory["missing_tools"]:
    lines.append(f"- {t}")
lines.append("")
lines.append("Dependency-not-ready MCP tools:")
for r in not_ready:
    lines.append(
        f"- {r['tool']} (missing_tools={r['missing_tools']}, missing_modules={r['missing_modules']})"
    )
lines.append("")
lines.append("Smoke non-ok MCP tools:")
for s in err:
    msg = s.get("message", "")
    lines.append(f"- {s['tool']} [{s['status']}] {msg}")

summary = "\n".join(lines) + "\n"
print(summary)
(report_dir / "summary.txt").write_text(summary, encoding="utf-8")
PY

echo "[INFO] Audit complete."
echo "[INFO] Reports: ${REPORT_DIR}"
echo "[INFO] Key files:"
echo "       - ${BUILD_LOG}"
echo "       - ${VALIDATE_LOG}"
echo "       - ${REPORT_DIR}/tool-inventory.json"
echo "       - ${REPORT_DIR}/tool-readiness.json"
echo "       - ${REPORT_DIR}/tool-smoke.json"
echo "       - ${SUMMARY_TXT}"
