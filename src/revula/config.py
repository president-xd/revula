"""
Revula Configuration — tool path detection, environment overrides, config file loading.

Detects available external tools at startup and provides a structured availability
report. Supports overrides via ~/.revula/config.toml and environment variables.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".revula"
CONFIG_FILE = CONFIG_DIR / "config.toml"
GHIDRA_PROJECTS_DIR = CONFIG_DIR / "ghidra_projects"
CACHE_DIR = CONFIG_DIR / "cache"


def _default_allowed_dirs() -> list[str]:
    """Return secure-by-default allowlisted directories."""
    defaults = [
        Path.home().resolve(strict=False),
        Path("/tmp").resolve(strict=False),
    ]
    deduped: list[str] = []
    for candidate in defaults:
        candidate_str = str(candidate)
        if candidate_str not in deduped:
            deduped.append(candidate_str)
    return deduped


# Environment variable overrides (key = env var, value = config path)
ENV_OVERRIDES: dict[str, str] = {
    "AAPT_PATH": "tools.aapt.path",
    "ADB_PATH": "tools.adb.path",
    "APKSIGNER_PATH": "tools.apksigner.path",
    "APKTOOL_PATH": "tools.apktool.path",
    "BAKSMALI_PATH": "tools.baksmali.path",
    "BINWALK_PATH": "tools.binwalk.path",
    "CAPA_PATH": "tools.capa.path",
    "CAPINFOS_PATH": "tools.capinfos.path",
    "CFR_PATH": "tools.cfr.path",
    "CHECKSEC_PATH": "tools.checksec.path",
    "CURL_PATH": "tools.curl.path",
    "DIEC_PATH": "tools.diec.path",
    "DRRUN_PATH": "tools.drrun.path",
    "FILE_PATH": "tools.file.path",
    "FLOSS_PATH": "tools.floss.path",
    "FRIDA_PATH": "tools.frida.path",
    "GDB_PATH": "tools.gdb.path",
    "GHIDRA_PATH": "tools.ghidra_headless.path",
    "GHIDRA_HEADLESS": "tools.ghidra_headless.path",
    "IKDASM_PATH": "tools.ikdasm.path",
    "JADX_PATH": "tools.jadx.path",
    "JAVA_PATH": "tools.java.path",
    "LLDB_PATH": "tools.lldb.path",
    "MONODIS_PATH": "tools.monodis.path",
    "MSFVENOM_PATH": "tools.msfvenom.path",
    "NM_PATH": "tools.nm.path",
    "OBJDUMP_PATH": "tools.objdump.path",
    "ONE_GADGET_PATH": "tools.one_gadget.path",
    "PDBUTIL_PATH": "tools.pdbutil.path",
    "QEMU_IMG_PATH": "tools.qemu_img.path",
    "QEMU_SYSTEM_PATH": "tools.qemu_system.path",
    "QEMU_USER_PATH": "tools.qemu_user.path",
    "QUARK_PATH": "tools.quark.path",
    "RADARE2_PATH": "tools.radare2.path",
    "READELF_PATH": "tools.readelf.path",
    "RETDEC_PATH": "tools.retdec_decompiler.path",
    "RIZIN_PATH": "tools.rizin.path",
    "ROPGADGET_PATH": "tools.ropgadget.path",
    "RZ_DIFF_PATH": "tools.rz_diff.path",
    "SEMGREP_PATH": "tools.semgrep.path",
    "SMALI_PATH": "tools.smali.path",
    "STRINGS_PATH": "tools.strings.path",
    "TSHARK_PATH": "tools.tshark.path",
    "UPX_PATH": "tools.upx.path",
    "WASM2WAT_PATH": "tools.wasm2wat.path",
    "REVULA_ALLOWED_DIRS": "security.allowed_dirs",
    "REVULA_MAX_MEMORY_MB": "security.max_memory_mb",
    "REVULA_DEFAULT_TIMEOUT": "security.default_timeout",
    "REVULA_MAX_TIMEOUT": "security.max_timeout",
}

# Tools to probe via shutil.which()
TOOL_BINARIES: dict[str, list[str]] = {
    "adb": ["adb"],
    "apksigner": ["apksigner"],
    "baksmali": ["baksmali"],
    "ghidra_headless": ["analyzeHeadless", "analyzeHeadless.bat"],
    "drrun": ["drrun", "drrun.exe"],
    "java": ["java", "javap", "jarsigner", "keytool"],
    "radare2": ["r2", "radare2"],
    "rizin": ["rizin", "rz", "rz-bin"],
    "gdb": ["gdb"],
    "lldb": ["lldb", "lldb-19", "lldb-18", "lldb-17"],
    "objdump": ["objdump", "llvm-objdump", "llvm-objdump-19"],
    "strings": ["strings"],
    "floss": ["floss"],
    "capa": ["capa"],
    "upx": ["upx"],
    "jadx": ["jadx"],
    "apktool": ["apktool"],
    "cfr": ["cfr"],
    "retdec_decompiler": ["retdec-decompiler", "retdec-decompiler.py"],
    "aapt": ["aapt", "aapt2"],
    "binwalk": ["binwalk"],
    "capinfos": ["capinfos"],
    "checksec": ["checksec"],
    "curl": ["curl"],
    "diec": ["diec"],
    "file": ["file"],
    "ikdasm": ["ikdasm", "ildasm"],
    "monodis": ["monodis"],
    "msfvenom": ["msfvenom"],
    "nm": ["nm", "llvm-nm"],
    "one_gadget": ["one_gadget"],
    "qemu_system": [
        "qemu-system-x86_64",
        "qemu-system-i386",
        "qemu-system-aarch64",
        "qemu-system-arm",
        "qemu-system-mips",
        "qemu-system-riscv64",
    ],
    "qemu_user": [
        "qemu-x86_64",
        "qemu-i386",
        "qemu-aarch64",
        "qemu-arm",
        "qemu-mips",
        "qemu-mipsel",
        "qemu-mips64",
        "qemu-ppc",
        "qemu-ppc64",
        "qemu-riscv32",
        "qemu-riscv64",
        "qemu-sparc",
        "qemu-s390x",
    ],
    "qemu_img": ["qemu-img"],
    "quark": ["quark"],
    "readelf": ["readelf", "llvm-readelf"],
    "ropgadget": ["ROPgadget", "ropper"],
    "rz_diff": ["rz-diff"],
    "semgrep": ["semgrep"],
    "smali": ["smali"],
    "tshark": ["tshark"],
    "wasm2wat": ["wasm2wat"],
    "pdbutil": [
        "llvm-pdbutil",
        "llvm-pdbutil-20",
        "llvm-pdbutil-19",
        "llvm-pdbutil-18",
        "llvm-pdbutil-17",
        "llvm-pdbutil-16",
        "llvm-pdbutil-15",
        "llvm-pdbutil-14",
    ],
}

# Backward-compatible aliases for legacy config file key names.
TOOL_OVERRIDE_ALIASES: dict[str, list[str]] = {
    "ghidra_headless": ["ghidra"],
    "retdec_decompiler": ["retdec"],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ToolInfo:
    """Information about an external tool."""

    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    install_hint: str = ""


@dataclass
class SecurityConfig:
    """Security-related configuration."""

    allowed_dirs: list[str] = field(default_factory=_default_allowed_dirs)
    max_memory_mb: int = 512
    default_timeout: int = 60
    max_timeout: int = 600


@dataclass
class ServerConfig:
    """Top-level server configuration."""

    tools: dict[str, ToolInfo] = field(default_factory=dict)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    platform: str = ""
    arch: str = ""
    python_modules: dict[str, bool] = field(default_factory=dict)
    _raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def tool_path(self, name: str) -> str | None:
        """Get the resolved path for a tool, or None if unavailable."""
        info = self.tools.get(name)
        return info.path if info and info.available else None

    def is_available(self, name: str) -> bool:
        """Check if a tool or Python module is available."""
        if name in self.tools:
            return self.tools[name].available
        return self.python_modules.get(name, False)

    def require_tool(self, name: str) -> str:
        """Get tool path or raise with install instructions."""
        info = self.tools.get(name)
        if info and info.available and info.path:
            return info.path
        hint = info.install_hint if info else f"Tool '{name}' is not configured."
        raise ToolNotAvailableError(name, hint)


class ToolNotAvailableError(Exception):
    """Raised when a required external tool is not installed."""

    def __init__(self, tool_name: str, install_hint: str = "") -> None:
        self.tool_name = tool_name
        self.install_hint = install_hint
        msg = f"Tool '{tool_name}' is not available."
        if install_hint:
            msg += f" Install: {install_hint}"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Install hints
# ---------------------------------------------------------------------------

INSTALL_HINTS: dict[str, str] = {
    "adb": "Install Android platform tools (adb): `sudo apt install adb`",
    "apksigner": "Install apksigner: `sudo apt install apksigner`",
    "baksmali": "Install smali/baksmali: https://github.com/JesusFreke/smali",
    "ghidra_headless": "Download Ghidra from https://ghidra-sre.org/ and add to PATH",
    "drrun": "Install DynamoRIO and add drrun to PATH: https://dynamorio.org/",
    "java": "Install JDK (java/javap/jarsigner/keytool): `sudo apt install default-jdk`",
    "radare2": "Install: https://github.com/radareorg/radare2 or `brew install radare2`",
    "rizin": "Install: https://rizin.re/ or `brew install rizin`",
    "gdb": "Install: `sudo apt install gdb` or `brew install gdb`",
    "lldb": "Install: `sudo apt install lldb` or comes with Xcode CLI tools on macOS",
    "objdump": "Install: `sudo apt install binutils` (usually pre-installed on Linux)",
    "strings": "Install: `sudo apt install binutils` (usually pre-installed on Linux)",
    "floss": "Install: `pip install flare-floss` or download from https://github.com/mandiant/flare-floss",
    "capa": "Install: `pip install flare-capa` or download from https://github.com/mandiant/capa",
    "upx": "Install from https://github.com/upx/upx/releases (or package manager if available)",
    "jadx": "Install: `brew install jadx` or download from https://github.com/skylot/jadx",
    "apktool": "Install: `brew install apktool` or download from https://ibotpeaches.github.io/Apktool/",
    "cfr": "Download cfr.jar from https://www.benf.org/other/cfr/ and wrap it as `cfr` command",
    "retdec_decompiler": "Install RetDec from https://github.com/avast/retdec/releases",
    "aapt": "Install Android build-tools (aapt/aapt2) via Android SDK manager",
    "binwalk": "Install: `pip install binwalk` or distro package `binwalk`",
    "capinfos": "Install Wireshark tools: `sudo apt install wireshark-common`",
    "checksec": "Install checksec: `sudo apt install checksec` or distro equivalent",
    "curl": "Install curl: `sudo apt install curl`",
    "diec": "Install Detect It Easy CLI from https://github.com/horsicq/DIE-engine/releases",
    "file": "Install file utility: `sudo apt install file`",
    "ikdasm": "Install Mono tools (`ikdasm`/`ildasm`): `sudo apt install mono-utils`",
    "monodis": "Install mono-utils: `sudo apt install mono-utils`",
    "msfvenom": "Install Metasploit Framework (provides msfvenom), e.g. apt.metasploit.com repo on Debian/Ubuntu",
    "nm": "Install binutils (nm): `sudo apt install binutils`",
    "one_gadget": "Install one_gadget: `gem install one_gadget`",
    "qemu_system": "Install QEMU system emulators: `sudo apt install qemu-system`",
    "qemu_user": "Install QEMU user emulators: `sudo apt install qemu-user`",
    "qemu_img": "Install qemu-utils: `sudo apt install qemu-utils`",
    "quark": "Install Quark Engine: `pip install quark-engine`",
    "readelf": "Install binutils (readelf): `sudo apt install binutils`",
    "ropgadget": "Install ROP tools: `pip install ROPGadget ropper`",
    "rz_diff": "Install Rizin diff tooling (`rz-diff`) from https://rizin.re/",
    "semgrep": "Install Semgrep: `pip install semgrep`",
    "smali": "Install smali assembler: https://github.com/JesusFreke/smali",
    "tshark": "Install tshark: `sudo apt install tshark`",
    "wasm2wat": "Install WABT tools (`wasm2wat`): `sudo apt install wabt`",
    "pdbutil": "Install LLVM: `sudo apt install llvm` or `brew install llvm`",
}

# Python modules to probe
PYTHON_MODULES: dict[str, str] = {
    "capstone": "pip install capstone",
    "lief": "pip install lief",
    "pefile": "pip install pefile",
    "elftools": "pip install pyelftools",
    "yara": "pip install yara-python",
    "r2pipe": "pip install r2pipe",
    "frida": "pip install frida frida-tools",
    "angr": "pip install angr",
    "unicorn": "pip install unicorn",
    "lldb": "Install matching python3-lldb package for your Python version and ensure it is on PYTHONPATH",
    "triton": "Build Triton from source: https://github.com/JonathanSalwan/Triton (PyPI triton is unrelated)",
    "scapy": "pip install scapy",
    "tlsh": "pip install python-tlsh",
    "ssdeep": "pip install ppdeep  # or ssdeep (C-ext, may not build on Python 3.13)",
    "uncompyle6": "pip install uncompyle6",
    "semgrep": "pip install semgrep",
    "quark": "pip install quark-engine",
}


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _load_config_file() -> dict[str, Any]:
    """Load config from ~/.revula/config.toml if it exists."""
    if not CONFIG_FILE.exists():
        return {}

    try:
        import tomllib

        with open(CONFIG_FILE, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        logger.warning("Failed to load config from %s: %s", CONFIG_FILE, e)
        return {}


def _resolve_nested(data: dict[str, Any], dotpath: str) -> Any | None:
    """Resolve a dot-separated path in a nested dict."""
    parts = dotpath.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _probe_tool(name: str, candidates: list[str], overrides: dict[str, Any]) -> ToolInfo:
    """Probe for a tool binary, checking overrides first."""
    # Check config overrides (including backward-compatible aliases)
    override_keys = [f"tools.{name}.path"]
    for legacy_name in TOOL_OVERRIDE_ALIASES.get(name, []):
        override_keys.append(f"tools.{legacy_name}.path")

    for override_key in override_keys:
        override_path = _resolve_nested(overrides, override_key)
        if override_path and isinstance(override_path, str):
            resolved = Path(override_path).expanduser()
            if resolved.exists() and os.access(str(resolved), os.X_OK):
                return ToolInfo(
                    name=name,
                    available=True,
                    path=str(resolved),
                    install_hint=INSTALL_HINTS.get(name, ""),
                )

    # Check env vars
    for env_var, config_path in ENV_OVERRIDES.items():
        if config_path in override_keys:
            env_val = os.environ.get(env_var)
            if env_val:
                resolved = Path(env_val).expanduser()
                if resolved.exists() and os.access(str(resolved), os.X_OK):
                    return ToolInfo(
                        name=name,
                        available=True,
                        path=str(resolved),
                        install_hint=INSTALL_HINTS.get(name, ""),
                    )

    # Probe PATH
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return ToolInfo(
                name=name,
                available=True,
                path=found,
                install_hint=INSTALL_HINTS.get(name, ""),
            )

    return ToolInfo(
        name=name,
        available=False,
        install_hint=INSTALL_HINTS.get(name, ""),
    )


def _probe_python_module(module_name: str) -> bool:
    """Check if a Python module is importable (fast, no actual import)."""
    import importlib.util

    # Fallback mapping: if primary module is missing, try alternative
    fallbacks: dict[str, str] = {
        "ssdeep": "ppdeep",  # pure-Python ssdeep alternative
    }

    try:
        if importlib.util.find_spec(module_name) is not None:
            return True
    except (ModuleNotFoundError, ValueError) as e:
        logger.debug("Module probe failed for %s: %s", module_name, e)

    # Try fallback
    alt = fallbacks.get(module_name)
    if alt:
        try:
            return importlib.util.find_spec(alt) is not None
        except (ModuleNotFoundError, ValueError) as e:
            logger.debug("Fallback module probe failed for %s via %s: %s", module_name, alt, e)

    return False


def _load_security_config(raw: dict[str, Any]) -> SecurityConfig:
    """Load security config from raw config dict + env vars."""
    sec = SecurityConfig()

    def _parse_int(value: Any, field_name: str, *, minimum: int = 1) -> int | None:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            logger.warning("Invalid security config for %s: %r", field_name, value)
            return None
        if parsed < minimum:
            logger.warning(
                "Invalid security config for %s: %r (must be >= %d)",
                field_name,
                value,
                minimum,
            )
            return None
        return parsed

    # From config file
    sec_raw = raw.get("security", {})
    if isinstance(sec_raw, dict):
        if "allowed_dirs" in sec_raw:
            raw_allowed = sec_raw["allowed_dirs"]
            if isinstance(raw_allowed, list):
                parsed_allowed = [str(d).strip() for d in raw_allowed if str(d).strip()]
                if parsed_allowed:
                    sec.allowed_dirs = parsed_allowed
                else:
                    logger.warning("security.allowed_dirs is empty; keeping secure defaults")
            else:
                logger.warning(
                    "Invalid security.allowed_dirs value (expected list): %r",
                    raw_allowed,
                )
        if "max_memory_mb" in sec_raw:
            parsed = _parse_int(sec_raw["max_memory_mb"], "security.max_memory_mb")
            if parsed is not None:
                sec.max_memory_mb = parsed
        if "default_timeout" in sec_raw:
            parsed = _parse_int(sec_raw["default_timeout"], "security.default_timeout")
            if parsed is not None:
                sec.default_timeout = parsed
        if "max_timeout" in sec_raw:
            parsed = _parse_int(sec_raw["max_timeout"], "security.max_timeout")
            if parsed is not None:
                sec.max_timeout = parsed

    # Env var overrides
    allowed = os.environ.get("REVULA_ALLOWED_DIRS")
    if allowed:
        parsed_allowed = [d.strip() for d in allowed.split(":") if d.strip()]
        if parsed_allowed:
            sec.allowed_dirs = parsed_allowed
        else:
            logger.warning("REVULA_ALLOWED_DIRS produced an empty allowlist; keeping secure defaults")

    mem = os.environ.get("REVULA_MAX_MEMORY_MB")
    if mem:
        parsed = _parse_int(mem, "REVULA_MAX_MEMORY_MB")
        if parsed is not None:
            sec.max_memory_mb = parsed

    timeout = os.environ.get("REVULA_DEFAULT_TIMEOUT")
    if timeout:
        parsed = _parse_int(timeout, "REVULA_DEFAULT_TIMEOUT")
        if parsed is not None:
            sec.default_timeout = parsed

    max_timeout = os.environ.get("REVULA_MAX_TIMEOUT")
    if max_timeout:
        parsed = _parse_int(max_timeout, "REVULA_MAX_TIMEOUT")
        if parsed is not None:
            sec.max_timeout = parsed

    if sec.max_timeout < sec.default_timeout:
        logger.warning(
            "security.max_timeout (%d) is less than default_timeout (%d); using default_timeout",
            sec.max_timeout,
            sec.default_timeout,
        )
        sec.max_timeout = sec.default_timeout

    return sec


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config() -> ServerConfig:
    """
    Load full server configuration.

    Order of precedence (highest first):
    1. Environment variables
    2. ~/.revula/config.toml
    3. Auto-detection via PATH
    """
    raw = _load_config_file()

    # Ensure directories exist
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    GHIDRA_PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Probe external tools
    tools: dict[str, ToolInfo] = {}
    for name, candidates in TOOL_BINARIES.items():
        tools[name] = _probe_tool(name, candidates, raw)

    # Probe Python modules
    python_modules: dict[str, bool] = {}
    for mod_name in PYTHON_MODULES:
        python_modules[mod_name] = _probe_python_module(mod_name)

    # Security config
    security = _load_security_config(raw)

    config = ServerConfig(
        tools=tools,
        security=security,
        platform=platform.system().lower(),
        arch=platform.machine().lower(),
        python_modules=python_modules,
        _raw=raw,
    )

    return config


def format_availability_report(config: ServerConfig) -> str:
    """Generate a human-readable tool availability report."""
    lines = [
        "╔══════════════════════════════════════════════════════╗",
        "║            Revula Tool Availability Report           ║",
        "╠══════════════════════════════════════════════════════╣",
        f"║  Platform: {config.platform:<12} Arch: {config.arch:<18} ║",
        "╠══════════════════════════════════════════════════════╣",
        "║  EXTERNAL TOOLS                                      ║",
        "╠══════════════════════════════════════════════════════╣",
    ]

    for name, info in sorted(config.tools.items()):
        status = "✓" if info.available else "✗"
        path_str = info.path or "not found"
        # Truncate path for display
        if len(path_str) > 38:
            path_str = "..." + path_str[-35:]
        lines.append(f"║  {status} {name:<20} {path_str:<30} ║")

    lines.extend(
        [
            "╠══════════════════════════════════════════════════════╣",
            "║  PYTHON MODULES                                      ║",
            "╠══════════════════════════════════════════════════════╣",
        ]
    )

    for mod_name, available in sorted(config.python_modules.items()):
        status = "✓" if available else "✗"
        hint = "" if available else PYTHON_MODULES.get(mod_name, "")
        if len(hint) > 30:
            hint = hint[:27] + "..."
        lines.append(f"║  {status} {mod_name:<20} {hint:<30} ║")

    lines.append("╚══════════════════════════════════════════════════════╝")
    return "\n".join(lines)


# Module-level singleton (lazy init)
_config: ServerConfig | None = None


def get_config() -> ServerConfig:
    """Get or create the global config singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> ServerConfig:
    """Force-reload configuration."""
    global _config
    _config = load_config()
    return _config
