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

# Environment variable overrides (key = env var, value = config path)
ENV_OVERRIDES: dict[str, str] = {
    "GHIDRA_PATH": "tools.ghidra.path",
    "GHIDRA_HEADLESS": "tools.ghidra.headless_path",
    "RETDEC_PATH": "tools.retdec.path",
    "RADARE2_PATH": "tools.radare2.path",
    "RIZIN_PATH": "tools.rizin.path",
    "GDB_PATH": "tools.gdb.path",
    "LLDB_PATH": "tools.lldb.path",
    "FRIDA_PATH": "tools.frida.path",
    "FLOSS_PATH": "tools.floss.path",
    "CAPA_PATH": "tools.capa.path",
    "UPX_PATH": "tools.upx.path",
    "JADX_PATH": "tools.jadx.path",
    "APKTOOL_PATH": "tools.apktool.path",
    "CFR_PATH": "tools.cfr.path",
    "OBJDUMP_PATH": "tools.objdump.path",
    "STRINGS_PATH": "tools.strings.path",
    "REVULA_ALLOWED_DIRS": "security.allowed_dirs",
    "REVULA_MAX_MEMORY_MB": "security.max_memory_mb",
    "REVULA_DEFAULT_TIMEOUT": "security.default_timeout",
}

# Tools to probe via shutil.which()
TOOL_BINARIES: dict[str, list[str]] = {
    "ghidra_headless": ["analyzeHeadless", "analyzeHeadless.bat"],
    "radare2": ["r2", "radare2"],
    "rizin": ["rizin", "rz"],
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
    "pdbutil": ["llvm-pdbutil", "llvm-pdbutil-19", "llvm-pdbutil-18", "llvm-pdbutil-17"],
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

    allowed_dirs: list[str] = field(default_factory=lambda: ["/"])
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
    "ghidra_headless": "Download Ghidra from https://ghidra-sre.org/ and add to PATH",
    "radare2": "Install: https://github.com/radareorg/radare2 or `brew install radare2`",
    "rizin": "Install: https://rizin.re/ or `brew install rizin`",
    "gdb": "Install: `sudo apt install gdb` or `brew install gdb`",
    "lldb": "Install: `sudo apt install lldb` or comes with Xcode CLI tools on macOS",
    "objdump": "Install: `sudo apt install binutils` (usually pre-installed on Linux)",
    "strings": "Install: `sudo apt install binutils` (usually pre-installed on Linux)",
    "floss": "Install: `pip install flare-floss` or download from https://github.com/mandiant/flare-floss",
    "capa": "Install: `pip install flare-capa` or download from https://github.com/mandiant/capa",
    "upx": "Install: `sudo apt install upx-ucl` or `brew install upx`",
    "jadx": "Install: `brew install jadx` or download from https://github.com/skylot/jadx",
    "apktool": "Install: `brew install apktool` or download from https://ibotpeaches.github.io/Apktool/",
    "cfr": "Download from https://www.benf.org/other/cfr/",
    "retdec_decompiler": "Install from https://github.com/avast/retdec",
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
    "triton": "pip install triton",
    "scapy": "pip install scapy",
    "tlsh": "pip install python-tlsh",
    "ssdeep": "pip install ppdeep  # or ssdeep (C-ext, may not build on Python 3.13)",
    "uncompyle6": "pip install uncompyle6",
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
    # Check config overrides
    override_path = _resolve_nested(overrides, f"tools.{name}.path")
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
        if config_path == f"tools.{name}.path":
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
    except (ModuleNotFoundError, ValueError):
        pass

    # Try fallback
    alt = fallbacks.get(module_name)
    if alt:
        try:
            return importlib.util.find_spec(alt) is not None
        except (ModuleNotFoundError, ValueError):
            pass

    return False


def _load_security_config(raw: dict[str, Any]) -> SecurityConfig:
    """Load security config from raw config dict + env vars."""
    sec = SecurityConfig()

    # From config file
    sec_raw = raw.get("security", {})
    if isinstance(sec_raw, dict):
        if "allowed_dirs" in sec_raw:
            sec.allowed_dirs = [str(d) for d in sec_raw["allowed_dirs"]]
        if "max_memory_mb" in sec_raw:
            sec.max_memory_mb = int(sec_raw["max_memory_mb"])
        if "default_timeout" in sec_raw:
            sec.default_timeout = int(sec_raw["default_timeout"])
        if "max_timeout" in sec_raw:
            sec.max_timeout = int(sec_raw["max_timeout"])

    # Env var overrides
    allowed = os.environ.get("REVULA_ALLOWED_DIRS")
    if allowed:
        sec.allowed_dirs = [d.strip() for d in allowed.split(":") if d.strip()]

    mem = os.environ.get("REVULA_MAX_MEMORY_MB")
    if mem:
        sec.max_memory_mb = int(mem)

    timeout = os.environ.get("REVULA_DEFAULT_TIMEOUT")
    if timeout:
        sec.default_timeout = int(timeout)

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

    lines.extend([
        "╠══════════════════════════════════════════════════════╣",
        "║  PYTHON MODULES                                      ║",
        "╠══════════════════════════════════════════════════════╣",
    ])

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
