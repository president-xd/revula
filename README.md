# revula

**Production-grade MCP server for universal reverse engineering automation.**

Connect Claude Desktop, MCP-compatible IDEs, or custom tooling to a complete reverse engineering backend. One server, every RE tool, orchestrated through the [Model Context Protocol](https://modelcontextprotocol.io/).

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
  - [Docker Installation](#docker-installation-alternative)
- [IDE & Client Setup](#ide--client-setup)
  - [How It Connects (Important)](#how-it-connects-important)
  - [Claude Desktop](#1-claude-desktop)
  - [Claude Code (CLI)](#2-claude-code-cli)
  - [VS Code (GitHub Copilot)](#3-vs-code-github-copilot)
  - [Cursor](#4-cursor)
  - [Windsurf (Codeium)](#5-windsurf-codeium)
  - [Continue.dev](#6-continuedev)
  - [Zed](#7-zed)
  - [Custom / Other Clients](#8-custom--other-clients)
  - [Universal Setup Script](#universal-setup-script)
- [Configuration](#configuration)
- [Tool Availability](#tool-availability)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Testing](#testing)
- [Scripts & Automation](#scripts--automation)
- [Usage Examples](#usage-examples)
- [Performance & Limitations](#performance--limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Static Analysis (8 tools)
- **Binary Parsing:** PE/ELF/Mach-O via LIEF with hash computation and suspicious indicator detection
- **Disassembly:** Multi-backend support including Capstone (always available), radare2, and objdump for x86/x64/ARM/MIPS/RISC-V
- **String Extraction:** FLOSS integration, regex fallback, 17 classifier patterns (URLs, IPs, crypto, registry keys)
- **Entropy Analysis:** Shannon entropy with sliding window, per-section analysis, and packing detection
- **Symbol Extraction:** DWARF, PDB, LIEF universal; function prologue scanning for stripped binaries
- **YARA Scanning:** Inline rules, file/directory rules, and community rules support
- **Capa Integration:** ATT&CK mapping, MBC behaviors, capability enumeration
- **Decompilation:** Ghidra (headless), RetDec, Binary Ninja with caching

### Dynamic Analysis (29 tools)
- **GDB Adapter:** Full GDB/MI protocol with breakpoints, stepping, registers, memory, backtrace, and heap inspection
- **LLDB Adapter:** Native SB API integration for macOS/Linux debugging
- **Frida Adapter:** Spawn/attach, script injection, function interception, memory scan/dump, and RPC exports
- **Code Coverage:** DynamoRIO drcov, Frida Stalker block tracing, and coverage analysis

### Android RE (24 tools)
- **APK Parsing:** Manifest extraction, permission analysis, component enumeration, and resource inspection
- **DEX Analysis:** Class/method listing, bytecode stats, and string extraction
- **Decompilation:** jadx/apktool integration, smali disassembly/assembly/patching
- **Native Binary Analysis:** ARM/AArch64 .so analysis with JNI detection
- **Device Interaction:** ADB bridge with 12 actions (logcat, install, shell, dumpsys, screenshot)
- **Frida for Android:** Root bypass, crypto hooking, SSL pinning bypass, API tracing, and memory dump
- **Traffic Interception:** tcpdump/mitmproxy integration with SSL key extraction
- **Repack and Sign:** APK rebuild with smali patches, zipalign + apksigner
- **Security Scanners:** MobSF, Quark-Engine, Semgrep, and manifest vulnerability detection

### Cross-Platform RE Tools (7 tools)
- **Rizin/r2:** Automated analysis with 13 actions and binary diffing
- **GDB Enhanced:** Heap analysis, ROP gadget finding, exploit helpers (pattern create/find, checksec)
- **QEMU:** User-mode emulation (4 actions) and full system emulation (5 actions)

### Exploit Development (11 tools)
- **ROP Chain Builder:** Multi-architecture gadget finding (x86/x64/ARM/ARM64) with semantic classification, automatic chain generation for execve/mprotect/syscalls, bad-char avoidance, and pwntools script generation
- **Heap Exploitation:** Malloc chunk analysis, bin classification (tcache/fastbin/smallbin/largebin), fake chunk generation, safe-linking encode/decode for glibc 2.32+, and technique templates (House of Force, Tcache Poisoning, Fastbin Dup, Unsafe Unlink)
- **Libc Database:** Symbol/offset extraction, libc identification from leaked addresses, ASLR defeat helpers (base calculation, GOT-to-libc, PLT-to-GOT), and one-gadget RCE finder
- **Shellcode:** Generation, encoding, bad-char analysis, extraction, and emulation testing
- **Format String:** Offset calculation, write payload generation, GOT overwrite, and address leaking

### Anti-Analysis (2 tools)
- **Detection:** Scan for anti-debug, anti-VM, anti-tamper, and packing indicators
- **Bypass Generation:** Frida/GDB/patch/LD_PRELOAD scripts for ptrace, IsDebuggerPresent, timing, and VM checks

### Malware Analysis (4 tools)
- **Triage:** Multi-hash, IoC extraction, suspicious import scoring, and risk assessment
- **Sandbox Queries:** VirusTotal, Hybrid Analysis, and MalwareBazaar API integration
- **YARA Generation:** Auto-generate YARA rules from binary artifacts
- **Config Extraction:** C2 URLs, IPs, domains, encryption keys, and mutexes

### Firmware RE (3 tools)
- **Extraction:** binwalk scan/extract, entropy analysis, and filesystem identification
- **Vulnerability Scanning:** Hardcoded credentials, known CVEs, unsafe functions, and weak crypto
- **Base Address Detection:** String reference analysis for firmware base address recovery

### Protocol RE (3 tools)
- **PCAP Analysis:** tshark-based with 8 actions (summary, flows, DNS, HTTP, TLS, filter, export, IoC)
- **Protocol Dissection:** Binary structure inference, field boundary detection, and pattern analysis
- **Protocol Fuzzing:** Mutation-based, boundary testing, field-specific, and template fuzzing

### Unpacking (4 tools)
- **Packer Detection:** UPX, Themida, VMProtect, ASPack, PECompact, MPRESS, and more
- **UPX Unpacking:** Static unpacking with automatic backup
- **Dynamic Unpacking:** Frida-based memory dump with OEP detection
- **PE Rebuild:** Fix section alignments, imports, and entry point after memory dump

### Deobfuscation (3 tools)
- **String Deobfuscation:** XOR brute force, ROT variants, Base64, RC4, and stack string reconstruction
- **Control Flow Flattening Detection:** OLLVM-style CFF pattern identification
- **Opaque Predicate Detection:** Always-true/false branch identification

### Symbolic Execution (4 tools)
- **angr Integration:** Path exploration, constraint solving, CFG generation, and vulnerability scanning
- **Triton DSE:** Dynamic symbolic execution with concrete and symbolic state

### Binary Format Specializations (4 tools)
- **APK/DEX:** Android analysis including manifest, permissions, native libs, and DEX parsing
- **.NET IL:** Assembly metadata, type/method listing, and IL disassembly
- **Java Class:** Class file parsing, javap integration, and bytecode disassembly
- **WebAssembly:** WASM section parsing, import/export extraction, and disassembly

### Utilities (8 tools)
- **Hex Tools:** Hexdump, pattern search (IDA-style wildcards), and binary diff
- **Crypto:** Hashing (MD5/SHA/TLSH/ssdeep), XOR analysis, and crypto constant scanning
- **Patching:** Binary patching with backup and NOP-sled support
- **Network:** PCAP analysis with protocol stats, DNS extraction, and C2 beacon detection

### Admin (2 tools)
- **Server Status:** Version, tool count, cache stats, rate limit stats, and available tools
- **Cache Management:** View stats, clear cache, and invalidate specific entries

---

## Quick Start

### Prerequisites

- Python 3.11 or later
- Linux recommended (macOS and WSL2 supported)
- `pip` (or `uv` / `pipx` for isolated installs)

### Install

```bash
# Clone
git clone https://github.com/president-xd/revula.git
cd revula

# Option 1: Automated install (recommended)
bash scripts/install/install_all.sh

# Option 2: Manual install
pip install -e .

# Option 3: Install with all optional dependencies
pip install -e ".[full]"

# Verify installation
python scripts/test/validate_install.py
```

The automated installer handles Python version checks, virtual environment creation, dependency installation, external tool detection, and configuration file generation.

### Verify What's Available

```bash
python -c "from revula.config import get_config, format_availability_report; print(format_availability_report(get_config()))"
```

This prints a table showing which external tools and Python modules are detected on your system.

### Docker Installation (Alternative)

Revula can be run in Docker for an isolated, stdio-only environment with core and common optional dependencies pre-configured:

```bash
# Build the Docker image
docker build -t revula:latest .

# Quick test
docker run --rm revula:latest python -c "import revula; print(revula.__version__)"
docker run --rm revula:latest python -c "from revula.server import _register_all_tools; from revula.tools import TOOL_REGISTRY; _register_all_tools(); print(TOOL_REGISTRY.count())"

# Run in stdio mode (for local MCP clients)
docker run -i --rm -v $(pwd)/workspace:/workspace -v revula-data:/root/.revula revula:latest

# Revula transport is stdio-only (no HTTP/SSE mode)
# Run it attached to your MCP client process
# (for Docker usage, run your MCP client inside the same container/environment)
```

**What's included in the Docker image:**
- All core Python dependencies (capstone, LIEF, pefile, yara)
- angr symbolic execution engine
- Frida dynamic instrumentation
- Ghidra headless analyzer
- GDB, radare2, rizin, binutils
- ADB and Android tools (apktool, jadx)
- FLARE tools (FLOSS, capa)
- Network analysis tools (tcpdump, tshark)

**Testing the Docker build:**
```bash
./scripts/docker/test.sh
```

For complete Docker documentation (stdio mode, volumes, compose usage, and troubleshooting), see **[DOCKER.md](DOCKER.md)**.

**Note on Docker vs Native:**
- Docker provides an isolated environment with core tooling pre-installed
- Native installation offers better performance and direct system access
- Choose based on your security and portability requirements

---

## IDE & Client Setup

### How It Connects (Important)

**Revula uses stdio transport only.** The server reads JSON-RPC from stdin and writes to stdout. Every MCP client listed below launches revula as a local subprocess. There is no HTTP server, no SSE endpoint, and no remote connection.

**What this means for you:**
- Revula must be installed on the **same machine** where your IDE/client runs.
- If you use a remote server or Docker, you must run both the client and revula inside the same environment (or use SSH piping; see [Custom / Other Clients](#8-custom--other-clients)).
- Every client below uses the same `revula` command. The only difference is _where_ you put the config.

### Before You Start

Make sure revula is installed and the command works:

```bash
# Should print the MCP protocol handshake (Ctrl+C to exit)
revula

# If you installed in a venv, activate it first:
source /path/to/venv/bin/activate
revula

# Or use the full path:
/path/to/venv/bin/revula
```

If `revula` is not in your PATH, use the full path in every config below.

---

### 1. Claude Desktop

**Status:** Fully supported. This is the primary client.

**Config file locations:**

| Platform | Path |
|----------|------|
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| WSL2 | `/mnt/c/Users/<YOU>/AppData/Roaming/Claude/claude_desktop_config.json` |

**Option A: Automatic setup (recommended)**

```bash
python scripts/setup/setup_claude_desktop.py
```

This auto-detects your OS, finds the config file, and merges the revula entry. It creates a backup first.

**Option B: Manual setup**

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "revula": {
      "command": "revula",
      "args": []
    }
  }
}
```

If revula is in a virtualenv:

```json
{
  "mcpServers": {
    "revula": {
      "command": "/home/you/venvs/revula/bin/revula",
      "args": []
    }
  }
}
```

If using `uvx` (zero-install):

```json
{
  "mcpServers": {
    "revula": {
      "command": "uvx",
      "args": ["revula"]
    }
  }
}
```

**After editing:** Quit and reopen Claude Desktop. Check the MCP tools icon to confirm 116 tools are available.

---

### 2. Claude Code (CLI)

**Status:** Fully supported.

**Option A: CLI command (recommended)**

```bash
claude mcp add revula -- revula
```

Claude Code will start revula as a subprocess when needed.

**Option B: Manual config**

Edit `~/.claude.json` (or `~/.claude/settings.json` depending on version):

```json
{
  "mcpServers": {
    "revula": {
      "command": "revula",
      "args": []
    }
  }
}
```

---

### 3. VS Code (GitHub Copilot)

**Status:** Supported. Requires GitHub Copilot extension with MCP support (VS Code 1.99+).

**Important:** MCP support in VS Code is available through the GitHub Copilot Chat extension. Make sure you have:
- VS Code 1.99 or later
- GitHub Copilot extension installed and active
- MCP enabled in settings: `"chat.mcp.enabled": true`

**Option A: Workspace config (already included in this repo)**

This repo ships with `.vscode/mcp.json`:

```json
{
  "servers": {
    "revula": {
      "command": "revula",
      "args": [],
      "env": {}
    }
  }
}
```

Just open this project in VS Code and Copilot will discover the MCP server automatically.

**Option B: User-level config (global, all projects)**

Open VS Code settings (`Ctrl+,`) → search "mcp" → edit `settings.json`:

```json
{
  "chat.mcp.enabled": true,
  "mcp": {
    "servers": {
      "revula": {
        "command": "revula",
        "args": [],
        "env": {}
      }
    }
  }
}
```

**Option C: Create `.vscode/mcp.json` in any project**

Copy the file from this repo or create it manually:

```bash
mkdir -p .vscode
cat > .vscode/mcp.json << 'EOF'
{
  "servers": {
    "revula": {
      "command": "revula",
      "args": [],
      "env": {}
    }
  }
}
EOF
```

**After editing:** Reload VS Code window (`Ctrl+Shift+P` → "Developer: Reload Window"). The MCP tools should appear in Copilot Chat.

---

### 4. Cursor

**Status:** Supported. Cursor has built-in MCP support.

**Config file:** `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project).

This repo ships with `.cursor/mcp.json` for per-project use.

**Option A: Per-project (already included)**

The `.cursor/mcp.json` in this repo:

```json
{
  "mcpServers": {
    "revula": {
      "command": "revula",
      "args": []
    }
  }
}
```

**Option B: Global config**

```bash
mkdir -p ~/.cursor
cat > ~/.cursor/mcp.json << 'EOF'
{
  "mcpServers": {
    "revula": {
      "command": "revula",
      "args": []
    }
  }
}
EOF
```

**After editing:** Restart Cursor. Check Settings → MCP to verify revula appears.

---

### 5. Windsurf (Codeium)

**Status:** Supported. Windsurf Cascade supports MCP servers.

**Config file:** `~/.codeium/windsurf/mcp_config.json`

```bash
mkdir -p ~/.codeium/windsurf
cat > ~/.codeium/windsurf/mcp_config.json << 'EOF'
{
  "mcpServers": {
    "revula": {
      "command": "revula",
      "args": []
    }
  }
}
EOF
```

**After editing:** Restart Windsurf. The Cascade panel should show revula tools.

---

### 6. Continue.dev

**Status:** Supported. Continue has MCP support in recent versions.

**Config file:** `~/.continue/config.json`

Add to your existing `config.json`:

```json
{
  "mcpServers": [
    {
      "name": "revula",
      "command": "revula",
      "args": []
    }
  ]
}
```

If you use `config.yaml`:

```yaml
mcpServers:
  - name: revula
    command: revula
    args: []
```

**After editing:** Restart your IDE. Continue should detect the MCP server.

---

### 7. Zed

**Status:** Supported. Zed has native MCP support via context servers.

**Config file:** `~/.config/zed/settings.json` (Linux/macOS)

Add to your `settings.json`:

```json
{
  "context_servers": {
    "revula": {
      "command": "revula",
      "args": []
    }
  }
}
```

**After editing:** Restart Zed. The context server should appear in the Assistant panel.

---

### 8. Custom / Other Clients

**Any MCP client that supports stdio transport will work with revula.** The protocol is standard JSON-RPC over stdin/stdout.

**Direct invocation:**

```bash
# Start the server (reads from stdin, writes to stdout, logs to stderr)
revula
```

**Over SSH (remote machine):**

```bash
# Run revula on a remote machine with stdio piped through SSH
ssh user@remote-host revula
```

**In Docker:**

```dockerfile
FROM python:3.11-slim
RUN pip install revula
# The entrypoint speaks stdio MCP
ENTRYPOINT ["revula"]
```

```bash
docker build -t revula .
# Use docker as the command in your client config:
# "command": "docker", "args": ["run", "-i", "--rm", "revula"]
```

**Python client (programmatic):**

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(command="revula", args=[])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"Connected: {len(tools.tools)} tools available")
            # Call a tool
            result = await session.call_tool("re_entropy", {"binary_path": "/bin/ls"})
            print(result)

asyncio.run(main())
```

---

### Universal Setup Script

Configure any client with one command:

```bash
# Interactive: pick a client from the menu
python scripts/setup/setup_ide.py

# Configure a specific client
python scripts/setup/setup_ide.py --client vscode
python scripts/setup/setup_ide.py --client cursor
python scripts/setup/setup_ide.py --client claude-desktop
python scripts/setup/setup_ide.py --client windsurf
python scripts/setup/setup_ide.py --client zed

# Configure all detected clients at once
python scripts/setup/setup_ide.py --all

# Print all configs without writing files (review first)
python scripts/setup/setup_ide.py --print-only

# Override the command (e.g., full path to venv)
python scripts/setup/setup_ide.py --client cursor --command "/home/you/venv/bin/revula"
```

The script auto-detects how to run revula (PATH, uvx, or python -m), creates backups before writing, and merges into existing configs.

---

## Configuration

### Config File

Create `~/.revula/config.toml` (or use the interactive generator):

```bash
python scripts/setup/setup_config_toml.py
```

Example configuration:

```toml
[tools.ghidra_headless]
path = "/opt/ghidra/support/analyzeHeadless"

[tools.radare2]
path = "/usr/bin/radare2"

[tools.jadx]
path = "/usr/local/bin/jadx"

[tools.retdec_decompiler]
path = "/usr/local/bin/retdec-decompiler"

[security]
max_memory_mb = 512
default_timeout = 60
max_timeout = 600
allowed_dirs = ["/home/user/samples", "/tmp/analysis"]
```

### Environment Variables

Environment variables override config file values:

```bash
export GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless  # Ghidra headless binary
export RETDEC_PATH=/usr/local/bin/retdec-decompiler         # RetDec decompiler binary
export REVULA_DEFAULT_TIMEOUT=120                            # Subprocess timeout (seconds)
export REVULA_MAX_MEMORY_MB=1024                             # Memory limit (MB)
```

---

## Tool Availability

revula degrades gracefully. Tools that depend on missing backends return clear error messages instead of crashing. Here is what each category needs:

| Category | Always Available | Needs External Tool | Needs Python Module |
|----------|-----------------|--------------------|--------------------|
| **Static** | PE/ELF parsing, entropy, strings | `objdump`, `radare2`, `ghidra`, `retdec`, `floss`, `capa` | `capstone` ✓, `lief` ✓, `pefile` ✓, `yara` ✓ |
| **Dynamic** | | `gdb`, `lldb` | `frida` |
| **Android** | APK manifest/DEX parsing (via zipfile) | `jadx`, `apktool`, `adb`, `zipalign`, `apksigner`, `tcpdump` | `frida`, `quark-engine` |
| **Platform** | | `rizin`, `radare2`, `gdb`, `qemu-user`, `qemu-system-*` | `r2pipe`, `binaryninja` |
| **Exploit** | ROP chain builder, heap analysis, libc database, format string helpers | | `capstone` ✓, `pwntools`, `keystone-engine` |
| **Anti-Analysis** | Pattern scanning (via `lief` + `capstone`) | | |
| **Malware** | File hashing, IoC extraction, risk scoring | | `yara` ✓, `ssdeep`, `tlsh` |
| **Firmware** | | `binwalk`, `sasquatch` | |
| **Protocol** | Binary protocol dissection, fuzzing | `tshark` | `scapy` |
| **Unpacking** | Packer signature detection | `upx` | `frida` |
| **Deobfuscation** | XOR/ROT/Base64 deobfuscation | | `capstone` ✓ |
| **Symbolic** | | | `angr`, `triton` |
| **Binary Formats** | | `aapt`, `javap`, `monodis`, `wasm2wat` | |
| **Utilities** | Hex dump, binary diff, patching | `tshark` | `scapy`, `ssdeep`, `tlsh` |

✓ = included in core dependencies (always installed).

### Installing Optional Dependencies

```bash
# Frida (dynamic instrumentation)
pip install frida frida-tools

# angr (symbolic execution, large install ~2 GB)
pip install angr

# radare2 bindings
pip install r2pipe

# Fuzzy hashing
pip install ssdeep tlsh

# Network analysis
pip install scapy

# Everything at once
pip install -e ".[full]"
```

### Installing External Tools (Debian/Ubuntu/Kali)

```bash
# Core analysis
sudo apt install gdb binutils radare2 binwalk upx-ucl

# Android RE
sudo apt install apktool jadx android-sdk adb zipalign apksigner

# Network
sudo apt install tshark

# Ghidra: download from https://ghidra-sre.org/
export GHIDRA_INSTALL=/opt/ghidra
```

---

## Architecture

```
src/revula/                     # 19,400+ LOC across 63 Python files
├── __init__.py                 # Version (__version__ = "0.1.0")
├── config.py                   # Tool detection, TOML config, env var loading
├── sandbox.py                  # Secure subprocess execution, path validation
├── session.py                  # Session lifecycle manager (debuggers, Frida)
├── server.py                   # MCP server entrypoint (stdio transport)
├── cache.py                    # LRU result cache with TTL
├── rate_limit.py               # Token-bucket rate limiter
└── tools/
    ├── __init__.py             # Tool registry + @register_tool decorator
    ├── static/                 # 8 files: PE/ELF, disasm, strings, entropy, symbols, YARA, capa, decompile
    ├── dynamic/                # 4 files: GDB, LLDB, Frida, coverage
    ├── android/                # 9 files: APK, DEX, decompile, native, device, frida, traffic, repack, scanners
    ├── platform/               # 3 files: Rizin, GDB-enhanced, QEMU
    ├── exploit/                # 5 files: ROP builder, heap exploitation, libc database, shellcode, format strings
    ├── antianalysis/           # 1 file:  anti-debug/VM detection and bypass generation
    ├── malware/                # 1 file:  triage, sandbox queries, YARA gen, config extraction
    ├── firmware/               # 1 file:  extraction, vuln scanning, base address detection
    ├── protocol/               # 1 file:  PCAP analysis, protocol dissection, fuzzing
    ├── deobfuscation/          # 1 file:  string deobfuscation, CFF, opaque predicates
    ├── unpacking/              # 1 file:  packer detection, UPX, dynamic unpack, PE rebuild
    ├── symbolic/               # 1 file:  angr + Triton
    ├── binary_formats/         # 1 file:  .NET, Java, WASM
    ├── utils/                  # 4 files: hex, crypto, patching, network
    └── admin/                  # 1 file:  server status, cache management
```

### How It Works

1. **Startup.** `server.py` loads `config.py`, which probes the system for external tools (via `shutil.which`) and Python modules (via `importlib.util.find_spec`). Results are cached in a `ServerConfig` singleton.

2. **Tool Registration.** Each tool file uses `@TOOL_REGISTRY.register()` to declare its name, description, JSON Schema, and async handler. Tools self-register on import.

3. **Request Dispatch.** When a `tools/call` request arrives, the server looks up the handler in `TOOL_REGISTRY`, validates arguments against the JSON Schema, checks rate limits, checks the result cache, and dispatches to the handler.

4. **Subprocess Execution.** All external tool invocations go through `sandbox.safe_subprocess()`, which enforces `shell=False`, sets `RLIMIT_AS` and `RLIMIT_CPU`, validates paths, and captures stdout/stderr.

5. **Result Caching.** Deterministic operations (disassembly, parsing) are cached with a configurable TTL. Mutating operations (patching, Frida injection) bypass the cache automatically.

6. **Session Management.** Long-lived debugger and Frida sessions are tracked by `SessionManager`, with automatic cleanup after 30 minutes of idle time.

### Infrastructure Components

| Component | Purpose | Key Detail |
|-----------|---------|------------|
| **ResultCache** | Avoid redundant subprocess calls | LRU, 256 entries, 10-minute TTL |
| **RateLimiter** | Prevent resource exhaustion | Token-bucket, 120 global / 30 per-tool RPM |
| **ToolRegistry** | Decorator-based tool dispatch | JSON Schema validation before handler call |
| **SessionManager** | Debugger/Frida persistence | Auto-cleanup after 30 min idle |
| **sandbox.py** | Secure execution layer | `shell=False`, RLIMIT enforcement, path validation |

---

## Security Model

revula operates on the principle that **user-supplied arguments are untrusted**. The following hardening measures are applied:

### Subprocess Isolation

- **No `shell=True`:** Every subprocess call uses `shell=False` with explicit argument lists. This is enforced by a CI test (`test_no_shell_true`) that scans every source file.
- **No `eval()` / `exec()`:** No dynamic code evaluation of user input.
- **No f-string injection:** User-supplied values are never interpolated into `python3 -c` code strings. Values are passed via `sys.argv`, `stdin`, or environment variables. Enforced by `test_no_fstring_in_subprocess_python_code`.
- **JavaScript escaping:** All user-controlled values interpolated into Frida JavaScript strings pass through `_js_escape()`, which escapes backslashes, quotes, newlines, and other injection vectors.
- **Resource limits:** Every subprocess gets `RLIMIT_AS` (512 MB default) and `RLIMIT_CPU` (60 s default) via `resource.setrlimit()`.
- **Timeout enforcement:** `asyncio.wait_for()` wraps all subprocess calls.

### Path Validation

- **Fail-closed:** `validate_path()` rejects all paths when no `allowed_dirs` are configured (falls back to `get_config().security.allowed_dirs`). It does not silently pass.
- **Traversal blocked:** `..` components are rejected after `os.path.realpath()` resolution.
- **Absolute paths required:** Relative paths are rejected.
- **Validated everywhere:** All file-accepting tool handlers call `validate_path()` before any file I/O.

### Frida Hardening

- **Script size limit:** Frida scripts are capped at 1 MB to prevent memory exhaustion.
- **Memory dump limit:** Memory dumps are capped at 100 MB.
- **JS injection prevention:** Class names, method names, module names, and other user-supplied values are escaped before interpolation into JavaScript templates.

### Temporary Files

- **No `tempfile.mktemp()`:** All temporary files use `tempfile.NamedTemporaryFile()` or `tempfile.mkdtemp()` to prevent TOCTOU race conditions.
- **No hardcoded `/tmp` paths:** All temporary paths use the `tempfile` module.

### Rate Limiting & Caching

- **Global limit:** 120 requests per minute (configurable).
- **Per-tool limit:** 30 requests per minute (configurable).
- **Result cache policy:** fail-closed explicit opt-in per tool (`cacheable=True`); mutating/stateful tools are never cached by default.
- **Session TTL:** Idle sessions auto-cleaned after 30 minutes.

---

## Testing

```bash
# Run full test suite
python -m pytest tests/ --timeout=30

# With coverage
python -m pytest tests/ --cov=revula --cov-report=html --timeout=30

# Verbose output
python -m pytest tests/ -v --timeout=30

# Specific test suites
python -m pytest tests/test_infra.py -v      # Cache, rate limiter, sessions
python -m pytest tests/test_core.py -v       # Config, sandbox, tool registry
python -m pytest tests/test_static.py -v     # Static analysis tools
python -m pytest tests/test_android.py -v    # Android module tests
python -m pytest tests/test_exploit.py -v    # ROP, heap, libc tools (32 tests)
python -m pytest tests/test_tools_new.py -v  # Exploit, malware, firmware, protocol, etc.
python -m pytest tests/test_security.py -v   # Security invariant tests

# Using the test runner script
bash scripts/test/run_tests.sh
```

### Test Categories

| Suite | Tests | Covers |
|-------|-------|--------|
| `test_infra.py` | Cache, rate limiter, session manager | Infrastructure correctness |
| `test_core.py` | Config loading, sandbox, tool registry | Core module behavior |
| `test_static.py` | Entropy, hex, crypto, strings, symbols | Static analysis tools |
| `test_android.py` | APK parse, DEX, device, Frida Android | Android module tests |
| `test_tools_new.py` | Exploit, malware, firmware, protocol, antianalysis, platform, deobfuscation, symbolic, unpacking, binary formats | All remaining tool categories |
| `test_security.py` | `shell=True` scan, injection scan, `mktemp` scan, hardcoded `/tmp` scan, path validation, JS escaping, shellcode validation | Security regression tests |

### Security Tests

The `TestVulnerabilityHardeningV3` suite in `test_security.py` enforces:

- **No f-string code injection:** Scans all source files for `"-c"` arguments containing f-strings.
- **No `tempfile.mktemp()`:** Prevents TOCTOU race conditions.
- **No hardcoded `/tmp/` paths:** Enforces use of the `tempfile` module.
- **Fail-closed path validation:** Verifies `validate_path()` rejects paths when `allowed_dirs` is empty.
- **Frida JS escaping:** Verifies `_js_escape()` blocks injection payloads.
- **Shellcode hex validation:** Verifies non-hex input is rejected, not passed to subprocess.

---

## Scripts & Automation

All scripts are in `scripts/` and are fully implemented:

### Installation

| Script | Purpose |
|--------|---------|
| `scripts/install/install_all.sh` | Master installer: Python check, venv, deps, external tools, config |
| `scripts/install/install_verify.sh` | Post-install verification: checks all dependencies and paths |

### Setup

| Script | Purpose |
|--------|---------|
| `scripts/setup/setup_ide.py` | Universal IDE/client configurator for Claude Desktop, VS Code, Cursor, Windsurf, Zed, and Continue |
| `scripts/setup/setup_claude_desktop.py` | Claude Desktop-specific auto-configurator (legacy, still functional) |
| `scripts/setup/setup_config_toml.py` | Interactive config.toml generator |
| `scripts/setup/setup_android_device.sh` | Prepare an Android device for RE (root, frida-server, certs) |

### Testing & Development

| Script | Purpose |
|--------|---------|
| `scripts/test/run_tests.sh` | Run full test suite with coverage |
| `scripts/test/validate_install.py` | Comprehensive installation validator |
| `scripts/dev/add_tool.py` | Scaffold a new tool module (creates file, registers, adds test) |
| `scripts/dev/lint_and_type.sh` | Run ruff + mypy |
| `scripts/utils/download_frida_server.py` | Download frida-server for a target architecture |

### Docker

| Script | Purpose |
|--------|---------|
| `scripts/docker/test.sh` | Automated Docker build and testing (tests all tools: Ghidra, angr, Frida) |
| `scripts/docker/validate.sh` | Docker configuration validation |

---

## Usage Examples

### Static Analysis: Analyze a PE Binary

Ask Claude: *"Analyze this binary for me: /home/user/samples/malware.exe"*

Behind the scenes, Claude can call:
1. `re_pe_elf` to parse PE headers, sections, imports, and exports
2. `re_strings` to extract and classify strings (URLs, IPs, crypto constants)
3. `re_entropy` to check for packing (high entropy sections)
4. `re_yara_scan` to scan with YARA rules
5. `re_capa_scan` to map to ATT&CK techniques

### Dynamic Analysis: Debug with GDB

Ask Claude: *"Debug /home/user/crackme and find the password check"*

Claude can orchestrate:
1. `re_gdb` with action `start` to launch the binary under GDB
2. `re_disasm` to disassemble key functions
3. `re_gdb` with action `breakpoint` to set breakpoints at comparison instructions
4. `re_gdb` with action `continue` and `registers` to run and inspect state

### Android: Reverse an APK

Ask Claude: *"Analyze this APK for security issues: /home/user/app.apk"*

Claude can call:
1. `re_apk_parse` to extract manifest, permissions, and components
2. `re_dex_analyze` to list classes and find suspicious methods
3. `re_android_decompile` to decompile with jadx
4. `re_android_scanner` to run security scanners
5. `re_antianalysis_detect` to check for anti-tampering

### Malware Triage

Ask Claude: *"Triage this suspected malware sample"*

Claude can call:
1. `re_malware_triage` for hashes, IoCs, import analysis, and risk score
2. `re_malware_config` to extract C2 URLs and encryption keys
3. `re_malware_yara_gen` to generate a YARA rule for the sample
4. `re_malware_sandbox` to query VirusTotal/Hybrid Analysis

### Exploit Development

Ask Claude: *"Build a ROP chain to call execve('/bin/sh') in this binary"*

Claude can orchestrate:
1. `re_rop_gadgets` to find useful gadgets (pop rdi, pop rsi, syscall) with semantic classification
2. `re_rop_chain` to automatically build an execve chain with proper register setup
3. `re_libc_offsets` to extract system/execve/binsh offsets from libc
4. `re_aslr_defeat` to calculate base addresses from leaked pointers
5. `re_heap_chunk` to analyze malloc chunks and bin classification for heap exploits
6. `re_heap_technique` to get templates for House of Force, Tcache Poisoning, etc.

---

## Performance & Limitations

### What Works Well Without Optional Dependencies

With just the core install (`pip install -e .`), you get full functionality for:
- PE/ELF/Mach-O parsing and header analysis
- Multi-architecture disassembly (via Capstone)
- String extraction and classification
- Shannon entropy analysis and packing detection
- YARA rule scanning
- Binary patching
- Hex dump and pattern search
- File hashing (MD5, SHA-1, SHA-256)
- ROP gadget finding and chain building (via Capstone)
- Heap exploitation helpers (chunk analysis, bin classification, safe-linking)
- Libc database tools (symbol extraction, offset calculation, ASLR defeat)
- Format string payload calculation
- XOR/ROT/Base64 deobfuscation
- Anti-analysis pattern detection

### What Needs External Tools

These tools produce clear "tool not found" errors when backends are missing:
- **Decompilation** requires Ghidra, RetDec, or Binary Ninja
- **Dynamic analysis** requires GDB, LLDB, or Frida
- **Android RE** requires jadx, apktool, and ADB
- **Symbolic execution** requires angr (large dependency, ~2 GB)
- **Network analysis** requires tshark or scapy
- **Firmware extraction** requires binwalk

### Performance Expectations

- **Startup:** ~1 second (probes system for available tools via `shutil.which` and `importlib.util.find_spec`)
- **Static analysis:** Sub-second for most operations on files under 100 MB
- **Disassembly:** Capstone disassembles ~1 MB/s; radare2 adds full analysis overhead
- **Subprocess calls:** Each external tool invocation has ~50-200 ms overhead from process spawn
- **Caching:** Result caching is explicit opt-in per tool; unless enabled, calls execute fresh
- **Rate limiting:** 120 requests/minute global, 30/minute per tool (configurable)

### Known Limitations

1. **No Windows native support.** Designed for Linux. macOS works for most tools. Windows requires WSL2.
2. **stdio transport only.** There is no HTTP/SSE server. Revula must run on the same machine as your IDE (or be piped via SSH/Docker). This is a deliberate design choice for security: MCP over stdio is simpler and avoids exposing a network socket.
3. **No GUI.** This is a headless MCP server. Use Claude Desktop, VS Code Copilot, Cursor, or another MCP client for the interface.
4. **Large binary analysis.** Files over 500 MB may hit the default memory limit (512 MB). Increase via `REVULA_MAX_MEMORY_MB`.
5. **angr install size.** The `angr` optional dependency is ~2 GB and takes several minutes to install.
6. **Frida version coupling.** Frida client and server versions must match exactly. Use `scripts/utils/download_frida_server.py` to get the right version.
7. **Single-user design.** The server handles one MCP client at a time via stdio. There is no multi-tenant isolation. Each IDE/client spawns its own server process.
8. **IDA Pro integration.** Requires IDA Pro with the REST API plugin. Not included.

---

## Troubleshooting

### Server Won't Start

```bash
# Check Python version (need 3.11+)
python --version

# Check MCP is installed
python -c "import mcp; print(mcp.__version__)"

# Run and capture server logs from stderr
revula 2> revula.log
tail -f revula.log
```

### Tool Says "not found"

```bash
# Check what's available
python -c "from revula.config import get_config, format_availability_report; print(format_availability_report(get_config()))"

# The report shows ✓/✗ for every external tool and Python module.
# Install what you need and restart the server.
```

### Path Validation Errors

```
Error: Path /some/path is not within allowed directories
```

Add the directory to your config:

```toml
[security]
allowed_dirs = ["/home/user/samples", "/tmp/analysis", "/some/path"]
```

Alternatively, set the value via environment variable. The server will use the config file's `allowed_dirs` as a fallback.

### Rate Limit Exceeded

```
Error: Rate limit exceeded for tool re_disasm
```

Rate limits are currently initialized from code defaults (`global_rpm=120`, `per_tool_rpm=30`, `burst_size=10`).
If you need different limits, adjust `RateLimitConfig(...)` in `src/revula/server.py` and restart.

### Frida Connection Issues

```bash
# Check Frida version match
frida --version
frida-server --version  # on device

# Download matching server
python scripts/utils/download_frida_server.py --arch arm64
```

### Tests Failing

```bash
# Run with verbose output
python -m pytest tests/ -v --timeout=30 --tb=long

# Clear bytecode cache (fixes stale imports)
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
python -m pytest tests/ --timeout=30
```

### Android Device Not Detected

```bash
# Run the device setup script
bash scripts/setup/setup_android_device.sh

# Manual check
adb devices
adb shell id  # should show root or shell
```

---

## Contributing

### Adding a New Tool

Use the scaffold generator:

```bash
python scripts/dev/add_tool.py
```

This creates the tool file, registers it in the category `__init__.py`, and generates a test stub.

### Code Quality

```bash
# Lint and type-check
bash scripts/dev/lint_and_type.sh

# Run full test suite
python -m pytest tests/ --timeout=30 -q

# Validate install
python scripts/test/validate_install.py
```

### Guidelines

- Every tool handler is `async` and returns `list[dict]` (MCP content blocks).
- All subprocess calls go through `sandbox.safe_subprocess()`.
- All file paths must be validated via `sandbox.validate_path()`.
- No `shell=True`, no `eval()`, no f-string interpolation into subprocess code.
- Every new tool needs at least one test.

---

## License

Released under the GNU General Public License. See [LICENSE](LICENSE) for details.
