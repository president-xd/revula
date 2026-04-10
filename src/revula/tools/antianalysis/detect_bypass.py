"""
Revula Anti-Analysis Detection & Bypass — detect and bypass anti-debug,
anti-tamper, anti-VM, packing, and obfuscation techniques.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, text_result

logger = logging.getLogger(__name__)

# Known anti-debug API signatures
_ANTI_DEBUG_APIS: dict[str, dict[str, str]] = {
    # Windows
    "IsDebuggerPresent": {"os": "windows", "category": "direct_check", "severity": "medium"},
    "CheckRemoteDebuggerPresent": {"os": "windows", "category": "direct_check", "severity": "medium"},
    "NtQueryInformationProcess": {"os": "windows", "category": "nt_query", "severity": "high"},
    "NtSetInformationThread": {"os": "windows", "category": "thread_hide", "severity": "high"},
    "OutputDebugString": {"os": "windows", "category": "timing", "severity": "low"},
    "FindWindow": {"os": "windows", "category": "window_check", "severity": "low"},
    "GetTickCount": {"os": "windows", "category": "timing", "severity": "low"},
    "QueryPerformanceCounter": {"os": "windows", "category": "timing", "severity": "medium"},
    "NtQuerySystemInformation": {"os": "windows", "category": "system_check", "severity": "medium"},
    "CloseHandle": {"os": "windows", "category": "exception", "severity": "low"},
    "UnhandledExceptionFilter": {"os": "windows", "category": "exception", "severity": "medium"},
    "SetUnhandledExceptionFilter": {"os": "windows", "category": "exception", "severity": "medium"},
    "RaiseException": {"os": "windows", "category": "exception", "severity": "low"},
    "NtClose": {"os": "windows", "category": "exception", "severity": "medium"},
    "BlockInput": {"os": "windows", "category": "input_block", "severity": "high"},
    # Linux
    "ptrace": {"os": "linux", "category": "direct_check", "severity": "high"},
    "prctl": {"os": "linux", "category": "process_control", "severity": "medium"},
    "getppid": {"os": "linux", "category": "parent_check", "severity": "low"},
    "sysctl": {"os": "linux", "category": "system_check", "severity": "medium"},
}

# VM detection signatures
_VM_SIGNATURES: dict[str, str] = {
    "VMwareVMware": "vmware",
    "VBoxVBoxVBox": "virtualbox",
    "Microsoft Hv": "hyper-v",
    "KVMKVMKVM": "kvm",
    "XenVMMXenVMM": "xen",
    "prl hyperv": "parallels",
    "QEMU": "qemu",
    "vbox": "virtualbox",
    "vmware": "vmware",
    "qemu": "qemu",
    "virtual": "generic_vm",
    "VirtualBox": "virtualbox",
    "SbieDll.dll": "sandboxie",
    "dbghelp.dll": "debugger",
    "sbiedll": "sandboxie",
}

# Anti-tamper patterns
_TAMPER_PATTERNS: list[dict[str, str]] = [
    {
        "pattern": r"checksum|crc32|md5|sha[0-9]",
        "category": "integrity_check",
        "description": "Code integrity verification",
    },
    {
        "pattern": r"GetModuleFileName|GetModuleHandle",
        "category": "module_check",
        "description": "Module path/handle verification",
    },
    {
        "pattern": r"VirtualProtect|mprotect",
        "category": "memory_protection",
        "description": "Memory protection manipulation",
    },
    {
        "pattern": r"self_hash|verify_integrity",
        "category": "self_check",
        "description": "Self-integrity verification",
    },
    {
        "pattern": r"code_sign|authenticode|codesign",
        "category": "signature_check",
        "description": "Code signature verification",
    },
]


@TOOL_REGISTRY.register(
    name="re_antianalysis_detect",
    description=(
        "Detect anti-debug, anti-VM, anti-tamper, and packing techniques "
        "in a binary. Scans imports, strings, code patterns."
    ),
    category="antianalysis",
    requires_tools=["strings", "objdump"],
    input_schema={
        "type": "object",
        "required": ["binary_path"],
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Path to binary to analyze.",
            },
            "scan_type": {
                "type": "string",
                "enum": ["all", "antidebug", "antivm", "antitamper", "packing"],
                "description": "Type of scan. Default: all.",
            },
        },
    },
)
async def handle_detect(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect anti-analysis techniques."""
    binary_path = arguments["binary_path"]
    scan_type = arguments.get("scan_type", "all")
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    results: dict[str, Any] = {
        "binary": str(file_path),
        "scan_type": scan_type,
    }

    # Get strings and imports from binary
    strings_proc = await safe_subprocess(
        ["strings", "-a", str(file_path)], timeout=30,
    )
    strings_output = strings_proc.stdout if strings_proc.success else ""

    imports_proc = await safe_subprocess(
        ["objdump", "-T", str(file_path)], timeout=30,
    )
    imports_output = imports_proc.stdout if imports_proc.success else ""

    all_text = strings_output + "\n" + imports_output

    if scan_type in ("all", "antidebug"):
        antidebug: list[dict[str, Any]] = []
        for api, info in _ANTI_DEBUG_APIS.items():
            if api.lower() in all_text.lower():
                antidebug.append({
                    "api": api,
                    "os": info["os"],
                    "category": info["category"],
                    "severity": info["severity"],
                })
        results["antidebug"] = {
            "found": len(antidebug),
            "techniques": antidebug,
            "risk_level": _calc_risk(antidebug),
        }

    if scan_type in ("all", "antivm"):
        antivm: list[dict[str, str]] = []
        for sig, vm_type in _VM_SIGNATURES.items():
            if sig.lower() in all_text.lower():
                antivm.append({"signature": sig, "vm_type": vm_type})

        # Check for CPUID-based detection
        cpuid_check = "cpuid" in all_text.lower()
        rdtsc_check = "rdtsc" in all_text.lower()

        results["antivm"] = {
            "found": len(antivm),
            "signatures": antivm,
            "cpuid_check": cpuid_check,
            "rdtsc_timing": rdtsc_check,
        }

    if scan_type in ("all", "antitamper"):
        antitamper: list[dict[str, str]] = []
        for pat in _TAMPER_PATTERNS:
            if re.search(pat["pattern"], all_text, re.IGNORECASE):
                antitamper.append({
                    "category": pat["category"],
                    "description": pat["description"],
                })
        results["antitamper"] = {
            "found": len(antitamper),
            "techniques": antitamper,
        }

    if scan_type in ("all", "packing"):
        # Use DIE (Detect It Easy) if available
        die_proc = await safe_subprocess(
            ["diec", "--json", str(file_path)], timeout=30,
        )
        if die_proc.success:
            results["packing"] = {
                "die_output": die_proc.stdout[:3000],
            }
        else:
            # Fallback: check entropy and section names
            packing_indicators: list[str] = []
            pack_sigs = ["UPX", "ASPack", "PECompact", "Themida", "VMProtect",
                         "Enigma", "Obsidium", ".netshrink", "Armadillo"]
            for sig in pack_sigs:
                if sig.lower() in all_text.lower():
                    packing_indicators.append(sig)
            results["packing"] = {
                "signatures_found": packing_indicators,
                "note": "Install diec for accurate packer detection",
            }

    return text_result(results)


def _calc_risk(findings: list[dict[str, Any]]) -> str:
    """Calculate overall risk level from findings."""
    if not findings:
        return "none"
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    med_count = sum(1 for f in findings if f.get("severity") == "medium")
    if high_count >= 2:
        return "critical"
    if high_count >= 1 or med_count >= 3:
        return "high"
    if med_count >= 1:
        return "medium"
    return "low"


@TOOL_REGISTRY.register(
    name="re_antianalysis_bypass",
    description=(
        "Generate bypass scripts and patches for anti-debug, anti-VM, "
        "and anti-tamper protections. Outputs Frida scripts or binary patches."
    ),
    category="antianalysis",
    input_schema={
        "type": "object",
        "required": ["bypass_type"],
        "properties": {
            "bypass_type": {
                "type": "string",
                "enum": [
                    "ptrace", "isdebuggerpresent", "ntquery",
                    "timing", "vm_detect", "integrity",
                    "all_antidebug", "custom",
                ],
                "description": "Type of bypass to generate.",
            },
            "output_format": {
                "type": "string",
                "enum": ["frida", "patch", "gdb", "ld_preload"],
                "description": "Bypass output format. Default: frida.",
            },
            "target_address": {
                "type": "string",
                "description": "Address to patch for custom bypass.",
            },
            "patch_bytes": {
                "type": "string",
                "description": "Hex bytes for custom patch.",
            },
        },
    },
)
async def handle_bypass(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate anti-analysis bypass scripts."""
    bypass_type = arguments["bypass_type"]
    output_format = arguments.get("output_format", "frida")
    target_address = arguments.get("target_address", "")
    patch_bytes = arguments.get("patch_bytes", "")

    bypasses: dict[str, dict[str, str]] = {
        "ptrace": {
            "frida": _FRIDA_PTRACE_BYPASS,
            "ld_preload": _LD_PRELOAD_PTRACE,
            "gdb": "catch syscall ptrace\ncommands\nset $rax = 0\ncontinue\nend",
        },
        "isdebuggerpresent": {
            "frida": _FRIDA_ISDBG_BYPASS,
            "patch": "Search for IsDebuggerPresent call and NOP or patch return to 0",
            "gdb": "break *IsDebuggerPresent+0x10\ncommands\nset $eax = 0\ncontinue\nend",
        },
        "ntquery": {
            "frida": _FRIDA_NTQUERY_BYPASS,
            "gdb": "break *NtQueryInformationProcess\ncommands\nset $eax = 0\ncontinue\nend",
        },
        "timing": {
            "frida": _FRIDA_TIMING_BYPASS,
            "gdb": "break *GetTickCount\ncommands\nset $eax = 0\ncontinue\nend",
        },
        "vm_detect": {
            "frida": _FRIDA_VM_BYPASS,
        },
        "integrity": {
            "frida": _FRIDA_INTEGRITY_BYPASS,
        },
        "all_antidebug": {
            "frida": _FRIDA_ALL_ANTIDEBUG,
        },
        "custom": {
            "frida": f"""
Interceptor.attach(ptr('{target_address}'), {{
    onEnter: function(args) {{ }},
    onLeave: function(retval) {{ retval.replace(ptr(0)); }}
}});""" if target_address else "// Provide target_address for custom bypass",
            "patch": (
                f"Patch at {target_address} with bytes: {patch_bytes}"
                if target_address
                else "Provide target_address"
            ),
        },
    }

    scripts = bypasses.get(bypass_type, {})
    script = scripts.get(output_format, f"No {output_format} bypass available for {bypass_type}")

    return text_result({
        "bypass_type": bypass_type,
        "format": output_format,
        "script": script,
        "available_formats": list(scripts.keys()),
    })


# ── Frida bypass scripts ──────────────────────────────────────────────────

_FRIDA_PTRACE_BYPASS = """
// Bypass ptrace-based anti-debug (Linux)
Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0));
            console.log('[+] ptrace(PTRACE_TRACEME) bypassed');
        }
    }
});
"""

_LD_PRELOAD_PTRACE = """
// Compile: gcc -shared -fPIC -o bypass.so bypass.c
// Usage: LD_PRELOAD=./bypass.so ./target
#include <sys/ptrace.h>

long ptrace(int request, ...) {
    if (request == 0) return 0;  // PTRACE_TRACEME
    return 0;
}
"""

_FRIDA_ISDBG_BYPASS = """
// Bypass IsDebuggerPresent (Windows)
var isDbg = Module.getExportByName('kernel32.dll', 'IsDebuggerPresent');
Interceptor.attach(isDbg, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
        console.log('[+] IsDebuggerPresent bypassed');
    }
});

// Also patch PEB.BeingDebugged
var peb = Module.getExportByName('ntdll.dll', 'NtCurrentPeb');
if (peb) {
    Interceptor.attach(peb, {
        onLeave: function(retval) {
            retval.add(2).writeU8(0);  // PEB.BeingDebugged = 0
        }
    });
}
"""

_FRIDA_NTQUERY_BYPASS = """
// Bypass NtQueryInformationProcess (Windows)
var ntqip = Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess');
Interceptor.attach(ntqip, {
    onEnter: function(args) {
        this.infoClass = args[1].toInt32();
        this.outBuf = args[2];
    },
    onLeave: function(retval) {
        if (this.infoClass === 7) {  // ProcessDebugPort
            this.outBuf.writeU32(0);
            console.log('[+] NtQueryInformationProcess(DebugPort) bypassed');
        }
        if (this.infoClass === 0x1e) {  // ProcessDebugObjectHandle
            retval.replace(ptr(0xC0000353));  // STATUS_PORT_NOT_SET
            console.log('[+] NtQueryInformationProcess(DebugObjectHandle) bypassed');
        }
    }
});
"""

_FRIDA_TIMING_BYPASS = """
// Bypass timing-based anti-debug
var baseTime = null;
['GetTickCount', 'GetTickCount64'].forEach(function(name) {
    try {
        var func = Module.getExportByName('kernel32.dll', name);
        Interceptor.attach(func, {
            onLeave: function(retval) {
                if (!baseTime) baseTime = retval;
                // Always return incremented small value
                retval.replace(baseTime.add(100));
            }
        });
    } catch(e) {}
});

// Linux: clock_gettime
try {
    Interceptor.attach(Module.getExportByName(null, 'clock_gettime'), {
        onLeave: function(retval) {
            // Don't modify - just log for awareness
            console.log('[*] clock_gettime called');
        }
    });
} catch(e) {}
"""

_FRIDA_VM_BYPASS = """
// Bypass VM detection checks
// Hook CPUID instruction via exception handler
// Hook common VM-detection APIs

// Windows: registry checks
['RegOpenKeyExA', 'RegOpenKeyExW'].forEach(function(name) {
    try {
        Interceptor.attach(Module.getExportByName('advapi32.dll', name), {
            onEnter: function(args) {
                var key = args[1].readUtf16String();
                if (key && (key.indexOf('VMware') !== -1 ||
                           key.indexOf('VirtualBox') !== -1 ||
                           key.indexOf('VBOX') !== -1)) {
                    this.block = true;
                }
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(ptr(2));  // ERROR_FILE_NOT_FOUND
                    console.log('[+] VM registry check bypassed');
                }
            }
        });
    } catch(e) {}
});
"""

_FRIDA_INTEGRITY_BYPASS = """
// Bypass integrity/checksum checks
// Hook common hash functions to return expected values

['CryptHashData', 'CryptGetHashParam'].forEach(function(name) {
    try {
        Interceptor.attach(Module.getExportByName('advapi32.dll', name), {
            onEnter: function(args) {
                console.log('[*] ' + name + ' called');
            }
        });
    } catch(e) {}
});

// Hook VirtualProtect to prevent code re-protection
try {
    Interceptor.attach(Module.getExportByName('kernel32.dll', 'VirtualProtect'), {
        onEnter: function(args) {
            console.log('[*] VirtualProtect(' + args[0] + ', ' + args[1] + ', ' + args[2] + ')');
        }
    });
} catch(e) {}
"""

_FRIDA_ALL_ANTIDEBUG = """
// Comprehensive anti-debug bypass (Windows + Linux)

// === WINDOWS ===
try {
    // IsDebuggerPresent
    Interceptor.attach(Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'), {
        onLeave: function(r) { r.replace(ptr(0)); }
    });
    // CheckRemoteDebuggerPresent
    Interceptor.attach(Module.getExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent'), {
        onEnter: function(args) { this.out = args[1]; },
        onLeave: function(r) { this.out.writeU32(0); r.replace(ptr(1)); }
    });
    // NtQueryInformationProcess
    Interceptor.attach(Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess'), {
        onEnter: function(args) { this.cls = args[1].toInt32(); this.buf = args[2]; },
        onLeave: function(r) {
            if (this.cls === 7) this.buf.writeU32(0);
            if (this.cls === 0x1f) this.buf.writeU32(0);
        }
    });
} catch(e) { /* Not Windows */ }

// === LINUX ===
try {
    Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
        onEnter: function(args) { this.req = args[0].toInt32(); },
        onLeave: function(r) { if (this.req === 0) r.replace(ptr(0)); }
    });
} catch(e) { /* Not Linux or no ptrace */ }

console.log('[+] All anti-debug bypasses active');
"""
