"""
Revula Android Frida Integration — Spawn, attach, hook, trace, bypass.

Provides high-level Frida tools for Android: spawn/attach to processes,
inject scripts, Java-layer hooking, method tracing, and common bypasses
(root detection, SSL pinning, anti-debug).
"""

from __future__ import annotations

import logging
import textwrap
import time
from typing import Any

from revula.session import FridaSession, SessionManager
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


def _js_escape(value: str) -> str:
    """Escape a string for safe interpolation into JavaScript single-quoted literals."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\0", "\\0")
    )


def _get_session_mgr(arguments: dict[str, Any]) -> SessionManager:
    """Get session manager from config or create default."""
    config = arguments.get("__config__")
    if config and hasattr(config, "session_manager"):
        return config.session_manager  # type: ignore[no-any-return]
    from revula.server import SESSION_MANAGER
    return SESSION_MANAGER


# ---------------------------------------------------------------------------
# Frida Script Templates
# ---------------------------------------------------------------------------


SCRIPT_ROOT_BYPASS = textwrap.dedent("""\
    Java.perform(function() {
        // Common root detection bypasses
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        if (RootBeer) {
            RootBeer.isRooted.implementation = function() { return false; };
            RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        }

        // Generic file existence checks
        var File = Java.use('java.io.File');
        var originalExists = File.exists;
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var rootPaths = ['/system/bin/su', '/system/xbin/su', '/sbin/su',
                '/data/local/su', '/data/local/bin/su', '/system/app/Superuser.apk',
                '/system/app/SuperSU', '/data/adb/magisk'];
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) return false;
            }
            return originalExists.call(this);
        };

        // Build.TAGS check
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';

        send({type: 'bypass', name: 'root_detection', status: 'active'});
    });
""")

SCRIPT_SSL_BYPASS = textwrap.dedent("""\
    Java.perform(function() {
        // TrustManager bypass
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        if (TrustManagerImpl) {
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain) {
                return untrustedChain;
            };
        }

        // OkHttp3 certificate pinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
            CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0')
                .implementation = function() {};
        } catch(e) {}

        // WebView SSL errors
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                handler.proceed();
            };
        } catch(e) {}

        // HttpsURLConnection
        try {
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(v) {};
        } catch(e) {}

        send({type: 'bypass', name: 'ssl_pinning', status: 'active'});
    });
""")

SCRIPT_ANTI_DEBUG_BYPASS = textwrap.dedent("""\
    // ptrace anti-debug bypass
    Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
        onEnter: function(args) {
            this.request = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (this.request === 0) { // PTRACE_TRACEME
                retval.replace(0);
            }
        }
    });

    // /proc/self/status TracerPid bypass
    Interceptor.attach(Module.findExportByName(null, 'fopen'), {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (path && path.indexOf('/proc/') !== -1 && path.indexOf('/status') !== -1) {
                this.isStatus = true;
            }
        },
        onLeave: function(retval) {}
    });

    Java.perform(function() {
        // Debug.isDebuggerConnected
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() { return false; };
    });

    send({type: 'bypass', name: 'anti_debug', status: 'active'});
""")


# ---------------------------------------------------------------------------
# Tool: re_android_frida_spawn
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_frida_spawn",
    description=(
        "Spawn an Android app via Frida, injecting a script before the app starts. "
        "Returns a session ID for further interaction."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Android package name to spawn (e.g. com.example.app).",
            },
            "device": {
                "type": "string",
                "description": "Device serial. Default: first USB device.",
            },
            "script": {
                "type": "string",
                "description": "Frida JS script to inject. Optional.",
            },
            "startup_script": {
                "type": "string",
                "enum": ["root_bypass", "ssl_bypass", "anti_debug_bypass", "all"],
                "description": "Pre-built startup script to inject.",
            },
            "pause_on_spawn": {
                "type": "boolean",
                "description": "Keep process paused after spawn. Default: false.",
            },
        },
    },
)
async def handle_frida_spawn(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Spawn app with Frida."""
    package = arguments["package_name"]
    device_id = arguments.get("device")
    script_code = arguments.get("script", "")
    startup = arguments.get("startup_script")
    pause = arguments.get("pause_on_spawn", False)

    # Enforce script size limit (1 MB)
    for s in [script_code, startup]:
        if s and len(s) > 1_048_576:
            return error_result("Frida script exceeds maximum size (1 MB)")

    try:
        import frida
    except ImportError:
        return error_result("frida not installed. Install: pip install frida frida-tools")

    try:
        dev = frida.get_device(device_id) if device_id else frida.get_usb_device(timeout=5)
    except Exception as e:
        return error_result(f"Failed to get Frida device: {e}")

    # Combine scripts
    scripts: list[str] = []
    if startup:
        if startup in ("root_bypass", "all"):
            scripts.append(SCRIPT_ROOT_BYPASS)
        if startup in ("ssl_bypass", "all"):
            scripts.append(SCRIPT_SSL_BYPASS)
        if startup in ("anti_debug_bypass", "all"):
            scripts.append(SCRIPT_ANTI_DEBUG_BYPASS)
    if script_code:
        scripts.append(script_code)

    combined_script = "\n\n".join(scripts)

    try:
        pid = dev.spawn([package])
        session = dev.attach(pid)

        messages: list[dict[str, Any]] = []

        if combined_script:
            frida_script = session.create_script(combined_script)

            def on_message(msg: dict[str, Any], _data: Any) -> None:
                messages.append(msg)

            frida_script.on("message", on_message)
            frida_script.load()

        if not pause:
            dev.resume(pid)

        # Store session
        sm = _get_session_mgr(arguments)
        frida_sess = FridaSession(
            device_type=device_id or dev.id,
            target_name=package,
            pid=pid,
        )
        session_id = await sm.create_session(frida_sess)

        time.sleep(0.5)  # Wait for initial messages

        return text_result({
            "session_id": session_id,
            "pid": pid,
            "package": package,
            "device": dev.id,
            "scripts_loaded": len(scripts),
            "paused": pause,
            "initial_messages": messages[:20],
        })

    except Exception as e:
        return error_result(f"Frida spawn failed: {e}")


# ---------------------------------------------------------------------------
# Tool: re_android_frida_attach
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_frida_attach",
    description=(
        "Attach Frida to a running Android process by PID or package name."
    ),
    category="android",
    input_schema={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Package name to attach to.",
            },
            "pid": {
                "type": "integer",
                "description": "Process ID to attach to.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "script": {
                "type": "string",
                "description": "Frida JS script to inject after attach.",
            },
        },
    },
)
async def handle_frida_attach(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Attach Frida to running process."""
    package = arguments.get("package_name")
    pid = arguments.get("pid")
    device_id = arguments.get("device")
    script_code = arguments.get("script")

    # Enforce script size limit (1 MB)
    if script_code and len(script_code) > 1_048_576:
        return error_result("Frida script exceeds maximum size (1 MB)")

    if not package and not pid:
        return error_result("Provide package_name or pid")

    try:
        import frida
    except ImportError:
        return error_result("frida not installed")

    try:
        dev = frida.get_device(device_id) if device_id else frida.get_usb_device(timeout=5)
    except Exception as e:
        return error_result(f"Device not found: {e}")

    try:
        if pid:
            session = dev.attach(pid)
            target_pid = pid
        else:
            session = dev.attach(package)
            target_pid = session.pid

        messages: list[dict[str, Any]] = []

        if script_code:
            frida_script = session.create_script(script_code)

            def on_message(msg: dict[str, Any], _data: Any) -> None:
                messages.append(msg)

            frida_script.on("message", on_message)
            frida_script.load()

        sm = _get_session_mgr(arguments)
        frida_sess = FridaSession(
            device_type=device_id or dev.id,
            target_name=package or str(pid),
            pid=target_pid,
        )
        session_id = await sm.create_session(frida_sess)

        time.sleep(0.3)

        return text_result({
            "session_id": session_id,
            "pid": target_pid,
            "target": package or str(pid),
            "device": dev.id,
            "messages": messages[:20],
        })

    except Exception as e:
        return error_result(f"Frida attach failed: {e}")


# ---------------------------------------------------------------------------
# Tool: re_android_hook
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_hook",
    description=(
        "Hook Android Java methods via Frida: intercept calls, modify arguments/return values, "
        "log method invocations. Supports overloaded methods."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name", "hooks"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Target package name.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "hooks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["class_name", "method_name"],
                    "properties": {
                        "class_name": {
                            "type": "string",
                            "description": "Fully qualified Java class name.",
                        },
                        "method_name": {
                            "type": "string",
                            "description": "Method name to hook.",
                        },
                        "arg_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Argument types for overloaded methods.",
                        },
                        "on_enter": {
                            "type": "string",
                            "description": "JS code for onEnter callback.",
                        },
                        "on_leave": {
                            "type": "string",
                            "description": "JS code for onLeave callback.",
                        },
                        "return_value": {
                            "type": "string",
                            "description": "Override return value (JS expression).",
                        },
                    },
                },
                "description": "Array of method hooks to install.",
            },
            "spawn": {
                "type": "boolean",
                "description": "Spawn app (true) or attach to running (false). Default: true.",
            },
        },
    },
)
async def handle_hook(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Install Java method hooks."""
    package = arguments["package_name"]
    hooks = arguments["hooks"]
    device_id = arguments.get("device")
    spawn = arguments.get("spawn", True)

    # Generate Frida script from hook definitions
    hook_blocks: list[str] = []
    for i, hook in enumerate(hooks):
        cls = _js_escape(hook["class_name"])
        method = _js_escape(hook["method_name"])
        arg_types = hook.get("arg_types")
        on_enter = hook.get("on_enter", "")
        on_leave = hook.get("on_leave", "")
        return_val = hook.get("return_value")

        if arg_types:
            overload_args = ", ".join(f"'{_js_escape(t)}'" for t in arg_types)
            method_ref = f".overload({overload_args})"
        else:
            method_ref = ""

        enter_code = on_enter or f"""
            send({{
                type: 'hook',
                hook_id: {i},
                class: '{cls}',
                method: '{method}',
                args: Array.prototype.slice.call(arguments).map(String)
            }});
        """

        leave_code = ""
        if return_val:
            leave_code = f"retval.replace({return_val});"
        elif on_leave:
            leave_code = on_leave

        block = f"""
        try {{
            var cls_{i} = Java.use('{cls}');
            cls_{i}.{method}{method_ref}.implementation = function() {{
                {enter_code}
                var retval = this.{method}{method_ref}.apply(this, arguments);
                {leave_code}
                return retval;
            }};
            send({{type: 'hook_installed', hook_id: {i}, class: '{cls}', method: '{method}'}});
        }} catch(e) {{
            send({{type: 'hook_error', hook_id: {i}, error: e.toString()}});
        }}
        """
        hook_blocks.append(block)

    script_code = "Java.perform(function() {\n" + "\n".join(hook_blocks) + "\n});"

    # Delegate to spawn/attach
    spawn_args: dict[str, Any] = {
        "package_name": package,
        "device": device_id,
        "script": script_code,
    }
    if "__config__" in arguments:
        spawn_args["__config__"] = arguments["__config__"]

    if spawn:
        return await handle_frida_spawn(spawn_args)
    else:
        return await handle_frida_attach(spawn_args)


# ---------------------------------------------------------------------------
# Tool: re_android_trace
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_trace",
    description=(
        "Trace Android method calls: Java method tracing, native function tracing, "
        "or syscall tracing via Frida."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name", "trace_type"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Target package name.",
            },
            "trace_type": {
                "type": "string",
                "enum": ["java", "native", "syscall"],
                "description": "Type of tracing.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "class_filter": {
                "type": "string",
                "description": "For java: class name/prefix to trace (e.g. 'com.example.*').",
            },
            "method_filter": {
                "type": "string",
                "description": "Method name filter.",
            },
            "module_name": {
                "type": "string",
                "description": "For native: .so module name to trace.",
            },
            "function_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "For native: specific function names to trace.",
            },
            "syscall_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "For syscall: specific syscall names (e.g. ['open', 'read', 'write']).",
            },
        },
    },
)
async def handle_trace(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Trace method/function/syscall calls."""
    package = arguments["package_name"]
    trace_type = arguments["trace_type"]
    device_id = arguments.get("device")

    if trace_type == "java":
        class_filter = _js_escape(arguments.get("class_filter", "*"))
        method_filter = _js_escape(arguments.get("method_filter", "*"))

        script = f"""
        Java.perform(function() {{
            var classFilter = '{class_filter}';
            var methodFilter = '{method_filter}';

            Java.enumerateLoadedClasses({{
                onMatch: function(className) {{
                    if (classFilter !== '*' && className.indexOf(classFilter.replace('*','')) === -1) return;

                    try {{
                        var cls = Java.use(className);
                        var methods = cls.class.getDeclaredMethods();
                        methods.forEach(function(m) {{
                            var name = m.getName();
                            if (methodFilter !== '*' && name.indexOf(methodFilter.replace('*','')) === -1) return;

                            try {{
                                cls[name].overloads.forEach(function(overload) {{
                                    overload.implementation = function() {{
                                        var args = Array.prototype.slice.call(arguments).map(String);
                                        send({{
                                            type: 'trace',
                                            trace_type: 'java',
                                            class: className,
                                            method: name,
                                            args: args.slice(0, 5),
                                            timestamp: Date.now()
                                        }});
                                        return this[name].apply(this, arguments);
                                    }};
                                }});
                            }} catch(e) {{}}
                        }});
                    }} catch(e) {{}}
                }},
                onComplete: function() {{
                    send({{type: 'trace_setup', status: 'complete', trace_type: 'java'}});
                }}
            }});
        }});
        """

    elif trace_type == "native":
        module = arguments.get("module_name")
        func_names = arguments.get("function_names", [])

        if module and func_names:
            # Trace specific functions
            attach_blocks = []
            safe_module = _js_escape(module)
            for fn in func_names:
                safe_fn = _js_escape(fn)
                attach_blocks.append(f"""
                try {{
                    var addr = Module.findExportByName('{safe_module}', '{safe_fn}');
                    if (addr) {{
                        Interceptor.attach(addr, {{
                            onEnter: function(args) {{
                                send({{
                                    type: 'trace',
                                    trace_type: 'native',
                                    module: '{safe_module}',
                                    function: '{safe_fn}',
                                    args: [args[0], args[1], args[2]].map(String),
                                    timestamp: Date.now()
                                }});
                            }}
                        }});
                    }}
                }} catch(e) {{ send({{type: 'error', function: '{safe_fn}', error: e.toString()}}); }}
                """)
            script = "\n".join(attach_blocks)
        elif module:
            # Trace all exports in module
            safe_module = _js_escape(module)
            script = f"""
            var exports = Module.enumerateExports('{safe_module}');
            exports.forEach(function(exp) {{
                if (exp.type === 'function') {{
                    try {{
                        Interceptor.attach(exp.address, {{
                            onEnter: function(args) {{
                                send({{
                                    type: 'trace',
                                    trace_type: 'native',
                                    module: '{safe_module}',
                                    function: exp.name,
                                    timestamp: Date.now()
                                }});
                            }}
                        }});
                    }} catch(e) {{}}
                }}
            }});
            send({{type: 'trace_setup', module: '{safe_module}', exports_hooked: exports.length}});
            """
        else:
            return error_result("module_name required for native tracing")

    elif trace_type == "syscall":
        syscalls = arguments.get("syscall_names", ["open", "read", "write", "connect"])
        attach_blocks = []
        for sc in syscalls:
            safe_sc = _js_escape(sc)
            attach_blocks.append(f"""
            try {{
                var addr = Module.findExportByName(null, '{safe_sc}');
                if (addr) {{
                    Interceptor.attach(addr, {{
                        onEnter: function(args) {{
                            send({{
                                type: 'trace',
                                trace_type: 'syscall',
                                syscall: '{safe_sc}',
                                args: [args[0], args[1], args[2]].map(String),
                                timestamp: Date.now()
                            }});
                        }}
                    }});
                }}
            }} catch(e) {{}}
            """)
        script = "\n".join(attach_blocks)
    else:
        return error_result(f"Unknown trace_type: {trace_type}")

    spawn_args: dict[str, Any] = {
        "package_name": package,
        "device": device_id,
        "script": script,
    }
    if "__config__" in arguments:
        spawn_args["__config__"] = arguments["__config__"]

    return await handle_frida_spawn(spawn_args)


# ---------------------------------------------------------------------------
# Tool: re_android_root_bypass
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_root_bypass",
    description=(
        "Apply common Android security bypasses via Frida: root detection, "
        "SSL pinning, anti-debug, or all combined."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name", "bypass_type"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Target package name.",
            },
            "bypass_type": {
                "type": "string",
                "enum": ["root", "ssl", "anti_debug", "all"],
                "description": "Type of bypass to apply.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "spawn": {
                "type": "boolean",
                "description": "Spawn (true) or attach (false). Default: true.",
            },
        },
    },
)
async def handle_bypass(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply security bypasses."""
    bypass_type = arguments["bypass_type"]

    startup_map = {
        "root": "root_bypass",
        "ssl": "ssl_bypass",
        "anti_debug": "anti_debug_bypass",
        "all": "all",
    }

    spawn_args: dict[str, Any] = {
        "package_name": arguments["package_name"],
        "device": arguments.get("device"),
        "startup_script": startup_map.get(bypass_type, "all"),
    }
    if "__config__" in arguments:
        spawn_args["__config__"] = arguments["__config__"]

    if arguments.get("spawn", True):
        return await handle_frida_spawn(spawn_args)
    else:
        return await handle_frida_attach(spawn_args)


# ---------------------------------------------------------------------------
# Tool: re_android_memory
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_memory",
    description=(
        "Android runtime memory analysis via Frida: dump memory regions, "
        "search for patterns, read/write memory, dump class instances."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name", "action"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Target package name.",
            },
            "action": {
                "type": "string",
                "enum": [
                    "list_modules",
                    "list_ranges",
                    "search_pattern",
                    "dump_class_instances",
                    "read_memory",
                    "heap_search",
                ],
                "description": "Memory action to perform.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "module_name": {
                "type": "string",
                "description": "Module name for list_ranges.",
            },
            "pattern": {
                "type": "string",
                "description": "Hex pattern for search (e.g. 'DE AD BE EF').",
            },
            "class_name": {
                "type": "string",
                "description": "Java class for dump_class_instances.",
            },
            "address": {
                "type": "string",
                "description": "Memory address for read_memory (hex, e.g. '0x7f000000').",
            },
            "size": {
                "type": "integer",
                "description": "Number of bytes for read_memory. Default: 256.",
            },
        },
    },
)
async def handle_memory(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Android memory analysis."""
    action = arguments["action"]
    package = arguments["package_name"]

    if action == "list_modules":
        script = """
        var modules = Process.enumerateModules();
        var result = modules.map(function(m) {
            return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
        });
        send({type: 'result', action: 'list_modules', data: result});
        """

    elif action == "list_ranges":
        module = arguments.get("module_name", "")
        if module:
            script = f"""
            var mod = Process.findModuleByName('{module}');
            if (mod) {{
                var ranges = mod.enumerateRanges('---');
                send({{type: 'result', action: 'list_ranges', module: '{module}',
                       data: ranges.map(function(r) {{
                           return {{base: r.base.toString(), size: r.size, protection: r.protection}};
                       }})}});
            }} else {{
                send({{type: 'error', message: 'Module not found: {module}'}});
            }}
            """
        else:
            script = """
            var ranges = Process.enumerateRanges('r--');
            send({type: 'result', action: 'list_ranges',
                  data: ranges.slice(0, 200).map(function(r) {
                      return {base: r.base.toString(), size: r.size, protection: r.protection};
                  })});
            """

    elif action == "search_pattern":
        pattern = arguments.get("pattern", "")
        if not pattern:
            return error_result("pattern required for search_pattern")
        script = f"""
        var pattern = '{pattern}';
        var ranges = Process.enumerateRanges('r--');
        var results = [];
        ranges.forEach(function(range) {{
            try {{
                var matches = Memory.scanSync(range.base, range.size, pattern);
                matches.forEach(function(m) {{
                    results.push({{address: m.address.toString(), size: m.size}});
                }});
            }} catch(e) {{}}
        }});
        send({{type: 'result', action: 'search_pattern', pattern: pattern,
               matches: results.slice(0, 1000)}});
        """

    elif action == "dump_class_instances":
        cls = arguments.get("class_name")
        if not cls:
            return error_result("class_name required")
        script = f"""
        Java.perform(function() {{
            Java.choose('{cls}', {{
                onMatch: function(instance) {{
                    try {{
                        send({{
                            type: 'result',
                            action: 'class_instance',
                            class: '{cls}',
                            toString: instance.toString(),
                            hashCode: instance.hashCode()
                        }});
                    }} catch(e) {{}}
                }},
                onComplete: function() {{
                    send({{type: 'result', action: 'dump_complete', class: '{cls}'}});
                }}
            }});
        }});
        """

    elif action == "read_memory":
        addr = arguments.get("address")
        size = arguments.get("size", 256)
        if not addr:
            return error_result("address required")
        script = f"""
        try {{
            var ptr = new NativePointer('{addr}');
            var data = ptr.readByteArray({size});
            send({{type: 'result', action: 'read_memory', address: '{addr}', size: {size}}}, data);
        }} catch(e) {{
            send({{type: 'error', message: e.toString()}});
        }}
        """

    elif action == "heap_search":
        cls = arguments.get("class_name")
        if not cls:
            return error_result("class_name required for heap_search")
        script = f"""
        Java.perform(function() {{
            var instances = [];
            Java.choose('{cls}', {{
                onMatch: function(inst) {{
                    var fields = {{}};
                    try {{
                        var clsRef = Java.use('{cls}');
                        var declaredFields = clsRef.class.getDeclaredFields();
                        for (var i = 0; i < declaredFields.length; i++) {{
                            declaredFields[i].setAccessible(true);
                            var name = declaredFields[i].getName();
                            try {{
                                fields[name] = String(declaredFields[i].get(inst));
                            }} catch(e) {{
                                fields[name] = '<error>';
                            }}
                        }}
                    }} catch(e) {{}}
                    instances.push({{toString: inst.toString(), fields: fields}});
                }},
                onComplete: function() {{
                    send({{type: 'result', action: 'heap_search', class: '{cls}',
                           count: instances.length, instances: instances.slice(0, 50)}});
                }}
            }});
        }});
        """
    else:
        return error_result(f"Unknown action: {action}")

    spawn_args: dict[str, Any] = {
        "package_name": package,
        "device": arguments.get("device"),
        "script": script,
    }
    if "__config__" in arguments:
        spawn_args["__config__"] = arguments["__config__"]

    return await handle_frida_attach(spawn_args)
