"""
Revula Android Traffic Interception + Activity Monitor.

Network traffic capture, mitmproxy integration, and
Android Activity/Intent monitoring via Frida.
"""

from __future__ import annotations

import logging
import shutil
import textwrap
from typing import Any

from revula.sandbox import safe_subprocess
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool: re_android_traffic_intercept
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_traffic_intercept",
    description=(
        "Intercept Android network traffic: configure proxy, capture HTTP/HTTPS "
        "requests via Frida hooks on OkHttp/HttpURLConnection/WebView, or manage "
        "mitmproxy/Burp proxy settings."
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
                    "hook_http",
                    "set_proxy",
                    "clear_proxy",
                    "capture_urls",
                    "hook_dns",
                ],
                "description": "Traffic interception action.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "proxy_host": {
                "type": "string",
                "description": "Proxy host for set_proxy (e.g. '192.168.1.100').",
            },
            "proxy_port": {
                "type": "integer",
                "description": "Proxy port. Default: 8080.",
            },
        },
    },
)
async def handle_traffic_intercept(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Android traffic interception."""
    action = arguments["action"]
    package = arguments["package_name"]
    device = arguments.get("device")

    adb = shutil.which("adb")
    if not adb:
        return error_result("adb not found on PATH")

    if action == "set_proxy":
        host = arguments.get("proxy_host", "127.0.0.1")
        port = arguments.get("proxy_port", 8080)
        cmd = [adb]
        if device:
            cmd.extend(["-s", device])
        cmd.extend(["shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"])
        proc = await safe_subprocess(cmd, timeout=10)
        return text_result({
            "action": "set_proxy",
            "proxy": f"{host}:{port}",
            "success": proc.returncode == 0,
        })

    elif action == "clear_proxy":
        cmd = [adb]
        if device:
            cmd.extend(["-s", device])
        cmd.extend(["shell", "settings", "put", "global", "http_proxy", ":0"])
        proc = await safe_subprocess(cmd, timeout=10)
        return text_result({"action": "clear_proxy", "success": proc.returncode == 0})

    elif action == "hook_http":
        script = textwrap.dedent("""\
        Java.perform(function() {
            // OkHttp3 interceptor
            try {
                var OkHttpClient = Java.use('okhttp3.OkHttpClient');
                var Builder = Java.use('okhttp3.OkHttpClient$Builder');
                var Interceptor = Java.use('okhttp3.Interceptor');

                var Response = Java.use('okhttp3.Response');
                var Request = Java.use('okhttp3.Request');

                Request.url.implementation = function() {
                    var url = this.url();
                    send({type: 'http', library: 'okhttp3', method: 'request',
                          url: url.toString()});
                    return url;
                };
            } catch(e) {}

            // HttpURLConnection
            try {
                var HttpURLConnection = Java.use('java.net.HttpURLConnection');
                HttpURLConnection.getInputStream.implementation = function() {
                    send({type: 'http', library: 'HttpURLConnection',
                          url: this.getURL().toString(),
                          method: this.getRequestMethod()});
                    return this.getInputStream();
                };
            } catch(e) {}

            // WebView
            try {
                var WebView = Java.use('android.webkit.WebView');
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    send({type: 'http', library: 'WebView', url: url});
                    return this.loadUrl(url);
                };
            } catch(e) {}

            send({type: 'setup', action: 'hook_http', status: 'complete'});
        });
        """)

        # Import and use frida_android spawn
        from revula.tools.android.frida_android import handle_frida_spawn

        spawn_args: dict[str, Any] = {
            "package_name": package,
            "device": device,
            "script": script,
        }
        if "__config__" in arguments:
            spawn_args["__config__"] = arguments["__config__"]
        return await handle_frida_spawn(spawn_args)

    elif action == "capture_urls":
        script = textwrap.dedent("""\
        Java.perform(function() {
            var URL = Java.use('java.net.URL');
            URL.$init.overload('java.lang.String').implementation = function(url) {
                send({type: 'url', url: url});
                return this.$init(url);
            };

            var URI = Java.use('java.net.URI');
            URI.create.implementation = function(uri) {
                send({type: 'uri', uri: uri});
                return this.create(uri);
            };

            send({type: 'setup', action: 'capture_urls', status: 'complete'});
        });
        """)

        from revula.tools.android.frida_android import handle_frida_spawn

        spawn_args = {
            "package_name": package,
            "device": device,
            "script": script,
        }
        if "__config__" in arguments:
            spawn_args["__config__"] = arguments["__config__"]
        return await handle_frida_spawn(spawn_args)

    elif action == "hook_dns":
        script = textwrap.dedent("""\
        // Hook DNS resolution
        Interceptor.attach(Module.findExportByName(null, 'getaddrinfo'), {
            onEnter: function(args) {
                this.host = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                send({type: 'dns', host: this.host, result: retval.toInt32()});
            }
        });

        Java.perform(function() {
            var InetAddress = Java.use('java.net.InetAddress');
            InetAddress.getByName.implementation = function(host) {
                send({type: 'dns_java', host: host});
                return this.getByName(host);
            };
        });

        send({type: 'setup', action: 'hook_dns', status: 'complete'});
        """)

        from revula.tools.android.frida_android import handle_frida_spawn

        spawn_args = {
            "package_name": package,
            "device": device,
            "script": script,
        }
        if "__config__" in arguments:
            spawn_args["__config__"] = arguments["__config__"]
        return await handle_frida_spawn(spawn_args)

    return error_result(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# Tool: re_android_activity_monitor
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_activity_monitor",
    description=(
        "Monitor Android Activity lifecycle, Intent routing, Fragment transitions, "
        "and BroadcastReceiver invocations via Frida."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Target package name.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "monitor_types": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["activity", "intent", "fragment", "broadcast", "content_provider"],
                },
                "description": "What to monitor. Default: all.",
            },
        },
    },
)
async def handle_activity_monitor(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Monitor Activity/Intent/Fragment lifecycle."""
    package = arguments["package_name"]
    device = arguments.get("device")
    monitor_types = arguments.get("monitor_types", ["activity", "intent", "fragment", "broadcast"])

    script_parts: list[str] = ["Java.perform(function() {"]

    if "activity" in monitor_types:
        script_parts.append("""
        // Activity lifecycle
        var Activity = Java.use('android.app.Activity');
        var lifecycle = ['onCreate', 'onStart', 'onResume', 'onPause', 'onStop', 'onDestroy'];
        lifecycle.forEach(function(method) {
            try {
                Activity[method].overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        send({type: 'activity_lifecycle', activity: this.getClass().getName(),
                              method: method, timestamp: Date.now()});
                        return overload.apply(this, arguments);
                    };
                });
            } catch(e) {}
        });
        """)

    if "intent" in monitor_types:
        script_parts.append("""
        // Intent monitoring
        var Activity = Java.use('android.app.Activity');
        Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
            send({type: 'intent', action: intent.getAction(),
                  component: intent.getComponent() ? intent.getComponent().toString() : null,
                  data: intent.getDataString(),
                  extras: intent.getExtras() ? intent.getExtras().toString() : null,
                  source: this.getClass().getName(), timestamp: Date.now()});
            return this.startActivity(intent);
        };

        Activity.startActivityForResult.overload(
            'android.content.Intent', 'int').implementation = function(intent, code) {
            send({type: 'intent_for_result', action: intent.getAction(),
                  component: intent.getComponent() ? intent.getComponent().toString() : null,
                  request_code: code, source: this.getClass().getName()});
            return this.startActivityForResult(intent, code);
        };
        """)

    if "fragment" in monitor_types:
        script_parts.append("""
        // Fragment lifecycle
        try {
            var Fragment = Java.use('androidx.fragment.app.Fragment');
            ['onAttach', 'onCreate', 'onCreateView', 'onResume', 'onPause', 'onDetach'].forEach(function(m) {
                try {
                    Fragment[m].overloads.forEach(function(overload) {
                        overload.implementation = function() {
                            send({type: 'fragment_lifecycle', fragment: this.getClass().getName(),
                                  method: m, timestamp: Date.now()});
                            return overload.apply(this, arguments);
                        };
                    });
                } catch(e) {}
            });
        } catch(e) {}
        """)

    if "broadcast" in monitor_types:
        script_parts.append("""
        // BroadcastReceiver
        var BroadcastReceiver = Java.use('android.content.BroadcastReceiver');
        BroadcastReceiver.onReceive.implementation = function(context, intent) {
            send({type: 'broadcast', receiver: this.getClass().getName(),
                  action: intent.getAction(),
                  data: intent.getDataString(), timestamp: Date.now()});
            return this.onReceive(context, intent);
        };
        """)

    if "content_provider" in monitor_types:
        script_parts.append("""
        // ContentResolver queries
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overloads.forEach(function(overload) {
            overload.implementation = function() {
                var uri = arguments[0];
                send({type: 'content_provider_query', uri: uri ? uri.toString() : null,
                      timestamp: Date.now()});
                return overload.apply(this, arguments);
            };
        });
        """)

    script_parts.append("send({type: 'monitor_setup', monitors: " + str(monitor_types).replace("'", '"') + "});")
    script_parts.append("});")

    script = "\n".join(script_parts)

    from revula.tools.android.frida_android import handle_frida_spawn

    spawn_args: dict[str, Any] = {
        "package_name": package,
        "device": device,
        "script": script,
    }
    if "__config__" in arguments:
        spawn_args["__config__"] = arguments["__config__"]
    return await handle_frida_spawn(spawn_args)


# ---------------------------------------------------------------------------
# Tool: re_android_crypto_monitor
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_android_crypto_monitor",
    description=(
        "Monitor cryptographic operations in an Android app via Frida: "
        "javax.crypto.Cipher, MessageDigest, SecretKeySpec, KeyStore, MAC. "
        "Captures algorithms, keys, IVs, and plaintext/ciphertext."
    ),
    category="android",
    input_schema={
        "type": "object",
        "required": ["package_name"],
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Target package name.",
            },
            "device": {
                "type": "string",
                "description": "Device serial.",
            },
            "capture_data": {
                "type": "boolean",
                "description": "Capture input/output data (may be large). Default: true.",
            },
        },
    },
)
async def handle_crypto_monitor(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Monitor crypto operations."""
    package = arguments["package_name"]
    device = arguments.get("device")
    capture_data = arguments.get("capture_data", True)

    data_capture = "true" if capture_data else "false"

    script = textwrap.dedent(f"""\
    Java.perform(function() {{
        var captureData = {data_capture};

        function bytesToHex(bytes) {{
            if (!bytes) return null;
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {{
                hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
            }}
            return hex;
        }}

        // Cipher
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(transform) {{
            send({{type: 'crypto', api: 'Cipher.getInstance', transform: transform}});
            return this.getInstance(transform);
        }};

        Cipher.init.overloads.forEach(function(overload) {{
            overload.implementation = function() {{
                var mode = arguments[0];
                var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'mode_' + mode;
                var key = arguments[1];
                var info = {{type: 'crypto', api: 'Cipher.init', mode: modeStr,
                            algorithm: this.getAlgorithm()}};
                if (key && key.getEncoded) {{
                    info.key_hex = bytesToHex(key.getEncoded());
                    info.key_algorithm = key.getAlgorithm();
                }}
                if (arguments.length > 2 && arguments[2]) {{
                    try {{ info.iv_hex = bytesToHex(arguments[2].getIV()); }} catch(e) {{}}
                }}
                send(info);
                return overload.apply(this, arguments);
            }};
        }});

        if (captureData) {{
            Cipher.doFinal.overload('[B').implementation = function(input) {{
                var output = this.doFinal(input);
                send({{type: 'crypto', api: 'Cipher.doFinal',
                      algorithm: this.getAlgorithm(),
                      input_hex: bytesToHex(input),
                      output_hex: bytesToHex(output),
                      input_size: input.length,
                      output_size: output.length}});
                return output;
            }};
        }}

        // MessageDigest
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {{
            send({{type: 'crypto', api: 'MessageDigest.getInstance', algorithm: algo}});
            return this.getInstance(algo);
        }};

        MessageDigest.digest.overload('[B').implementation = function(input) {{
            var output = this.digest(input);
            send({{type: 'crypto', api: 'MessageDigest.digest',
                  algorithm: this.getAlgorithm(),
                  input_size: input.length,
                  output_hex: bytesToHex(output)}});
            return output;
        }};

        // SecretKeySpec
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {{
            send({{type: 'crypto', api: 'SecretKeySpec', algorithm: algo,
                  key_hex: bytesToHex(key), key_size: key.length * 8}});
            return this.$init(key, algo);
        }};

        // MAC
        try {{
            var Mac = Java.use('javax.crypto.Mac');
            Mac.getInstance.overload('java.lang.String').implementation = function(algo) {{
                send({{type: 'crypto', api: 'Mac.getInstance', algorithm: algo}});
                return this.getInstance(algo);
            }};
        }} catch(e) {{}}

        // KeyStore
        try {{
            var KeyStore = Java.use('java.security.KeyStore');
            KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {{
                send({{type: 'crypto', api: 'KeyStore.getInstance', keystore_type: type}});
                return this.getInstance(type);
            }};
        }} catch(e) {{}}

        send({{type: 'setup', action: 'crypto_monitor', status: 'complete'}});
    }});
    """)

    from revula.tools.android.frida_android import handle_frida_spawn

    spawn_args: dict[str, Any] = {
        "package_name": package,
        "device": device,
        "script": script,
    }
    if "__config__" in arguments:
        spawn_args["__config__"] = arguments["__config__"]
    return await handle_frida_spawn(spawn_args)
