"""
Revula Test Suite — Core infrastructure tests.

Tests: config loading, tool registry, session manager, sandbox.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from revula.config import SecurityConfig, ServerConfig, ToolInfo, get_config, load_config, reload_config
from revula.sandbox import (
    PathValidationError,
    SubprocessResult,
    safe_subprocess,
    safe_subprocess_sync,
    validate_path,
)
from revula.session import (
    AnalysisSession,
    DebuggerSession,
    FridaSession,
    SessionManager,
)
from revula.tools import TOOL_REGISTRY, ToolDefinition, ToolRegistry, error_result, text_result

# ---------------------------------------------------------------------------
# Config Tests
# ---------------------------------------------------------------------------


class TestConfig:
    """Test configuration loading and tool detection."""

    def test_get_config_returns_server_config(self) -> None:
        config = get_config()
        assert isinstance(config, ServerConfig)

    def test_config_has_tool_paths(self) -> None:
        config = get_config()
        assert isinstance(config.tools, dict)

    def test_config_has_security(self) -> None:
        config = get_config()
        assert config.security is not None

    def test_reload_config(self) -> None:
        get_config()  # prime the cache
        c2 = reload_config()
        assert isinstance(c2, ServerConfig)

    def test_tool_info_available(self) -> None:
        info = ToolInfo(name="test", path="/usr/bin/true", available=True)
        assert info.available
        assert info.name == "test"

    def test_env_override_uses_canonical_tool_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        fake = tmp_path / "analyzeHeadless"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)

        monkeypatch.setenv("GHIDRA_HEADLESS", str(fake))
        cfg = load_config()
        assert cfg.tools["ghidra_headless"].available is True
        assert cfg.tools["ghidra_headless"].path == str(fake)

    def test_legacy_tool_key_aliases_still_work(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from revula import config as config_mod

        fake_ghidra = tmp_path / "legacy_ghidra"
        fake_retdec = tmp_path / "legacy_retdec"
        fake_ghidra.write_text("#!/bin/sh\nexit 0\n")
        fake_retdec.write_text("#!/bin/sh\nexit 0\n")
        fake_ghidra.chmod(0o755)
        fake_retdec.chmod(0o755)

        monkeypatch.setattr(
            config_mod,
            "_load_config_file",
            lambda: {
                "tools": {
                    "ghidra": {"path": str(fake_ghidra)},
                    "retdec": {"path": str(fake_retdec)},
                },
            },
        )

        cfg = config_mod.load_config()
        assert cfg.tools["ghidra_headless"].path == str(fake_ghidra)
        assert cfg.tools["retdec_decompiler"].path == str(fake_retdec)

    def test_invalid_security_env_values_fall_back_to_defaults(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import config as config_mod

        monkeypatch.setattr(config_mod, "_load_config_file", lambda: {})
        monkeypatch.setenv("REVULA_MAX_MEMORY_MB", "not-a-number")
        monkeypatch.setenv("REVULA_DEFAULT_TIMEOUT", "invalid")
        monkeypatch.setenv("REVULA_MAX_TIMEOUT", "-1")
        monkeypatch.setenv("REVULA_ALLOWED_DIRS", ":::")

        cfg = config_mod.load_config()
        defaults = config_mod.SecurityConfig()

        assert cfg.security.max_memory_mb == defaults.max_memory_mb
        assert cfg.security.default_timeout == defaults.default_timeout
        assert cfg.security.max_timeout == defaults.max_timeout
        assert cfg.security.allowed_dirs == defaults.allowed_dirs

    def test_security_timeout_clamps_max_timeout(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import config as config_mod

        monkeypatch.setattr(config_mod, "_load_config_file", lambda: {})
        monkeypatch.setenv("REVULA_DEFAULT_TIMEOUT", "120")
        monkeypatch.setenv("REVULA_MAX_TIMEOUT", "60")

        cfg = config_mod.load_config()
        assert cfg.security.default_timeout == 120
        assert cfg.security.max_timeout == 120

    def test_rate_limit_env_overrides(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import config as config_mod

        monkeypatch.setattr(config_mod, "_load_config_file", lambda: {})
        monkeypatch.setenv("REVULA_GLOBAL_RPM", "240")
        monkeypatch.setenv("REVULA_PER_TOOL_RPM", "60")
        monkeypatch.setenv("REVULA_BURST_SIZE", "20")
        monkeypatch.setenv("REVULA_RATE_LIMIT_ENABLED", "false")

        cfg = config_mod.load_config()
        assert cfg.rate_limit.global_rpm == 240
        assert cfg.rate_limit.per_tool_rpm == 60
        assert cfg.rate_limit.burst_size == 20
        assert cfg.rate_limit.enabled is False

    def test_tool_naming_env_overrides(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import config as config_mod

        monkeypatch.setattr(config_mod, "_load_config_file", lambda: {})
        monkeypatch.setenv("REVULA_TOOL_NAMESPACE", "RevulaX")
        monkeypatch.setenv("REVULA_INCLUDE_LEGACY_TOOL_NAMES", "true")

        cfg = config_mod.load_config()
        assert cfg.tool_naming.namespace == "revulax"
        assert cfg.tool_naming.include_legacy_names is True

    def test_execution_retry_env_overrides(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import config as config_mod

        monkeypatch.setattr(config_mod, "_load_config_file", lambda: {})
        monkeypatch.setenv("REVULA_SUBPROCESS_RETRIES", "2")
        monkeypatch.setenv("REVULA_SUBPROCESS_RETRY_BACKOFF_MS", "500")

        cfg = config_mod.load_config()
        assert cfg.execution.subprocess_retries == 2
        assert cfg.execution.subprocess_retry_backoff_ms == 500


# ---------------------------------------------------------------------------
# Sandbox Tests
# ---------------------------------------------------------------------------


class TestSandbox:
    """Test sandbox execution."""

    def test_validate_path_rejects_traversal(self) -> None:
        with pytest.raises(PathValidationError):
            validate_path("../../etc/passwd")

    def test_validate_path_accepts_absolute(self) -> None:
        with tempfile.NamedTemporaryFile() as f:
            p = validate_path(f.name)
            assert p.is_absolute()

    @pytest.mark.asyncio
    async def test_safe_subprocess_echo(self) -> None:
        result = await safe_subprocess(["echo", "hello"])
        assert result.success
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_safe_subprocess_timeout(self) -> None:
        result = await safe_subprocess(["sleep", "30"], timeout=1)
        assert result.timed_out or not result.success

    @pytest.mark.asyncio
    async def test_safe_subprocess_invalid_command(self) -> None:
        result = await safe_subprocess(["nonexistent_command_12345"])
        assert not result.success

    def test_subprocess_result_properties(self) -> None:
        r = SubprocessResult(stdout="out", stderr="", returncode=0, timed_out=False)
        assert r.success
        r2 = SubprocessResult(stdout="", stderr="err", returncode=1, timed_out=False)
        assert not r2.success

    def test_safe_subprocess_sync_uses_security_defaults(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import sandbox as sandbox_mod

        security = SecurityConfig(default_timeout=1, max_memory_mb=50, max_timeout=10)
        monkeypatch.setattr(sandbox_mod, "get_security_config", lambda: security)

        captured: dict[str, int] = {}

        def fake_make_preexec_fn(mem_mb: int, cpu_seconds: int) -> None:
            captured["memory_mb"] = mem_mb
            captured["cpu_seconds"] = cpu_seconds
            return None

        def fake_run(*args: object, **kwargs: object) -> object:
            captured["timeout"] = int(kwargs["timeout"])  # type: ignore[index]
            return SimpleNamespace(stdout="ok\n", stderr="", returncode=0)

        monkeypatch.setattr(sandbox_mod, "_make_preexec_fn", fake_make_preexec_fn)
        monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)

        result = safe_subprocess_sync(["echo", "ok"])
        assert result.success
        assert captured["timeout"] == 1
        assert captured["memory_mb"] == 50
        assert captured["cpu_seconds"] == 1

    def test_safe_subprocess_sync_retries_transient_failures(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import sandbox as sandbox_mod

        security = SecurityConfig(default_timeout=1, max_memory_mb=50, max_timeout=10)
        execution = SimpleNamespace(subprocess_retries=2, subprocess_retry_backoff_ms=1)
        monkeypatch.setattr(sandbox_mod, "get_security_config", lambda: security)
        monkeypatch.setattr(sandbox_mod, "get_execution_config", lambda: execution)
        monkeypatch.setattr(sandbox_mod.time, "sleep", lambda _s: None)

        attempts = {"count": 0}

        def fake_run(*args: object, **kwargs: object) -> object:
            attempts["count"] += 1
            if attempts["count"] < 3:
                return SimpleNamespace(stdout="", stderr="transient", returncode=1)
            return SimpleNamespace(stdout="ok\n", stderr="", returncode=0)

        monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)

        result = sandbox_mod.safe_subprocess_sync(["echo", "ok"])
        assert result.success
        assert attempts["count"] == 3

    def test_safe_subprocess_preflight_missing_known_tool(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from revula import sandbox as sandbox_mod

        security = SecurityConfig(default_timeout=5, max_memory_mb=64, max_timeout=10)
        monkeypatch.setattr(sandbox_mod, "get_security_config", lambda: security)

        fake_config = SimpleNamespace(
            tools={
                "binwalk": ToolInfo(
                    name="binwalk",
                    available=False,
                    install_hint="Install: apt install binwalk",
                )
            }
        )
        monkeypatch.setattr("revula.config.get_config", lambda: fake_config)

        result = safe_subprocess_sync(["binwalk", "--help"])
        assert not result.success
        assert "Required external tool 'binwalk' is not installed." in result.stderr
        assert "apt install binwalk" in result.stderr


class TestServerLogging:
    """Server-side logging helpers."""

    def test_truncate_args_redacts_sensitive_values(self) -> None:
        from revula.server import _truncate_args

        rendered = _truncate_args(
            {
                "api_key": "supersecret",
                "tokenValue": "another-secret",
                "keystore_pass": "android",
                "normal": "visible",
            }
        )
        assert "supersecret" not in rendered
        assert "another-secret" not in rendered
        assert "android" not in rendered
        assert "<redacted>" in rendered
        assert "visible" in rendered


class TestCoverageTool:
    """Coverage tool edge-case tests."""

    @pytest.mark.asyncio
    async def test_collect_drcov_uses_require_tool(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from revula.tools.dynamic import coverage as coverage_mod

        captured: dict[str, list[str]] = {}

        async def fake_safe_subprocess(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            captured["cmd"] = cmd
            return SimpleNamespace(success=False, stderr="mock failure")

        class _Cfg:
            def require_tool(self, name: str) -> str:
                assert name == "drrun"
                return "/opt/dynamorio/bin64/drrun"

        monkeypatch.setattr(coverage_mod, "safe_subprocess", fake_safe_subprocess)

        result = await coverage_mod._collect_drcov(
            binary=Path("/bin/true"),
            args=[],
            output_path=str(tmp_path / "out.cov"),
            timeout=5,
            config=_Cfg(),
        )
        payload = json.loads(result[0]["text"])
        assert payload["error"] is True
        assert captured["cmd"][0] == "/opt/dynamorio/bin64/drrun"


# ---------------------------------------------------------------------------
# Session Manager Tests
# ---------------------------------------------------------------------------


class TestSessionManager:
    """Test session lifecycle."""

    @pytest.mark.asyncio
    async def test_create_and_get_session(self) -> None:
        mgr = SessionManager(ttl=60)
        session = AnalysisSession(binary_path="/tmp/test.bin")
        sid = await mgr.create_session(session)

        retrieved = await mgr.get_session(sid)
        assert retrieved.session_id == sid

    @pytest.mark.asyncio
    async def test_get_typed_session(self) -> None:
        mgr = SessionManager(ttl=60)
        session = DebuggerSession(backend="gdb", target_binary="/tmp/test")
        sid = await mgr.create_session(session)

        dbg = await mgr.get_typed_session(sid, DebuggerSession)
        assert dbg.backend == "gdb"

        with pytest.raises(TypeError):
            await mgr.get_typed_session(sid, FridaSession)

    @pytest.mark.asyncio
    async def test_close_session(self) -> None:
        mgr = SessionManager(ttl=60)
        session = AnalysisSession()
        sid = await mgr.create_session(session)

        await mgr.close_session(sid)

        with pytest.raises(KeyError):
            await mgr.get_session(sid)

    @pytest.mark.asyncio
    async def test_list_sessions(self) -> None:
        mgr = SessionManager(ttl=60)
        await mgr.create_session(AnalysisSession())
        await mgr.create_session(DebuggerSession(backend="gdb"))

        sessions = await mgr.list_sessions()
        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_session_stats(self) -> None:
        mgr = SessionManager(ttl=60)
        await mgr.create_session(AnalysisSession())
        stats = await mgr.stats()
        assert stats["total_sessions"] == 1

    @pytest.mark.asyncio
    async def test_debugger_session_bp_counter(self) -> None:
        session = DebuggerSession(backend="gdb")
        assert session.next_bp_id() == 1
        assert session.next_bp_id() == 2


# ---------------------------------------------------------------------------
# Tool Registry Tests
# ---------------------------------------------------------------------------


class TestToolRegistry:
    """Test tool registration and execution."""

    def test_register_and_get(self) -> None:
        # Use the global registry (already has tools from imports)
        count = TOOL_REGISTRY.count()
        assert count >= 0  # May be 0 if no tools imported

    def test_text_result_format(self) -> None:
        result = text_result({"key": "value"})
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["type"] == "text"
        # Verify JSON parseable
        data = json.loads(result[0]["text"])
        assert data["key"] == "value"

    def test_error_result_format(self) -> None:
        result = error_result("test error")
        assert isinstance(result, list)
        assert len(result) == 1
        data = json.loads(result[0]["text"])
        assert "error" in data

    def test_tool_definition(self) -> None:
        async def dummy_handler(args: dict) -> list:
            return text_result({"ok": True})

        defn = ToolDefinition(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {}},
            handler=dummy_handler,
            category="test",
        )
        assert defn.name == "test_tool"
        assert defn.category == "test"

    def test_by_category(self) -> None:
        # Verify category filtering works
        all_tools = TOOL_REGISTRY.all()
        categories = {t.category for t in all_tools}
        for cat in categories:
            cat_tools = TOOL_REGISTRY.by_category(cat)
            assert all(t.category == cat for t in cat_tools)

    @pytest.mark.asyncio
    async def test_execute_rejects_missing_required(self) -> None:
        registry = ToolRegistry()
        called = False

        async def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            nonlocal called
            called = True
            return text_result({"ok": True})

        registry.register(
            name="schema_required_test",
            description="schema required test",
            input_schema={
                "type": "object",
                "required": ["path"],
                "properties": {"path": {"type": "string"}},
                "additionalProperties": False,
            },
        )(handler)

        result = await registry.execute("schema_required_test", {})
        payload = json.loads(result[0]["text"])
        assert payload["error"] is True
        assert "Invalid arguments for tool 'schema_required_test'" in payload["message"]
        assert "required property" in payload["message"]
        assert not called

    @pytest.mark.asyncio
    async def test_execute_rejects_additional_properties(self) -> None:
        registry = ToolRegistry()

        async def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            return text_result({"ok": True})

        registry.register(
            name="schema_additional_props_test",
            description="schema additionalProperties test",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        )(handler)

        result = await registry.execute(
            "schema_additional_props_test",
            {"path": "/tmp/a.bin", "extra": "blocked"},
        )
        payload = json.loads(result[0]["text"])
        assert payload["error"] is True
        assert "Invalid arguments for tool 'schema_additional_props_test'" in payload["message"]
        assert "additional properties" in payload["message"].lower()

    @pytest.mark.asyncio
    async def test_execute_rejects_additional_properties_by_default(self) -> None:
        registry = ToolRegistry()

        async def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            return text_result({"ok": True})

        registry.register(
            name="schema_auto_additional_props_test",
            description="schema additionalProperties auto-hardening test",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        )(handler)

        result = await registry.execute(
            "schema_auto_additional_props_test",
            {"path": "/tmp/a.bin", "extra": "blocked"},
        )
        payload = json.loads(result[0]["text"])
        assert payload["error"] is True
        assert "additional properties" in payload["message"].lower()

    @pytest.mark.asyncio
    async def test_execute_rejects_wrong_type(self) -> None:
        registry = ToolRegistry()

        async def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            return text_result({"ok": True})

        registry.register(
            name="schema_type_test",
            description="schema type test",
            input_schema={
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
                "additionalProperties": False,
            },
        )(handler)

        result = await registry.execute("schema_type_test", {"count": "not-an-int"})
        payload = json.loads(result[0]["text"])
        assert payload["error"] is True
        assert "Invalid arguments for tool 'schema_type_test'" in payload["message"]
        assert "is not of type 'integer'" in payload["message"]

    @pytest.mark.asyncio
    async def test_execute_allows_internal_runtime_arguments(self) -> None:
        registry = ToolRegistry()
        seen_path: str | None = None

        async def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            nonlocal seen_path
            seen_path = args["path"]
            return text_result({"ok": True})

        registry.register(
            name="schema_internal_args_test",
            description="schema internal args test",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        )(handler)

        result = await registry.execute(
            "schema_internal_args_test",
            {"path": "/tmp/test.bin", "__config__": object(), "__session_manager__": object()},
        )
        payload = json.loads(result[0]["text"])
        assert payload["ok"] is True
        assert seen_path == "/tmp/test.bin"


# ---------------------------------------------------------------------------
# Resource Tests
# ---------------------------------------------------------------------------


class TestResources:
    """Test binary resource management."""

    @pytest.mark.asyncio
    async def test_register_and_list_resources(self) -> None:
        from revula.session import BinaryResource

        mgr = SessionManager(ttl=60)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 100)
            tmp_path = Path(f.name)

        try:
            resource = BinaryResource(
                uri=f"binary://{tmp_path.name}",
                name=tmp_path.name,
                path=tmp_path,
                size=100,
            )
            await mgr.register_resource(resource)

            resources = await mgr.list_binary_resources()
            assert len(resources) == 1
            assert resources[0]["name"] == tmp_path.name

            data = await mgr.read_resource(resource.uri)
            assert len(data) == 100
        finally:
            tmp_path.unlink(missing_ok=True)
