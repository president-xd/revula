from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text(encoding="utf-8")


def _load_generate_toml():
    script_path = REPO_ROOT / "scripts" / "setup" / "setup_config_toml.py"
    spec = importlib.util.spec_from_file_location("setup_config_toml", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.generate_toml


def test_docker_test_script_is_stdio_only() -> None:
    text = _read("scripts/docker/test.sh")
    assert "--sse" not in text
    assert "--list-tools" not in text
    assert "docker compose --profile stdio run --rm revula-stdio" in text


def test_install_script_does_not_force_full_extra() -> None:
    text = _read("scripts/install/install_all.sh")
    assert "[full]" not in text
    assert 'install -e "${project_root}"' in text
    assert 'install "revula"' in text


def test_setup_config_emits_ghidra_headless_schema() -> None:
    generate_toml = _load_generate_toml()
    toml = generate_toml(
        ["/tmp"],
        {"ghidra_headless.path": "/opt/ghidra/support/analyzeHeadless"},
        {"max_memory_mb": 512, "default_timeout": 60, "max_timeout": 600},
        {"enabled": True, "global_rpm": 120, "per_tool_rpm": 30, "burst_size": 10},
        {"namespace": "revula", "include_legacy_names": False},
        {"subprocess_retries": 1, "subprocess_retry_backoff_ms": 250},
    )
    assert "[tools.ghidra_headless]" in toml
    assert "headless_path" not in toml


def test_readme_docker_script_description_matches_current_behavior() -> None:
    readme = _read("README.md")
    assert "tests all tools: Ghidra, angr, Frida" not in readme
