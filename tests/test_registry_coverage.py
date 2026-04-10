from __future__ import annotations

import ast
from pathlib import Path

import pytest

from revula.config import TOOL_BINARIES
from revula.server import _register_all_tools
from revula.tools import TOOL_REGISTRY

_register_all_tools()
ALL_TOOL_DEFS = TOOL_REGISTRY.all()
ALL_TOOL_NAMES = [tool.name for tool in ALL_TOOL_DEFS]
TOOLS_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "revula" / "tools"

_EXTERNAL_CALL_NAMES = {
    "safe_subprocess",
    "run_command",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "shutil.which",
}


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return func.attr
    return ""


def _is_tool_registration(decorator: ast.expr) -> bool:
    if not isinstance(decorator, ast.Call):
        return False
    if not isinstance(decorator.func, ast.Attribute):
        return False
    if decorator.func.attr != "register":
        return False
    return isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == "TOOL_REGISTRY"


def _has_requires_tools(decorator: ast.Call) -> bool:
    for kw in decorator.keywords:
        if kw.arg != "requires_tools":
            continue
        if isinstance(kw.value, (ast.List, ast.Tuple)):
            return len(kw.value.elts) > 0
        return True
    return False


def test_every_registered_tool_has_basic_metadata() -> None:
    assert ALL_TOOL_DEFS, "No tools registered"
    for tool in ALL_TOOL_DEFS:
        assert tool.name.startswith("re_")
        assert tool.description.strip()
        assert tool.category.strip()
        assert tool.input_schema.get("type") == "object"


def test_requires_tools_keys_are_known() -> None:
    missing = sorted(
        {
            key
            for tool in ALL_TOOL_DEFS
            for key in tool.requires_tools
            if key not in TOOL_BINARIES
        },
    )
    assert not missing, f"Unknown requires_tools keys: {missing}"


@pytest.mark.parametrize("tool_name", ALL_TOOL_NAMES)
def test_registry_contains_every_registered_tool(tool_name: str) -> None:
    assert TOOL_REGISTRY.get(tool_name) is not None


def test_subprocess_using_handlers_declare_requires_tools() -> None:
    missing: list[str] = []
    for py_file in TOOLS_SRC_ROOT.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            registration = next(
                (d for d in node.decorator_list if _is_tool_registration(d)),
                None,
            )
            if not isinstance(registration, ast.Call):
                continue
            uses_external = any(
                isinstance(n, ast.Call)
                and (
                    _call_name(n) in _EXTERNAL_CALL_NAMES
                    or _call_name(n).startswith("subprocess.")
                )
                for n in ast.walk(node)
            )
            if uses_external and not _has_requires_tools(registration):
                rel = py_file.relative_to(TOOLS_SRC_ROOT.parent.parent)
                missing.append(f"{rel}:{node.lineno}:{node.name}")
    assert not missing, f"Missing requires_tools on subprocess handlers: {missing}"
