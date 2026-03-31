"""
Revula Test Suite — Security hardening tests (v3).

Tests for:
- validate_path() hardening (null bytes, pseudo-FS, size limits, extensions, symlinks)
- safe_subprocess_sync() string command rejection
- safe_subprocess() timeout + command list enforcement
- No unguarded subprocess usage in codebase
"""

from __future__ import annotations

import errno
import os
import tempfile
from pathlib import Path

import pytest

from revula.sandbox import (
    PathValidationError,
    safe_subprocess_sync,
    validate_path,
)

# ---------------------------------------------------------------------------
# validate_path — Null byte injection
# ---------------------------------------------------------------------------


class TestValidatePathNullByte:
    """Null byte injection must be rejected."""

    def test_null_byte_in_filename(self, tmp_dir: Path) -> None:
        with pytest.raises(PathValidationError, match=r"[Nn]ull"):
            validate_path(str(tmp_dir / "file\x00.txt"), [str(tmp_dir)])

    def test_null_byte_in_directory(self, tmp_dir: Path) -> None:
        with pytest.raises(PathValidationError, match=r"[Nn]ull"):
            validate_path(str(tmp_dir) + "\x00/file.txt", [str(tmp_dir)])

    def test_null_byte_embedded_mid_path(self, tmp_dir: Path) -> None:
        with pytest.raises(PathValidationError, match=r"[Nn]ull"):
            validate_path(f"{tmp_dir}/a\x00b/c.bin", [str(tmp_dir)])


# ---------------------------------------------------------------------------
# validate_path — Pseudo-filesystem blocking
# ---------------------------------------------------------------------------


class TestValidatePathPseudoFS:
    """Paths under /proc, /sys, /dev must be blocked."""

    @pytest.mark.parametrize(
        "dangerous_path",
        [
            "/proc/self/environ",
            "/proc/1/cmdline",
            "/sys/class/net/eth0",
            "/dev/sda",
            "/dev/null",
        ],
    )
    def test_pseudo_fs_blocked(self, dangerous_path: str) -> None:
        with pytest.raises(PathValidationError):
            validate_path(dangerous_path, ["/"])


# ---------------------------------------------------------------------------
# validate_path — Basic path traversal
# ---------------------------------------------------------------------------


class TestValidatePathTraversal:
    """Path traversal must be rejected."""

    def test_dot_dot_traversal(self, tmp_dir: Path) -> None:
        with pytest.raises(PathValidationError):
            validate_path(str(tmp_dir / ".." / ".." / "etc" / "passwd"), [str(tmp_dir)])

    def test_allowed_path_succeeds(self, tmp_dir: Path) -> None:
        target = tmp_dir / "test.bin"
        target.write_bytes(b"\x00" * 10)
        result = validate_path(str(target), [str(tmp_dir)])
        assert result == target.resolve()

    def test_empty_path_rejected(self, tmp_dir: Path) -> None:
        with pytest.raises((PathValidationError, ValueError)):
            validate_path("", [str(tmp_dir)])


# ---------------------------------------------------------------------------
# validate_path — File size limits
# ---------------------------------------------------------------------------


class TestValidatePathSizeLimit:
    """File size enforcement via max_size_mb."""

    def test_file_under_limit_passes(self, tmp_dir: Path) -> None:
        target = tmp_dir / "small.bin"
        target.write_bytes(b"\x00" * 100)
        result = validate_path(str(target), [str(tmp_dir)], max_size_mb=1)
        assert result == target.resolve()

    def test_file_over_limit_rejected(self, tmp_dir: Path) -> None:
        target = tmp_dir / "big.bin"
        # Write 2MB
        target.write_bytes(b"\x00" * (2 * 1024 * 1024))
        with pytest.raises(PathValidationError, match=r"[Ss]ize|[Ll]arge|[Ee]xceed"):
            validate_path(str(target), [str(tmp_dir)], max_size_mb=1)

    def test_no_limit_allows_any_size(self, tmp_dir: Path) -> None:
        target = tmp_dir / "any.bin"
        target.write_bytes(b"\x00" * (5 * 1024 * 1024))
        # No max_size_mb param → should pass
        result = validate_path(str(target), [str(tmp_dir)])
        assert result == target.resolve()


# ---------------------------------------------------------------------------
# validate_path — Extension whitelist
# ---------------------------------------------------------------------------


class TestValidatePathExtensions:
    """allowed_extensions enforcement."""

    def test_allowed_extension_passes(self, tmp_dir: Path) -> None:
        target = tmp_dir / "test.bin"
        target.write_bytes(b"\x00")
        result = validate_path(
            str(target), [str(tmp_dir)], allowed_extensions=[".bin", ".elf"]
        )
        assert result == target.resolve()

    def test_disallowed_extension_rejected(self, tmp_dir: Path) -> None:
        target = tmp_dir / "test.exe"
        target.write_bytes(b"\x00")
        with pytest.raises(PathValidationError, match=r"[Ee]xtension|[Tt]ype|[Nn]ot allowed"):
            validate_path(
                str(target), [str(tmp_dir)], allowed_extensions=[".bin", ".elf"]
            )

    def test_no_extension_filter_allows_all(self, tmp_dir: Path) -> None:
        target = tmp_dir / "test.xyz"
        target.write_bytes(b"\x00")
        result = validate_path(str(target), [str(tmp_dir)])
        assert result == target.resolve()


# ---------------------------------------------------------------------------
# validate_path — Regular file check
# ---------------------------------------------------------------------------


class TestValidatePathFileType:
    """Non-regular files (directories, symlinks to outside) must be handled."""

    def test_directory_rejected(self, tmp_dir: Path) -> None:
        subdir = tmp_dir / "subdir"
        subdir.mkdir()
        with pytest.raises(PathValidationError):
            validate_path(str(subdir), [str(tmp_dir)])

    def test_symlink_inside_allowed_dir(self, tmp_dir: Path) -> None:
        target = tmp_dir / "real.bin"
        target.write_bytes(b"\x00")
        link = tmp_dir / "link.bin"
        try:
            link.symlink_to(target)
        except OSError as exc:
            if exc.errno == errno.EPERM or getattr(exc, "winerror", None) == 1314:
                pytest.skip("Symlink creation requires elevated privileges on this Windows setup")
            raise
        # Should resolve through symlink and pass
        result = validate_path(str(link), [str(tmp_dir)])
        assert result == target.resolve()


# ---------------------------------------------------------------------------
# safe_subprocess_sync — String command rejection
# ---------------------------------------------------------------------------


class TestSafeSubprocessSync:
    """safe_subprocess_sync must reject string commands to prevent shell injection."""

    def test_string_command_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match=r"[Ll]ist|[Ss]tring|[Ss]hell"):
            safe_subprocess_sync("echo hello")  # type: ignore[arg-type]

    def test_list_command_succeeds(self) -> None:
        result = safe_subprocess_sync(["echo", "test"])
        assert result.success
        assert "test" in result.stdout

    def test_string_with_pipe_rejected(self) -> None:
        with pytest.raises(TypeError):
            safe_subprocess_sync("cat /etc/passwd | head")  # type: ignore[arg-type]

    def test_string_with_semicolon_rejected(self) -> None:
        with pytest.raises(TypeError):
            safe_subprocess_sync("echo a; rm -rf /")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# safe_subprocess_sync — Timeout enforcement
# ---------------------------------------------------------------------------


class TestSafeSubprocessTimeout:
    """Subprocess timeout must be enforced."""

    def test_fast_command_no_timeout(self) -> None:
        result = safe_subprocess_sync(["echo", "fast"], timeout=10)
        assert result.success
        assert not result.timed_out

    def test_slow_command_times_out(self) -> None:
        result = safe_subprocess_sync(["sleep", "30"], timeout=1)
        assert result.timed_out
        assert not result.success


# ---------------------------------------------------------------------------
# Codebase security invariants
# ---------------------------------------------------------------------------


class TestCodebaseSecurityInvariants:
    """Verify no raw subprocess or shell=True leaks into source."""

    def test_no_raw_subprocess_run(self) -> None:
        """No unguarded subprocess.run() calls outside sandbox.py."""
        import re
        src_root = Path(__file__).parent.parent / "src" / "revula"
        violations: list[str] = []
        for py_file in src_root.rglob("*.py"):
            if py_file.name == "sandbox.py":
                continue
            text = py_file.read_text(encoding="utf-8")
            # Look for subprocess.run( not inside comments/strings
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'"):
                    continue
                if re.search(r"subprocess\.run\s*\(", stripped):
                    violations.append(f"{py_file.name}:{i}")
        assert not violations, f"Raw subprocess.run() found in: {violations}"

    def test_no_shell_true(self) -> None:
        """No shell=True in any source file (excluding comments and strings)."""
        import ast
        src_root = Path(__file__).parent.parent / "src" / "revula"
        violations: list[str] = []
        for py_file in src_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            # Use AST to find string literal line ranges so we can skip them
            string_lines: set[int] = set()
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.Constant,)) and isinstance(node.value, str):
                        if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                                string_lines.add(ln)
            except SyntaxError:
                pass  # If file doesn't parse, fall back to line-by-line
            for i, line in enumerate(text.splitlines(), 1):
                if i in string_lines:
                    continue
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                # Strip inline comment
                code_part = stripped.split("#")[0]
                if "shell=True" in code_part and "shell=False" not in code_part:
                    violations.append(f"{py_file.name}:{i}")
        assert not violations, f"shell=True found in: {violations}"

    def test_no_eval_or_exec(self) -> None:
        """No Python eval() or exec() in source code."""
        import re as regex_mod
        src_root = Path(__file__).parent.parent / "src" / "revula"
        violations: list[str] = []
        for py_file in src_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith('"') or stripped.startswith("'"):
                    continue
                # Match eval( or exec( as standalone calls, not mi_exec or similar
                if regex_mod.search(r"\beval\s*\(", stripped) or regex_mod.search(r"(?<!_)\bexec\s*\(", stripped):
                    violations.append(f"{py_file.name}:{i}")
        assert not violations, f"eval/exec found in: {violations}"


class TestVulnerabilityHardeningV3:
    """Tests for v3 hardening fixes."""

    def test_no_fstring_in_subprocess_python_code(self) -> None:
        """No f-string interpolation into Python source passed to subprocess -c."""
        import re as regex_mod
        src_root = Path(__file__).parent.parent / "src" / "revula"
        violations: list[str] = []
        for py_file in src_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            # Look for patterns like: ["python3", "-c", f"...{var}..."]
            # This finds dangerous code injection patterns
            matches = regex_mod.finditer(
                r'"-c"\s*,\s*f["\']',
                text,
            )
            for m in matches:
                line_num = text[:m.start()].count("\n") + 1
                violations.append(f"{py_file.name}:{line_num}")
        assert not violations, f"Potential code injection via f-string subprocess -c: {violations}"

    def test_no_mktemp_usage(self) -> None:
        """No insecure tempfile.mktemp() usage (TOCTOU race)."""
        src_root = Path(__file__).parent.parent / "src" / "revula"
        violations: list[str] = []
        for py_file in src_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                if "mktemp(" in stripped and "tempfile.mktemp" in stripped:
                    violations.append(f"{py_file.name}:{i}")
        assert not violations, f"Insecure tempfile.mktemp() found: {violations}"

    def test_no_hardcoded_tmp_paths(self) -> None:
        """No hardcoded /tmp/ paths in tool code (except comments/strings)."""
        import ast
        src_root = Path(__file__).parent.parent / "src" / "revula" / "tools"
        violations: list[str] = []
        for py_file in src_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            # Use AST to find string literal ranges
            string_lines: set[int] = set()
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                                string_lines.add(ln)
            except SyntaxError:
                pass
            for i, line in enumerate(text.splitlines(), 1):
                if i in string_lines:
                    continue
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                # Look for hardcoded /tmp/ assignments (not in tempfile calls)
                if '"/tmp/' in stripped and "tempfile" not in stripped:
                    violations.append(f"{py_file.name}:{i}")
        assert not violations, f"Hardcoded /tmp paths found: {violations}"

    def test_validate_path_failclosed_without_config(self) -> None:
        """validate_path should use config defaults when allowed_dirs is None."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"\x00" * 16)
            temp_path = tf.name
        try:
            # With allowed_dirs=None, it should fall back to config defaults
            # which default to ["/"], so this should pass
            result = validate_path(temp_path, allowed_dirs=None, must_exist=True)
            assert result.exists()
        finally:
            os.unlink(temp_path)

    def test_frida_js_escape_helper(self) -> None:
        """_js_escape properly escapes dangerous characters."""
        from revula.tools.dynamic.frida import _js_escape
        assert "\\'" in _js_escape("test'injection")
        assert "\\\\" in _js_escape("test\\path")
        assert "\\n" in _js_escape("test\nnewline")
        assert "\\0" in _js_escape("test\x00null")
        # Clean string should pass through unchanged
        assert _js_escape("clean_string_123") == "clean_string_123"

    def test_shellcode_emulate_no_injection(self) -> None:
        """Shellcode emulator should reject non-hex input."""
        # Read the shellcode.py file and verify it validates hex input
        src_file = Path(__file__).parent.parent / "src" / "revula" / "tools" / "exploit" / "shellcode.py"
        text = src_file.read_text()
        # The fix should include hex character validation
        assert "re.fullmatch" in text or "set(shellcode_hex" in text or "all(c in" in text, \
            "shellcode.py should validate hex input characters"
