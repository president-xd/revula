#!/usr/bin/env python3
"""
Revula — Download frida-server binaries for Android.

Downloads frida-server binaries matching the installed frida-python version
(or a specified version) for one or more Android architectures.

Usage:
    python scripts/utils/download_frida_server.py
    python scripts/utils/download_frida_server.py --arches arm64 arm
    python scripts/utils/download_frida_server.py --version 16.5.2 --output-dir /tmp/frida
"""
from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_RELEASE_URL = "https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"
VALID_ARCHES = ("arm64", "arm", "x86_64", "x86")
DEFAULT_OUTPUT_DIR = Path.home() / ".revula" / "cache" / "frida"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def info(msg: str) -> None:
    print(_color("34", "[INFO]") + f"  {msg}")

def success(msg: str) -> None:
    print(_color("32", "[  OK]") + f"  {msg}")

def warn(msg: str) -> None:
    print(_color("33", "[WARN]") + f"  {msg}")

def error(msg: str) -> None:
    print(_color("31", "[ERR!]") + f"  {msg}", file=sys.stderr)


def detect_frida_version() -> str:
    """Detect the installed frida-python version."""
    try:
        import frida  # type: ignore[import-untyped]
        return frida.__version__
    except ImportError:
        info("frida module not importable; falling back to pip metadata lookup")

    # Fallback: try pip show
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", "frida"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    except Exception as e:
        warn(f"Unable to query frida version via pip: {e}")

    return ""


def decompress_xz(xz_path: Path, output_path: Path) -> bool:
    """Decompress an .xz file. Tries lzma module first, then xz command."""
    try:
        import lzma
        with lzma.open(xz_path, "rb") as f_in:
            with open(output_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        return True
    except Exception as e:
        warn(f"Python lzma decompression failed, trying xz binary: {e}")

    # Fallback to xz command
    if shutil.which("xz"):
        try:
            # Copy xz to a temp name and decompress in place
            temp_xz = output_path.with_suffix(".xz")
            shutil.copy2(xz_path, temp_xz)
            subprocess.run(["xz", "-d", "-f", str(temp_xz)], check=True, timeout=60)
            return output_path.exists()
        except Exception as e:
            warn(f"xz decompression failed: {e}")

    return False


def download_file(url: str, dest: Path) -> bool:
    """Download a file with progress indication."""
    try:
        info(f"Downloading: {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "revula/0.1"})

        with urllib.request.urlopen(req, timeout=120) as response:
            total = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 64

            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = downloaded * 100 // total
                        mb = downloaded / (1024 * 1024)
                        print(f"\r  Progress: {pct}% ({mb:.1f} MB)", end="", flush=True)

            if total > 0:
                print()  # newline after progress
        return True
    except Exception as e:
        error(f"Download failed: {e}")
        return False


def sha256sum(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Main download logic
# ---------------------------------------------------------------------------

def download_frida_server(
    version: str,
    arch: str,
    output_dir: Path,
) -> Path | None:
    """Download and extract frida-server for a given arch. Returns path or None."""
    output_dir.mkdir(parents=True, exist_ok=True)

    binary_name = f"frida-server-{version}-android-{arch}"
    final_path = output_dir / binary_name

    if final_path.exists():
        success(f"Already cached: {final_path}")
        return final_path

    url = GITHUB_RELEASE_URL.format(version=version, arch=arch)
    xz_path = output_dir / f"{binary_name}.xz"

    if not download_file(url, xz_path):
        xz_path.unlink(missing_ok=True)
        return None

    info(f"Decompressing {binary_name}.xz ...")
    if not decompress_xz(xz_path, final_path):
        error(f"Failed to decompress {xz_path}")
        xz_path.unlink(missing_ok=True)
        return None

    xz_path.unlink(missing_ok=True)

    # Make executable
    final_path.chmod(0o755)

    file_hash = sha256sum(final_path)
    success(f"Ready: {final_path}")
    info(f"  SHA-256: {file_hash}")
    info(f"  Size: {final_path.stat().st_size / (1024*1024):.1f} MB")

    return final_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download frida-server binaries for Android.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # auto-detect version, download arm64
  %(prog)s --arches arm64 arm x86_64    # download for multiple arches
  %(prog)s --version 16.5.2             # pin a specific version
  %(prog)s --output-dir /tmp/frida      # custom output directory
        """,
    )
    parser.add_argument(
        "--arches",
        nargs="+",
        default=["arm64"],
        choices=VALID_ARCHES,
        help=f"Target architectures (default: arm64). Valid: {', '.join(VALID_ARCHES)}",
    )
    parser.add_argument(
        "--version",
        default="",
        help="Frida version to download (default: match installed frida-python)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   Revula — Frida Server Downloader                  ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Determine version
    version = args.version
    if not version:
        info("Auto-detecting frida-python version...")
        version = detect_frida_version()
        if not version:
            error("Could not detect frida version. Install frida or use --version.")
            sys.exit(1)
    success(f"Frida version: {version}")

    arches: list[str] = args.arches
    output_dir: Path = args.output_dir
    info(f"Architectures: {', '.join(arches)}")
    info(f"Output directory: {output_dir}")
    print()

    # Download each
    results: dict[str, Path | None] = {}
    for arch in arches:
        results[arch] = download_frida_server(version, arch, output_dir)
        print()

    # Summary
    print("══════════════════════════════════════════════════════")
    ok = sum(1 for v in results.values() if v is not None)
    fail = sum(1 for v in results.values() if v is None)
    print(f"  Downloaded: {ok}  |  Failed: {fail}")
    for arch, path in results.items():
        status = _color("32", "✓") if path else _color("31", "✗")
        loc = str(path) if path else "FAILED"
        print(f"  {status} {arch}: {loc}")
    print("══════════════════════════════════════════════════════")
    print()

    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
