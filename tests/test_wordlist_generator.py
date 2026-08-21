#!/usr/bin/env python3
"""Negative integrity tests for the embedded-wordlist generator."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RELATIVE_FILES = (
    Path("extras/gen_wordlist_header.py"),
    Path("third_party/bip39/english.txt"),
    Path("include/arborkdf/generated/bip39_english_wordlist.hpp"),
)


def prepare_tree(destination: Path) -> None:
    for relative in RELATIVE_FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / relative, target)


def run_check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(root / "extras/gen_wordlist_header.py"), "--check"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )


def require_failure(result: subprocess.CompletedProcess[str], text: str) -> None:
    if result.returncode == 0:
        raise RuntimeError("generator check unexpectedly accepted mutated data")
    if text not in result.stderr:
        raise RuntimeError(
            f"generator failure did not contain {text!r}: {result.stderr!r}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="arborkdf-wordlist-source-") as name:
        root = Path(name)
        prepare_tree(root)
        result = run_check(root)
        if result.returncode != 0:
            raise RuntimeError(f"clean generator check failed: {result.stderr}")
        source = root / "third_party/bip39/english.txt"
        source.write_bytes(source.read_bytes()[:-1])
        require_failure(run_check(root), "SHA-512 mismatch")

    with tempfile.TemporaryDirectory(prefix="arborkdf-wordlist-header-") as name:
        root = Path(name)
        prepare_tree(root)
        header = root / "include/arborkdf/generated/bip39_english_wordlist.hpp"
        header.write_bytes(header.read_bytes()[:-1])
        require_failure(run_check(root), "generated header is stale")

    print("wordlist generator integrity tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
