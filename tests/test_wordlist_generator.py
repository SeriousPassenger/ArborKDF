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
    Path("third_party/arborkdf-wordlists/en_tr_jp_131072.txt"),
    Path("third_party/arborkdf-wordlists/en_tr_jp_131072.manifest.json"),
    Path("include/arborkdf/generated/bip39_english_wordlist.hpp"),
    Path("include/arborkdf/generated/en_tr_jp_131072_wordlist.hpp"),
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
    mutations = (
        (Path("third_party/bip39/english.txt"), "SHA-512 mismatch"),
        (
            Path("third_party/arborkdf-wordlists/en_tr_jp_131072.txt"),
            "expected 1262297 bytes",
        ),
        (
            Path(
                "third_party/arborkdf-wordlists/"
                "en_tr_jp_131072.manifest.json"
            ),
            "SHA-512 mismatch",
        ),
        (
            Path("include/arborkdf/generated/bip39_english_wordlist.hpp"),
            "generated header is stale",
        ),
        (
            Path(
                "include/arborkdf/generated/"
                "en_tr_jp_131072_wordlist.hpp"
            ),
            "generated header is stale",
        ),
    )
    for relative, expected_error in mutations:
        with tempfile.TemporaryDirectory(
            prefix="arborkdf-wordlist-integrity-"
        ) as name:
            root = Path(name)
            prepare_tree(root)
            result = run_check(root)
            if result.returncode != 0:
                raise RuntimeError(
                    f"clean generator check failed: {result.stderr}"
                )
            target = root / relative
            target.write_bytes(target.read_bytes()[:-1])
            require_failure(run_check(root), expected_error)

    print("wordlist generator integrity tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
