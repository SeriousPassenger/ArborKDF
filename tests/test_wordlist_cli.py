#!/usr/bin/env python3
"""Cross-platform integration tests for embedded-wordlist discovery/export."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


EXPECTED_SELECTORS = ("embedded_bip39", "embedded_en_tr_jp_131072")
EXPECTED_BIP39_SHA512 = (
    "416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8b"
    "aed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123"
)
EXPECTED_COMBINED_SHA512 = (
    "e59905f19627e0f98e72887187463f9a0767592612ec337a8ff5e71e373f96d7"
    "e5b5c4066427ceb89a8acbb13bd5092327e92f7802b0afc2e64ee83e58780c8a"
)
EXPECTED_COMBINED_FIRST_WORD = "kyounenji"


def run(program: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(program), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def require_success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed with {result.returncode}: {result.stderr!r}"
        )


def parse_catalog(text: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for block in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(": ")
            if not separator or key in fields:
                raise RuntimeError(f"invalid wordlist-list line: {line!r}")
            fields[key] = value
        selector = fields.get("selector")
        if selector is None or selector in result:
            raise RuntimeError("missing or duplicate selector in wordlist list")
        result[selector] = fields
    return result


def parse_counts(value: str) -> dict[str, int]:
    if value == "none":
        return {}
    result: dict[str, int] = {}
    for item in value.split(","):
        label, separator, count = item.partition("=")
        if not separator or label in result:
            raise RuntimeError(f"invalid count field: {value!r}")
        result[label] = int(count)
    return result


def check_export(
    program: Path, selector: str, metadata: dict[str, str], output: Path
) -> bytes:
    result = run(
        program,
        "wordlist",
        "export",
        "--wordlist",
        selector,
        "--output",
        str(output),
    )
    require_success(result)
    raw = output.read_bytes()
    raw.decode("utf-8")
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise RuntimeError(f"{selector}: export is not canonical LF text")
    if raw.count(b"\n") != int(metadata["entries"]):
        raise RuntimeError(f"{selector}: exported line count mismatch")
    if len(raw) != int(metadata["canonical-bytes"]):
        raise RuntimeError(f"{selector}: exported byte count mismatch")
    if hashlib.sha512(raw).hexdigest() != metadata["sha512"]:
        raise RuntimeError(f"{selector}: exported SHA-512 mismatch")
    return raw


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_wordlist_cli.py PROGRAM", file=sys.stderr)
        return 2
    program = Path(sys.argv[1]).resolve()

    listed = run(program, "wordlist", "list")
    require_success(listed)
    catalog = parse_catalog(listed.stdout)
    if tuple(catalog) != EXPECTED_SELECTORS:
        raise RuntimeError(f"unexpected selector order: {tuple(catalog)!r}")

    bip39 = catalog["embedded_bip39"]
    if bip39["entries"] != "2048" or bip39["bits-per-word"] != "11":
        raise RuntimeError("incorrect BIP-39 size metadata")
    if bip39["byte-aligned-block-bits"] != "88":
        raise RuntimeError("incorrect BIP-39 byte-alignment metadata")
    if bip39["sha512"] != EXPECTED_BIP39_SHA512:
        raise RuntimeError("incorrect BIP-39 SHA-512 metadata")

    combined = catalog["embedded_en_tr_jp_131072"]
    if combined["standard-id"] != "ArborKDF-en-tr-jp-131072-v1":
        raise RuntimeError("incorrect combined wordlist standard identifier")
    if combined["entries"] != "131072" or combined["bits-per-word"] != "17":
        raise RuntimeError("incorrect combined wordlist size metadata")
    if combined["byte-aligned-block-bits"] != "136":
        raise RuntimeError("incorrect combined wordlist byte-alignment metadata")
    if combined["sha512"] != EXPECTED_COMBINED_SHA512:
        raise RuntimeError("incorrect combined wordlist SHA-512 metadata")
    if combined["canonical-bytes"] != "1262297":
        raise RuntimeError("incorrect combined wordlist canonical byte count")
    memberships = parse_counts(combined["language-memberships"])
    overlaps = parse_counts(combined["exact-overlaps"])
    if memberships != {"en": 43691, "tr": 43691, "ja": 43690}:
        raise RuntimeError("incorrect combined wordlist memberships")
    if overlaps != {"en&tr": 0, "en&ja": 0, "tr&ja": 0, "en&tr&ja": 0}:
        raise RuntimeError("incorrect combined wordlist overlaps")
    union_count = (
        memberships["en"]
        + memberships["tr"]
        + memberships["ja"]
        - overlaps["en&tr"]
        - overlaps["en&ja"]
        - overlaps["tr&ja"]
        + overlaps["en&tr&ja"]
    )
    if union_count != 131072:
        raise RuntimeError("language membership inclusion-exclusion mismatch")

    for metadata in catalog.values():
        digest = metadata["sha512"]
        if len(digest) != 128 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise RuntimeError("SHA-512 metadata is not canonical lowercase hex")

    for compatible_bits in (136, 272, 544):
        zero_hex = "00" * (compatible_bits // 8)
        encoded = run(
            program,
            "encoding",
            "encode",
            "--input-hex",
            zero_hex,
            "--wordlist",
            "embedded_en_tr_jp_131072",
        )
        require_success(encoded)
        expected_words = compatible_bits // 17
        phrase = encoded.stdout.strip()
        if phrase.split() != [EXPECTED_COMBINED_FIRST_WORD] * expected_words:
            raise RuntimeError(
                f"incorrect {compatible_bits}-bit combined encoding vector"
            )
        decoded = run(
            program,
            "encoding",
            "decode",
            "--input-words",
            phrase,
            "--wordlist",
            "embedded_en_tr_jp_131072",
        )
        require_success(decoded)
        if decoded.stdout.strip() != zero_hex:
            raise RuntimeError(
                f"incorrect {compatible_bits}-bit combined decoding vector"
            )

    for incompatible_bits, remainder in ((128, 9), (256, 1), (512, 2)):
        rejected = run(
            program,
            "encoding",
            "encode",
            "--input-hex",
            "00" * (incompatible_bits // 8),
            "--wordlist",
            "embedded_en_tr_jp_131072",
        )
        if rejected.returncode == 0:
            raise RuntimeError(
                f"accepted incompatible {incompatible_bits}-bit input"
            )
        if (
            f"remainder {remainder}" not in rejected.stderr
            or "refuses to discard or pad any bit" not in rejected.stderr
        ):
            raise RuntimeError(
                f"incomplete {incompatible_bits}-bit losslessness diagnostic"
            )

    with tempfile.TemporaryDirectory(prefix="arborkdf-wordlist-cli-") as name:
        root = Path(name)
        bip39_path = root / "bip39.txt"
        bip39_bytes = check_export(
            program, "embedded_bip39", bip39, bip39_path
        )

        repeated = run(
            program,
            "wordlist",
            "export",
            "--wordlist",
            "embedded_bip39",
            "--output",
            str(bip39_path),
        )
        if repeated.returncode == 0 or bip39_path.read_bytes() != bip39_bytes:
            raise RuntimeError("repeat export overwrote an existing file")

        sentinel_path = root / "sentinel.txt"
        sentinel = b"must remain unchanged\n"
        sentinel_path.write_bytes(sentinel)
        refused = run(
            program,
            "wordlist",
            "export",
            "--wordlist",
            "embedded_en_tr_jp_131072",
            "--output",
            str(sentinel_path),
        )
        if refused.returncode == 0 or sentinel_path.read_bytes() != sentinel:
            raise RuntimeError("export overwrote a pre-existing sentinel")

        directory_path = root / "existing-directory"
        directory_path.mkdir()
        directory_refused = run(
            program,
            "wordlist",
            "export",
            "--wordlist",
            "embedded_bip39",
            "--output",
            str(directory_path),
        )
        if directory_refused.returncode == 0 or not directory_path.is_dir():
            raise RuntimeError("export accepted an existing directory")

        symlink_path = root / "existing-symlink.txt"
        try:
            symlink_path.symlink_to(sentinel_path)
        except OSError:
            # Creating symlinks normally requires extra privileges on Windows.
            pass
        else:
            # MSYS2 defaults symlink creation to a deep copy when native
            # Windows symlinks are unavailable. Only exercise symlink semantics
            # when the path that was created is actually a symlink.
            if symlink_path.is_symlink():
                symlink_refused = run(
                    program,
                    "wordlist",
                    "export",
                    "--wordlist",
                    "embedded_bip39",
                    "--output",
                    str(symlink_path),
                )
                if (
                    symlink_refused.returncode == 0
                    or not symlink_path.is_symlink()
                    or sentinel_path.read_bytes() != sentinel
                ):
                    raise RuntimeError("export followed or replaced a symlink")

        dangling_target = root / "must-not-be-created.txt"
        dangling_symlink = root / "dangling-symlink.txt"
        dangling_symlink_tested = False
        try:
            dangling_symlink.symlink_to(dangling_target)
        except OSError:
            pass
        else:
            if dangling_symlink.is_symlink():
                dangling_symlink_tested = True
                dangling_refused = run(
                    program,
                    "wordlist",
                    "export",
                    "--wordlist",
                    "embedded_bip39",
                    "--output",
                    str(dangling_symlink),
                )
                if (
                    dangling_refused.returncode == 0
                    or not dangling_symlink.is_symlink()
                    or dangling_target.exists()
                ):
                    raise RuntimeError("export followed a dangling symlink")
        if (
            os.environ.get("ARBORKDF_TEST_REQUIRE_NATIVE_SYMLINK") == "1"
            and not dangling_symlink_tested
        ):
            raise RuntimeError(
                "native symlink support is required for this test run"
            )

        unicode_path = root / "türkçe-日本語.txt"
        check_export(
            program,
            "embedded_en_tr_jp_131072",
            combined,
            unicode_path,
        )

        unknown_path = root / "unknown.txt"
        unknown = run(
            program,
            "wordlist",
            "export",
            "--wordlist",
            "embedded_unknown",
            "--output",
            str(unknown_path),
        )
        if unknown.returncode == 0 or unknown_path.exists():
            raise RuntimeError("unknown selector created an output file")

    print("wordlist CLI tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
