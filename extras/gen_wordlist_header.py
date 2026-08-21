#!/usr/bin/env python3
"""Verify immutable wordlist artifacts and generate C++ embedding headers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATED_DIR = PROJECT_ROOT / "include" / "arborkdf" / "generated"

BIP39_SOURCE = PROJECT_ROOT / "third_party" / "bip39" / "english.txt"
BIP39_OUTPUT = GENERATED_DIR / "bip39_english_wordlist.hpp"
BIP39_SHA512 = (
    "416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8b"
    "aed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123"
)
BIP39_COMMIT = "b9f9a8d6e854fa0b0c8f818753420b0aa6e875aa"
BIP39_GIT_BLOB = "942040ed50f7205cafc465496229128ba4f78e75"
BIP39_WORD_COUNT = 2048

COMBINED_SOURCE = (
    PROJECT_ROOT
    / "third_party"
    / "arborkdf-wordlists"
    / "en_tr_jp_131072.txt"
)
COMBINED_MANIFEST = COMBINED_SOURCE.with_suffix(".manifest.json")
COMBINED_OUTPUT = GENERATED_DIR / "en_tr_jp_131072_wordlist.hpp"
COMBINED_SHA512 = (
    "e59905f19627e0f98e72887187463f9a0767592612ec337a8ff5e71e373f96d7"
    "e5b5c4066427ceb89a8acbb13bd5092327e92f7802b0afc2e64ee83e58780c8a"
)
COMBINED_MANIFEST_SHA512 = (
    "80c529c958d0eb02194216f4d1c4b5d7b24896e9e823ecc1e10a3658797b0a4d"
    "1d8d030378dac15ade5ce198a7964e5ca1617965d66ea0fd1d31943a21cc8306"
)
COMBINED_WORD_COUNT = 131_072
COMBINED_CANONICAL_BYTES = 1_262_297
COMBINED_MEMBERSHIPS = {"en": 43_691, "tr": 43_691, "ja": 43_690}
COMBINED_OVERLAPS = {"en-tr": 0, "en-ja": 0, "tr-ja": 0, "en-tr-ja": 0}
COMBINED_CANDIDATES_BEFORE = {"en": 64_488, "tr": 72_596, "ja": 136_920}
COMBINED_CANDIDATES_AFTER = {"en": 63_492, "tr": 71_104, "ja": 136_033}
COMBINED_COLLISIONS = {
    "en-tr": 834,
    "en-ja": 229,
    "tr-ja": 725,
    "en-tr-ja": 67,
    "unique-tokens-removed": 1_654,
}
COMBINED_SELECTED_ENGLISH = {
    "common": 41_379,
    "american_only": 1_280,
    "british_only": 1_032,
}
COMBINED_SHA3_512 = (
    "6ba29b110dc43ffa1dedaef2e3577c782036c2a4fedeb4cc18efd6e938d65c9a"
    "3627dc112a93339516e88a1b08057c2faf429a2ae3405b2990e5eeba6742ed00"
)
COMBINED_GOLDEN_WORDS = {
    0: "kyounenji",
    1: "gudani",
    65_535: "momonokihana",
    65_536: "impedes",
    131_071: "derkenar",
}

ASCII_WORD_PATTERN = re.compile(r"[a-z]+", re.ASCII)
COMBINED_WORD_PATTERN = re.compile(r"[a-zçğıöşü]{4,16}")
MAXIMUM_CANONICAL_CHUNK_BYTES = 4096
MAXIMUM_LITERAL_SOURCE_CHARACTERS = 96


def sha512_hex(raw: bytes) -> str:
    return hashlib.sha512(raw).hexdigest()


def canonical_lines(raw: bytes, source: Path, encoding: str) -> list[str]:
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise ValueError(f"{source}: expected LF endings and a final LF")
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as error:
        raise ValueError(f"{source}: invalid {encoding}") from error
    return text[:-1].split("\n")


def verify_bip39() -> list[str]:
    raw = BIP39_SOURCE.read_bytes()
    actual_digest = sha512_hex(raw)
    if actual_digest != BIP39_SHA512:
        raise ValueError(
            f"{BIP39_SOURCE}: SHA-512 mismatch; expected {BIP39_SHA512}, "
            f"got {actual_digest}"
        )
    words = canonical_lines(raw, BIP39_SOURCE, "ascii")
    if len(words) != BIP39_WORD_COUNT:
        raise ValueError(
            f"{BIP39_SOURCE}: expected {BIP39_WORD_COUNT} words, "
            f"got {len(words)}"
        )
    if any(ASCII_WORD_PATTERN.fullmatch(word) is None for word in words):
        raise ValueError(f"{BIP39_SOURCE}: invalid lowercase ASCII word")
    if len(set(words)) != len(words):
        raise ValueError(f"{BIP39_SOURCE}: duplicate word")
    if words != sorted(words):
        raise ValueError(f"{BIP39_SOURCE}: words are not sorted")
    if len({word[:4] for word in words}) != len(words):
        raise ValueError(f"{BIP39_SOURCE}: first four characters are not unique")
    return words


def verify_combined_manifest(raw: bytes) -> None:
    actual_digest = sha512_hex(raw)
    if actual_digest != COMBINED_MANIFEST_SHA512:
        raise ValueError(
            f"{COMBINED_MANIFEST}: SHA-512 mismatch; expected "
            f"{COMBINED_MANIFEST_SHA512}, got {actual_digest}"
        )
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{COMBINED_MANIFEST}: invalid UTF-8 JSON") from error

    expected_scalars = {
        "standard": "ArborKDF-en-tr-jp-131072-v1",
        "selector": "embedded_en_tr_jp_131072",
        "entries": COMBINED_WORD_COUNT,
        "bits_per_word": 17,
        "byte_aligned_block_bits": 136,
    }
    for name, expected in expected_scalars.items():
        if manifest.get(name) != expected:
            raise ValueError(f"{COMBINED_MANIFEST}: invalid {name!r}")
    if manifest.get("final_language_memberships") != COMBINED_MEMBERSHIPS:
        raise ValueError(f"{COMBINED_MANIFEST}: invalid language memberships")
    if manifest.get("final_overlaps") != COMBINED_OVERLAPS:
        raise ValueError(f"{COMBINED_MANIFEST}: invalid final overlaps")
    expected_maps = {
        "candidate_counts_before_cross_language_removal": (
            COMBINED_CANDIDATES_BEFORE
        ),
        "candidate_counts_after_cross_language_removal": (
            COMBINED_CANDIDATES_AFTER
        ),
        "cross_language_collisions": COMBINED_COLLISIONS,
        "selected_counts": COMBINED_MEMBERSHIPS,
        "selected_english_composition": COMBINED_SELECTED_ENGLISH,
    }
    for name, expected in expected_maps.items():
        if manifest.get(name) != expected:
            raise ValueError(f"{COMBINED_MANIFEST}: invalid {name!r}")
    canonical = manifest.get("canonical_text")
    if not isinstance(canonical, dict):
        raise ValueError(f"{COMBINED_MANIFEST}: missing canonical_text")
    if canonical.get("bytes") != COMBINED_CANONICAL_BYTES:
        raise ValueError(f"{COMBINED_MANIFEST}: invalid canonical byte count")
    if canonical.get("sha512") != COMBINED_SHA512:
        raise ValueError(f"{COMBINED_MANIFEST}: invalid canonical SHA-512")
    if canonical.get("sha3_512") != COMBINED_SHA3_512:
        raise ValueError(f"{COMBINED_MANIFEST}: invalid canonical SHA3-512")


def verify_combined() -> bytes:
    manifest_raw = COMBINED_MANIFEST.read_bytes()
    verify_combined_manifest(manifest_raw)

    raw = COMBINED_SOURCE.read_bytes()
    if len(raw) != COMBINED_CANONICAL_BYTES:
        raise ValueError(
            f"{COMBINED_SOURCE}: expected {COMBINED_CANONICAL_BYTES} bytes, "
            f"got {len(raw)}"
        )
    actual_digest = sha512_hex(raw)
    if actual_digest != COMBINED_SHA512:
        raise ValueError(
            f"{COMBINED_SOURCE}: SHA-512 mismatch; expected {COMBINED_SHA512}, "
            f"got {actual_digest}"
        )
    words = canonical_lines(raw, COMBINED_SOURCE, "utf-8")
    if len(words) != COMBINED_WORD_COUNT:
        raise ValueError(
            f"{COMBINED_SOURCE}: expected {COMBINED_WORD_COUNT} words, "
            f"got {len(words)}"
        )
    if any(unicodedata.normalize("NFC", word) != word for word in words):
        raise ValueError(f"{COMBINED_SOURCE}: word is not NFC-normalized")
    if any(COMBINED_WORD_PATTERN.fullmatch(word) is None for word in words):
        raise ValueError(f"{COMBINED_SOURCE}: invalid canonical word")
    if len(set(words)) != len(words):
        raise ValueError(f"{COMBINED_SOURCE}: duplicate word")
    for index, expected in COMBINED_GOLDEN_WORDS.items():
        if words[index] != expected:
            raise ValueError(
                f"{COMBINED_SOURCE}: golden index {index} expected "
                f"{expected!r}, got {words[index]!r}"
            )
    return raw


def make_bip39_header(words: list[str]) -> str:
    entries = "\n".join(
        f'    std::string_view{{"{word}"}},' for word in words
    )
    return f"""// Generated by extras/gen_wordlist_header.py. Do not edit.
// Source: bitcoin/bips bip-0039/english.txt
// Upstream commit: {BIP39_COMMIT}
// Upstream Git blob: {BIP39_GIT_BLOB}
// Source SHA-512: {BIP39_SHA512}
#pragma once

#include <array>
#include <string_view>

namespace arborkdf::generated {{

inline constexpr std::string_view kBip39EnglishSelector{{"embedded_bip39"}};
inline constexpr std::array<std::string_view, {BIP39_WORD_COUNT}U>
    kBip39EnglishWords{{{{
{entries}
}}}};

static_assert(kBip39EnglishWords.size() == {BIP39_WORD_COUNT}U);

}}  // namespace arborkdf::generated
"""


def split_canonical_chunks(raw: bytes) -> list[bytes]:
    chunks: list[bytes] = []
    offset = 0
    while offset < len(raw):
        boundary = min(offset + MAXIMUM_CANONICAL_CHUNK_BYTES, len(raw))
        if boundary != len(raw):
            final_lf = raw.rfind(b"\n", offset, boundary)
            if final_lf < offset:
                raise ValueError("canonical word exceeds generated chunk limit")
            boundary = final_lf + 1
        chunks.append(raw[offset:boundary])
        offset = boundary
    if any(not chunk.endswith(b"\n") for chunk in chunks):
        raise ValueError("internal generated chunk does not end at a word boundary")
    return chunks


def cpp_escape_byte(byte: int) -> str:
    if byte == 0x0A:
        return r"\n"
    if byte == 0x22:
        return r'\"'
    if byte == 0x5C:
        return r"\\"
    if 0x20 <= byte <= 0x7E:
        return chr(byte)
    return f"\\{byte:03o}"


def cpp_literal_lines(chunk: bytes) -> list[str]:
    lines: list[str] = []
    current = ""
    for byte in chunk:
        escaped = cpp_escape_byte(byte)
        if current and len(current) + len(escaped) > MAXIMUM_LITERAL_SOURCE_CHARACTERS:
            lines.append(current)
            current = ""
        current += escaped
    if current:
        lines.append(current)
    return lines


def make_combined_header(raw: bytes) -> str:
    chunks = split_canonical_chunks(raw)
    chunk_entries: list[str] = []
    for chunk in chunks:
        literals = "\n".join(
            f'            "{line}"' for line in cpp_literal_lines(chunk)
        )
        chunk_entries.append(
            "        std::string_view{\n"
            + literals
            + f",\n            {len(chunk)}U\n        }},"
        )
    entries = "\n".join(chunk_entries)
    return f"""// Generated by extras/gen_wordlist_header.py. Do not edit.
// Source: third_party/arborkdf-wordlists/en_tr_jp_131072.txt
// Manifest: third_party/arborkdf-wordlists/en_tr_jp_131072.manifest.json
// License notices: third_party/arborkdf-wordlists/NOTICE.md
// Complete composite data/embedding file: MPL-2.0; see all source notices.
// Source SHA-512: {COMBINED_SHA512}
// Manifest SHA-512: {COMBINED_MANIFEST_SHA512}
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace arborkdf::generated {{

inline constexpr std::string_view kEnTrJp131072Selector{{
    "embedded_en_tr_jp_131072"}};
inline constexpr std::size_t kEnTrJp131072WordCount = {COMBINED_WORD_COUNT}U;
inline constexpr std::size_t kEnTrJp131072CanonicalBytes =
    {COMBINED_CANONICAL_BYTES}U;
inline constexpr std::string_view kEnTrJp131072Sha512{{
    "{COMBINED_SHA512[:64]}"
    "{COMBINED_SHA512[64:]}"}};
inline constexpr std::size_t kEnTrJp131072EnglishCount = 43691U;
inline constexpr std::size_t kEnTrJp131072TurkishCount = 43691U;
inline constexpr std::size_t kEnTrJp131072JapaneseCount = 43690U;
inline constexpr std::size_t kEnTrJp131072EnglishTurkishOverlap = 0U;
inline constexpr std::size_t kEnTrJp131072EnglishJapaneseOverlap = 0U;
inline constexpr std::size_t kEnTrJp131072TurkishJapaneseOverlap = 0U;
inline constexpr std::size_t kEnTrJp131072EnglishTurkishJapaneseOverlap = 0U;

inline constexpr std::array<std::string_view, {len(chunks)}U>
    kEnTrJp131072Chunks{{{{
{entries}
}}}};

static_assert(kEnTrJp131072WordCount == (std::size_t{{1U}} << 17U));

}}  // namespace arborkdf::generated
"""


def expected_headers() -> dict[Path, str]:
    return {
        BIP39_OUTPUT: make_bip39_header(verify_bip39()),
        COMBINED_OUTPUT: make_combined_header(verify_combined()),
    }


def check_headers(headers: dict[Path, str]) -> None:
    for path, expected in headers.items():
        try:
            actual = path.read_bytes()
        except FileNotFoundError as error:
            raise ValueError(
                f"{path}: generated header is missing; run "
                "python3 extras/gen_wordlist_header.py"
            ) from error
        if actual != expected.encode("utf-8"):
            raise ValueError(
                f"{path}: generated header is stale; run "
                "python3 extras/gen_wordlist_header.py"
            )


def write_atomic(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(contents)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "verify pinned wordlist artifacts and generate their C++ headers"
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify source digests and committed generated headers",
    )
    arguments = parser.parse_args()
    try:
        headers = expected_headers()
        if arguments.check:
            check_headers(headers)
        else:
            for path, contents in headers.items():
                write_atomic(path, contents)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
