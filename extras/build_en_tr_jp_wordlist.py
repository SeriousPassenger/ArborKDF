#!/usr/bin/env python3
"""Rebuild the immutable ArborKDF English/Turkish/Japanese wordlist.

This is a release-engineering tool, not part of a normal build.  It consumes
four exact, pinned upstream files, removes ambiguous cross-language tokens,
selects near-equal language quotas by domain-separated SHA3-512 rank, and
permutes the final index order with a separate SHA3-512 domain.

The hash ranking prevents source/lexicographic truncation bias.  It does not
add entropy; uniform random selection of one of the final 2^17 indices is what
provides exactly 17 ideal bits per word.

The kana conversion below is the kata2alphabet/kana2alphabet behavior from
jaconv 0.5.0, reduced to the code needed for this generator.  jaconv is MIT
licensed; its notice is vendored in third_party/jaconv/LICENSE.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "third_party" / "arborkdf-wordlists" / "en_tr_jp_131072.txt"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "third_party"
    / "arborkdf-wordlists"
    / "en_tr_jp_131072.manifest.json"
)

EXPECTED_SHA512 = {
    "american": (
        "58466bdacfce54022a9b4fd5f308397018befc2c8e3e56a20680e1be46e3dd31d"
        "bb43febbac0daf1d9815c47afa2125e6a245527461cc85d814ca2b5e33c8f19"
    ),
    "british": (
        "229bc29c63d4ae43a34e6688acc896047d6d986539108e1458faca8f4fbb80a6"
        "082f6aa6d6b7506917977ab8b79a53a3c954ec5523dd5d2283f07bd6a340e5a6"
    ),
    "turkish": (
        "f0464703769963d3ea22b248b5b2afdf955c53df21976cff253dea547f131b58e"
        "b68a129c9e78e41cf577c500d1c917149817f519f5aa189415a699c9ee6d4cf"
    ),
    "naist": (
        "f6ccadbaaf66b12b5afebbdf1b3c22b2ca6d811ac4fb7cc1f3235a447529ffc0"
        "c3a3489f04c2b4159d5581ab88c218eabe59086a567a56924d028e5c74b8cc00"
    ),
}

EXPECTED_LINE_COUNTS = {
    "american": 104_334,
    "british": 103_494,
    "turkish": 75_910,  # Hunspell count header plus 75,909 entries.
    "naist": 485_863,
}

WORDLIST_SIZE = 131_072
QUOTAS = {"en": 43_691, "tr": 43_691, "ja": 43_690}
MINIMUM_LENGTH = 4
MAXIMUM_LENGTH = 16
ASCII_WORD = re.compile(r"[a-z]{4,16}", re.ASCII)
TURKISH_LETTERS = re.compile(r"[abcçdefgğhıijklmnoöprsştuüvyz]+")

SELECT_DOMAINS = {
    language: (
        f"ArborKDF/wordlist/en-tr-jp-131072/v1/select/{language}"
    ).encode("ascii")
    for language in ("en", "tr", "ja")
}
ORDER_DOMAIN = b"ArborKDF/wordlist/en-tr-jp-131072/v1/order"

GOLDEN_ROMANIZATIONS = {
    "ガッコウ": "gakkou",
    "マッチ": "macchi",
    "コーヒー": "ko-hi-",
}


# Exact jaconv 0.5.0 full-width katakana-to-hiragana table.
_HIRAGANA = (
    "ぁあぃいぅうぇえぉおかがきぎくぐけげこごさざしじすず"
    "せぜそぞただちぢっつづてでとどなにぬねのはばぱひびぴ"
    "ふぶぷへべぺほぼぽまみむめもゃやゅゆょよらりるれろわ"
    "をんーゎゐゑゕゖゔゝゞ・「」。、"
)
_KATAKANA = (
    "ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソ"
    "ゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペ"
    "ホボポマミムメモャヤュユョヨラリルレロワヲンーヮヰヱヵヶヴ"
    "ヽヾ・「」。、"
)
_KATAKANA_TO_HIRAGANA = str.maketrans(_KATAKANA, _HIRAGANA)
_KANA_TO_ALPHABET = str.maketrans(
    "ぁぃぅぇぉあいうえおんる〜ー", "aiueoaiueonl~-"
)


def kana_to_ascii(reading: str) -> str:
    """Apply the pinned jaconv 0.5.0 roman-input conversion."""

    text = reading.translate(_KATAKANA_TO_HIRAGANA)
    replacements = (
        ("きゃ", "kya"), ("きゅ", "kyu"), ("きょ", "kyo"),
        ("ぎゃ", "gya"), ("ぎゅ", "gyu"), ("ぎょ", "gyo"),
        ("しゃ", "sha"), ("しゅ", "shu"), ("しょ", "sho"),
        ("じゃ", "ja"), ("じゅ", "ju"), ("じょ", "jo"),
        ("ちゃ", "cha"), ("ちゅ", "chu"), ("ちょ", "cho"),
        ("にゃ", "nya"), ("にゅ", "nyu"), ("にょ", "nyo"),
        ("ひゃ", "hya"), ("ひゅ", "hyu"), ("ひょ", "hyo"),
        ("ふぁ", "fa"), ("ふぃ", "fi"), ("ふぇ", "fe"),
        ("ふぉ", "fo"),
        ("みゃ", "mya"), ("みゅ", "myu"), ("みょ", "myo"),
        ("りゃ", "rya"), ("りゅ", "ryu"), ("りょ", "ryo"),
        ("びゃ", "bya"), ("びゅ", "byu"), ("びょ", "byo"),
        ("ぴゃ", "pya"), ("ぴゅ", "pyu"), ("ぴょ", "pyo"),
        ("が", "ga"), ("ぎ", "gi"), ("ぐ", "gu"),
        ("げ", "ge"), ("ご", "go"), ("ざ", "za"),
        ("じ", "ji"), ("ず", "zu"), ("ぜ", "ze"),
        ("ぞ", "zo"), ("だ", "da"), ("ぢ", "ji"),
        ("づ", "zu"), ("で", "de"), ("ど", "do"),
        ("ば", "ba"), ("び", "bi"), ("ぶ", "bu"),
        ("べ", "be"), ("ぼ", "bo"), ("ぱ", "pa"),
        ("ぴ", "pi"), ("ぷ", "pu"), ("ぺ", "pe"),
        ("ぽ", "po"),
        ("か", "ka"), ("き", "ki"), ("く", "ku"),
        ("け", "ke"), ("こ", "ko"), ("さ", "sa"),
        ("し", "shi"), ("す", "su"), ("せ", "se"),
        ("そ", "so"), ("た", "ta"), ("ち", "chi"),
        ("つ", "tsu"), ("て", "te"), ("と", "to"),
        ("な", "na"), ("に", "ni"), ("ぬ", "nu"),
        ("ね", "ne"), ("の", "no"), ("は", "ha"),
        ("ひ", "hi"), ("ふ", "fu"), ("へ", "he"),
        ("ほ", "ho"), ("ま", "ma"), ("み", "mi"),
        ("む", "mu"), ("め", "me"), ("も", "mo"),
        ("ら", "ra"), ("り", "ri"), ("る", "ru"),
        ("れ", "re"), ("ろ", "ro"),
        ("や", "ya"), ("ゆ", "yu"), ("よ", "yo"),
        ("わ", "wa"), ("ゐ", "wi"), ("を", "wo"),
        ("ゑ", "we"),
        ("ゔぁ", "va"), ("ゔぃ", "vi"), ("ゔぅ", "vuu"),
        ("ゔぇ", "ve"), ("ゔぉ", "vo"),
        ("ゃ", "ya"), ("ゅ", "yu"), ("ょ", "yo"),
        ("ぁ", "a"), ("ぃ", "i"), ("ぅ", "u"),
        ("ぇ", "e"), ("ぉ", "o"), ("ゎ", "wa"),
        ("ゔ", "vu"), ("ヵ", "ka"),
    )
    for source, target in replacements:
        text = text.replace(source, target)
    text = text.translate(_KANA_TO_ALPHABET)

    while "っ" in text:
        characters = list(text)
        position = characters.index("っ")
        if len(characters) <= position + 1:
            return "".join(characters[:-1]) + "xtsu"
        if position == 0 or characters[position + 1] == "っ":
            characters[position] = "xtsu"
        else:
            characters[position] = characters[position + 1]
        text = "".join(characters)
    return text


def verify_romanizer() -> None:
    for source, expected in GOLDEN_ROMANIZATIONS.items():
        actual = kana_to_ascii(source)
        if actual != expected:
            raise ValueError(
                f"internal romanization mismatch for {source!r}: "
                f"expected {expected!r}, got {actual!r}"
            )


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source(path: Path, name: str) -> None:
    actual_digest = sha512_file(path)
    if actual_digest != EXPECTED_SHA512[name]:
        raise ValueError(
            f"{path}: SHA-512 mismatch for {name}; expected "
            f"{EXPECTED_SHA512[name]}, got {actual_digest}"
        )
    with path.open("rb") as stream:
        actual_lines = sum(1 for _ in stream)
    if actual_lines != EXPECTED_LINE_COUNTS[name]:
        raise ValueError(
            f"{path}: expected {EXPECTED_LINE_COUNTS[name]} lines, "
            f"got {actual_lines}"
        )


def read_english(path: Path) -> tuple[set[str], dict[str, int]]:
    raw_lines = path.read_bytes().splitlines()
    accepted: set[str] = set()
    rejected = {"not-lowercase-ascii-4-to-16": 0, "duplicate": 0}
    for raw in raw_lines:
        try:
            word = raw.decode("ascii")
        except UnicodeDecodeError:
            rejected["not-lowercase-ascii-4-to-16"] += 1
            continue
        if ASCII_WORD.fullmatch(word) is None:
            rejected["not-lowercase-ascii-4-to-16"] += 1
            continue
        if word in accepted:
            rejected["duplicate"] += 1
        accepted.add(word)
    return accepted, rejected


def read_turkish(path: Path) -> tuple[set[str], dict[str, int]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != str(len(lines) - 1):
        raise ValueError(f"{path}: invalid Hunspell entry-count header")

    accepted: set[str] = set()
    rejected = {
        "not-nfc": 0,
        "not-lowercase": 0,
        "not-letters": 0,
        "outside-length-4-to-16": 0,
        "duplicate": 0,
    }
    for raw in lines[1:]:
        word = raw.split("/", 1)[0]
        if unicodedata.normalize("NFC", word) != word:
            rejected["not-nfc"] += 1
            continue
        if word.lower() != word:
            rejected["not-lowercase"] += 1
            continue
        if TURKISH_LETTERS.fullmatch(word) is None:
            rejected["not-letters"] += 1
            continue
        if not MINIMUM_LENGTH <= len(word) <= MAXIMUM_LENGTH:
            rejected["outside-length-4-to-16"] += 1
            continue
        if word in accepted:
            rejected["duplicate"] += 1
        accepted.add(word)
    return accepted, rejected


def read_japanese(path: Path) -> tuple[set[str], dict[str, int]]:
    accepted: set[str] = set()
    rejected = {
        "short-row": 0,
        "missing-reading": 0,
        "non-base-conjugation": 0,
        "not-lowercase-ascii-4-to-16": 0,
        "duplicate-romanization": 0,
    }
    with path.open("r", encoding="euc_jp", newline="") as stream:
        for row in csv.reader(stream):
            if len(row) <= 11:
                rejected["short-row"] += 1
                continue
            reading = row[11]
            if reading == "*" or not reading:
                rejected["missing-reading"] += 1
                continue
            # Non-conjugating entries use '*'. Conjugating entries contribute
            # only their dictionary/base form, avoiding hundreds of thousands
            # of mechanically inflected surface forms in a mnemonic codebook.
            if row[9] not in ("*", "基本形"):
                rejected["non-base-conjugation"] += 1
                continue
            word = kana_to_ascii(reading).lower()
            if ASCII_WORD.fullmatch(word) is None:
                rejected["not-lowercase-ascii-4-to-16"] += 1
                continue
            if word in accepted:
                rejected["duplicate-romanization"] += 1
            accepted.add(word)
    return accepted, rejected


def rank(domain: bytes, word: str, language: str | None = None) -> tuple[bytes, bytes]:
    encoded = word.encode("utf-8")
    frame = bytearray(domain)
    frame.append(0)
    if language is not None:
        frame.extend(language.encode("ascii"))
        frame.append(0)
    frame.extend(struct.pack(">I", len(encoded)))
    frame.extend(encoded)
    digest = hashlib.sha3_512(frame).digest()
    return digest, encoded


def collision_statistics(pools: dict[str, set[str]]) -> dict[str, int]:
    en = pools["en"]
    tr = pools["tr"]
    ja = pools["ja"]
    return {
        "en-tr": len(en & tr),
        "en-ja": len(en & ja),
        "tr-ja": len(tr & ja),
        "en-tr-ja": len(en & tr & ja),
        "unique-tokens-removed": len(
            (en & tr) | (en & ja) | (tr & ja)
        ),
    }


def write_atomic(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(contents)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build(arguments: argparse.Namespace) -> tuple[bytes, bytes]:
    verify_romanizer()
    paths = {
        "american": arguments.american,
        "british": arguments.british,
        "turkish": arguments.turkish,
        "naist": arguments.naist,
    }
    for name, path in paths.items():
        verify_source(path, name)

    american, american_rejected = read_english(paths["american"])
    british, british_rejected = read_english(paths["british"])
    turkish, turkish_rejected = read_turkish(paths["turkish"])
    japanese, japanese_rejected = read_japanese(paths["naist"])
    pools = {"en": american | british, "tr": turkish, "ja": japanese}
    raw_counts = {name: len(words) for name, words in pools.items()}
    collisions = collision_statistics(pools)

    ambiguous = {
        word
        for word in pools["en"] | pools["tr"] | pools["ja"]
        if sum(word in words for words in pools.values()) > 1
    }
    unambiguous = {
        name: words - ambiguous for name, words in pools.items()
    }

    selected_by_language: dict[str, list[str]] = {}
    for language in ("en", "tr", "ja"):
        candidates = unambiguous[language]
        quota = QUOTAS[language]
        if len(candidates) < quota:
            raise ValueError(
                f"{language}: only {len(candidates)} unambiguous candidates "
                f"remain for quota {quota}"
            )
        selected_by_language[language] = sorted(
            candidates, key=lambda word, lang=language: rank(
                SELECT_DOMAINS[lang], word
            )
        )[:quota]

    selected = set().union(*map(set, selected_by_language.values()))
    if len(selected) != WORDLIST_SIZE:
        raise ValueError(
            f"internal selection error: expected {WORDLIST_SIZE} unique words, "
            f"got {len(selected)}"
        )
    selected_language = {
        word: language
        for language, words in selected_by_language.items()
        for word in words
    }
    ordered = sorted(
        selected,
        key=lambda word: (
            *rank(ORDER_DOMAIN, word, selected_language[word]),
            selected_language[word],
        ),
    )
    canonical = ("\n".join(ordered) + "\n").encode("utf-8")

    manifest = {
        "standard": "ArborKDF-en-tr-jp-131072-v1",
        "selector": "embedded_en_tr_jp_131072",
        "entries": WORDLIST_SIZE,
        "bits_per_word": 17,
        "byte_aligned_block_bits": 136,
        "word_length_code_points": {
            "minimum": MINIMUM_LENGTH,
            "maximum": MAXIMUM_LENGTH,
        },
        "selection": {
            "collision_policy": (
                "remove every normalized token present in more than one "
                "language pool before selection"
            ),
            "rank_hash": "SHA3-512",
            "selection_rank_frame": (
                "domain || 0x00 || u32be(UTF-8 byte length) || UTF-8(word)"
            ),
            "order_rank_frame": (
                "domain || 0x00 || language || 0x00 || "
                "u32be(UTF-8 byte length) || UTF-8(word)"
            ),
            "selection_domains": {
                language: SELECT_DOMAINS[language].decode("ascii")
                for language in ("en", "tr", "ja")
            },
            "order_domain": ORDER_DOMAIN.decode("ascii"),
            "tie_breaker": (
                "unsigned lexicographic UTF-8 bytes, then ASCII language tag"
            ),
            "quotas": QUOTAS,
        },
        "sources": {
            "american": {
                "name": "Debian wamerican 2020.12.07-4",
                "package_url": (
                    "https://deb.debian.org/debian/pool/main/s/scowl/"
                    "wamerican_2020.12.07-4_all.deb"
                ),
                "package_sha256": (
                    "3b66a8174e8577767aec4c08b8742a2a7551f3a938da351d9aaef13f"
                    "f0587f1e"
                ),
                "extracted_path": "usr/share/dict/american-english",
                "entries": EXPECTED_LINE_COUNTS["american"],
                "sha512": EXPECTED_SHA512["american"],
                "accepted": len(american),
                "rejected": american_rejected,
            },
            "british": {
                "name": "Debian wbritish 2020.12.07-4",
                "package_url": (
                    "https://deb.debian.org/debian/pool/main/s/scowl/"
                    "wbritish_2020.12.07-4_all.deb"
                ),
                "package_sha256": (
                    "460507558c9cec1ba9c41f074d4eab6a4a0015ec637787545dc4c70c"
                    "cde2527f"
                ),
                "extracted_path": "usr/share/dict/british-english",
                "entries": EXPECTED_LINE_COUNTS["british"],
                "sha512": EXPECTED_SHA512["british"],
                "accepted": len(british),
                "rejected": british_rejected,
            },
            "turkish": {
                "name": "tdd-ai/hunspell-tr v1.1.1 tr_TR.dic",
                "commit": "7302eca5f3652fe7ae3d3ec06c44697c97342b4e",
                "source_url": (
                    "https://raw.githubusercontent.com/tdd-ai/hunspell-tr/"
                    "7302eca5f3652fe7ae3d3ec06c44697c97342b4e/tr_TR.dic"
                ),
                "entries": EXPECTED_LINE_COUNTS["turkish"] - 1,
                "sha512": EXPECTED_SHA512["turkish"],
                "accepted": len(turkish),
                "rejected": turkish_rejected,
            },
            "japanese": {
                "name": "mecab-naist-jdic 0.6.3b-20111013",
                "archive_url": (
                    "https://deb.debian.org/debian/pool/main/m/"
                    "mecab-naist-jdic/"
                    "mecab-naist-jdic_0.6.3.b-20111013.orig.tar.gz"
                ),
                "archive_sha256": (
                    "cb37700dc9a77b953f2bf3b15b49cfecd67848530a2cf8abcb09b594"
                    "ca5628cc"
                ),
                "archive_sha512": (
                    "03d04505d3d8d097d1389af987e87aca43d56ef36b0def9eb85e19ee"
                    "15ffe3598d3acb1c78c6dde3b31519419acb87c595aaad594dd116b98"
                    "ac5cabb82a2e61c"
                ),
                "extracted_path": (
                    "mecab-naist-jdic-0.6.3b-20111013/naist-jdic.csv"
                ),
                "entries": EXPECTED_LINE_COUNTS["naist"],
                "sha512": EXPECTED_SHA512["naist"],
                "accepted": len(japanese),
                "rejected": japanese_rejected,
                "romanization": "jaconv 0.5.0 kata2alphabet behavior",
                "romanization_source": {
                    "url": "https://github.com/ikegami-yukino/jaconv",
                    "tag_object": "be1700fe9570f0f7b05fee5e7474ecf7441c5745",
                    "commit": "4a1ea0b7a88602ac525c138b519bdd9d3e545449",
                    "golden_vectors": GOLDEN_ROMANIZATIONS,
                },
            },
        },
        "candidate_counts_before_cross_language_removal": raw_counts,
        "english_pool_composition": {
            "common": len(american & british),
            "american_only": len(american - british),
            "british_only": len(british - american),
        },
        "cross_language_collisions": collisions,
        "candidate_counts_after_cross_language_removal": {
            name: len(words) for name, words in unambiguous.items()
        },
        "selected_counts": {
            name: len(words) for name, words in selected_by_language.items()
        },
        "selected_english_composition": {
            "common": sum(
                word in american and word in british
                for word in selected_by_language["en"]
            ),
            "american_only": sum(
                word in american and word not in british
                for word in selected_by_language["en"]
            ),
            "british_only": sum(
                word in british and word not in american
                for word in selected_by_language["en"]
            ),
        },
        "final_language_memberships": QUOTAS,
        "final_overlaps": {
            "en-tr": 0,
            "en-ja": 0,
            "tr-ja": 0,
            "en-tr-ja": 0,
        },
        "canonical_text": {
            "encoding": "UTF-8",
            "line_endings": "LF",
            "final_lf": True,
            "bytes": len(canonical),
            "sha512": hashlib.sha512(canonical).hexdigest(),
            "sha3_512": hashlib.sha3_512(canonical).hexdigest(),
        },
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return canonical, manifest_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--american", type=Path, required=True)
    parser.add_argument("--british", type=Path, required=True)
    parser.add_argument("--turkish", type=Path, required=True)
    parser.add_argument("--naist", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments = parser.parse_args()

    try:
        canonical, manifest = build(arguments)
        write_atomic(arguments.output, canonical)
        write_atomic(arguments.manifest, manifest)
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"wrote {arguments.output} ({WORDLIST_SIZE} entries, "
        f"{len(canonical)} bytes, SHA-512 "
        f"{hashlib.sha512(canonical).hexdigest()})"
    )
    print(f"wrote {arguments.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
