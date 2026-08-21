# ArborKDF English/Turkish/Japanese 131072 v1 notices

`en_tr_jp_131072.txt` is the canonical source form of the immutable
`ArborKDF-en-tr-jp-131072-v1` recovery vocabulary. The generated
`include/arborkdf/generated/en_tr_jp_131072_wordlist.hpp` embeds those exact
bytes. Both complete composite files are made available under Mozilla Public
License 2.0 because they contain modified MPL-covered Turkish dictionary data;
its full text is in `third_party/hunspell-tr/LICENSE`. The English and Japanese
components retain the applicable notices and permissive conditions described
below. ArborKDF's original program code is separately MIT-licensed.

ArborKDF's modifications are: filtering to the documented alphabets and
4-to-16-code-point length, NFC validation for Turkish, Japanese kana-reading
romanization, exact de-duplication, removal of tokens occurring in more than
one language pool, deterministic SHA3-512-ranked quota selection, and a
separately domain-separated deterministic ordering. The ranking only makes
selection independent of upstream lexical/source order. It does not add
randomness or entropy.

The canonical file contains 131,072 unique UTF-8 words, one per LF-terminated
line, with no checksum. Its SHA-512 (including the final LF) is:

`e59905f19627e0f98e72887187463f9a0767592612ec337a8ff5e71e373f96d7e5b5c4066427ceb89a8acbb13bd5092327e92f7802b0afc2e64ee83e58780c8a`

The exact transformation and audit counts are recorded in
`en_tr_jp_131072.manifest.json`. `extras/build_en_tr_jp_wordlist.py` rebuilds
the artifacts only from source files matching all pinned hashes and line
counts.

## English: SCOWL-derived Debian dictionaries

- Debian packages: `wamerican` and `wbritish`, version `2020.12.07-4`
- Canonical package pool: <https://deb.debian.org/debian/pool/main/s/scowl/>
- Extracted `american-english` SHA-512:
  `58466bdacfce54022a9b4fd5f308397018befc2c8e3e56a20680e1be46e3dd31dbb43febbac0daf1d9815c47afa2125e6a245527461cc85d814ca2b5e33c8f19`
- Extracted `british-english` SHA-512:
  `229bc29c63d4ae43a34e6688acc896047d6d986539108e1458faca8f4fbb80a6082f6aa6d6b7506917977ab8b79a53a3c954ec5523dd5d2283f07bd6a340e5a6`

SCOWL is a composite vocabulary with several permissive and public-domain
sources. The complete Debian copyright file, including all required notices,
conditions, modification marking, disclaimers, and non-endorsement terms, is
preserved verbatim at `third_party/scowl/COPYRIGHT`. This combined vocabulary
is a modified derivative and is not an unmodified SCOWL distribution.

## Turkish: tdd-ai/hunspell-tr

- Release: `v1.1.1`
- Commit: `7302eca5f3652fe7ae3d3ec06c44697c97342b4e`
- Source: <https://github.com/tdd-ai/hunspell-tr>
- `tr_TR.dic` SHA-512:
  `f0464703769963d3ea22b248b5b2afdf955c53df21976cff253dea547f131b58eb68a129c9e78e41cf577c500d1c917149817f519f5aa189415a699c9ee6d4cf`
- License: Mozilla Public License 2.0, preserved verbatim at
  `third_party/hunspell-tr/LICENSE`

The canonical ArborKDF file and generator are the available source form for
ArborKDF's modifications; the pinned upstream dictionary supplies the original
source material.

## Japanese: NAIST Japanese Dictionary

- Release: `mecab-naist-jdic 0.6.3b-20111013`
- Source archive:
  <https://deb.debian.org/debian/pool/main/m/mecab-naist-jdic/mecab-naist-jdic_0.6.3.b-20111013.orig.tar.gz>
- Archive SHA-512:
  `03d04505d3d8d097d1389af987e87aca43d56ef36b0def9eb85e19ee15ffe3598d3acb1c78c6dde3b31519419acb87c595aaad594dd116b98ac5cabb82a2e61c`
- Extracted `naist-jdic.csv` SHA-512:
  `f6ccadbaaf66b12b5afebbdf1b3c22b2ca6d811ac4fb7cc1f3235a447529ffc0c3a3489f04c2b4159d5581ab88c218eabe59086a567a56924d028e5c74b8cc00`
- License: BSD 3-Clause, preserved verbatim at
  `third_party/mecab-naist-jdic/COPYING`

ArborKDF uses the EUC-JP CSV reading field and includes only non-conjugating or
base-form rows before romanization and de-duplication.

## Japanese conversion: jaconv

- Release behavior: `jaconv 0.5.0` `kata2alphabet`/`kana2alphabet`
- Source: <https://github.com/ikegami-yukino/jaconv>
- Annotated tag object: `be1700fe9570f0f7b05fee5e7474ecf7441c5745`
- Peeled commit: `4a1ea0b7a88602ac525c138b519bdd9d3e545449`
- License: MIT, preserved verbatim at `third_party/jaconv/LICENSE`

The required conversion behavior is implemented directly and deterministically
inside the rebuild script. Its output is Roman-input-style ASCII for this
codebook, not a claim of canonical, reversible, or linguistically unique
Japanese romanization.

Binary distributions containing the generated embedding must reproduce all
applicable notices and comply with MPL-2.0 executable-form source-availability
requirements. A standalone executable without its notices and corresponding
source information is not a complete ArborKDF distribution.
