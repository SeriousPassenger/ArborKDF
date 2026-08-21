# Wordlist formats

ArborKDF separates two jobs that have different mathematical requirements.

## Selecting a wordlist

Every wordlist option accepts either a custom file path or one of the reserved
embedded selectors:

```text
--wordlist embedded_bip39
--input-wordlist embedded_en_tr_jp_131072
--output-wordlist embedded_en_tr_jp_131072
```

There is no default. Any other value is interpreted strictly as a file path. A
custom file whose name matches a selector can be selected with an unambiguous
path such as `./embedded_bip39` or with an absolute path. Unknown values beginning with
`embedded_` fail as unknown selectors instead of falling back to a file.

The executable reports the complete compiled catalog and can export its exact
recovery bytes:

```text
arborkdf wordlist list
arborkdf wordlist export --wordlist embedded_en_tr_jp_131072 --output en_tr_jp_131072.txt
```

`wordlist list` includes entry count, index width, byte-aligned encoding block,
language memberships and overlaps, canonical byte count, and SHA-512. Export
writes canonical UTF-8 text with LF line endings and a final LF. It requires a
new path: existing files, directories, and symlinks are never overwritten, and
standard-output export is deliberately unsupported. Custom files remain usable
as wordlist inputs but are not copied by this command.

An embedded selector fixes both vocabulary and index order as public recovery
data. `embedded_en_tr_jp_131072` is immutable; an incompatible future revision
must use a new selector rather than silently changing what this name means.

## `embedded_bip39`

This selector is the exact 2,048-entry BIP-39 English vocabulary. ArborKDF
does **not** add the BIP-39 checksum or run BIP-39's mnemonic-to-seed procedure;
it uses the vocabulary with ArborKDF's own explicitly documented phrase framing
or `wordlist-bits-v1` codec.

The canonical LF-terminated source is vendored at
`third_party/bip39/english.txt`. Its project-pinned SHA-512 is:

```text
416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8baed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123
```

This digest is computed over the authoritative file including its final LF; it
is not an upstream-published BIP-39 checksum. On every build,
`extras/gen_wordlist_header.py --check` verifies the source digest, entry count,
sorting, uniqueness, lowercase-ASCII form, unique four-character prefixes, and
the exact generated header before compilation. SHA-512 verification and source
file access occur only at build time; the executable reads the compiled table
and performs no runtime integrity hash or wordlist file I/O for this selector.
To regenerate intentionally:

```text
make regenerate-wordlists
make verify-wordlists
```

## `embedded_en_tr_jp_131072`

This project-defined, immutable v1 codebook deliberately includes all three
requested language groups. Its final membership is exact:

| Language group | Entries | Notes |
|---|---:|---|
| English (`en`) | 43,691 | 41,379 common to the US/GB sources, 1,280 US-only, and 1,032 GB-only |
| Turkish (`tr`) | 43,691 | Lowercase NFC Turkish dictionary entries |
| Japanese (`ja`) | 43,690 | ASCII roman-input-style forms derived from Japanese readings |
| **Total** | **131,072 (`2^17`)** | No exact token occurs in more than one final language group |

The Japanese forms are a pinned mechanical conversion for this codebook. They
are not claimed to be canonical, reversible, or linguistically preferred
romanizations. The Turkish entries may contain `ç`, `ğ`, dotless `ı`, `ö`, `ş`,
and `ü`, so the combined file as a whole is UTF-8 rather than ASCII.

The canonical LF-terminated source and its audit manifest are:

```text
third_party/arborkdf-wordlists/en_tr_jp_131072.txt
third_party/arborkdf-wordlists/en_tr_jp_131072.manifest.json
```

Its canonical text has 131,072 unique entries, is 1,262,297 bytes including the
final LF, and has SHA-512:

```text
e59905f19627e0f98e72887187463f9a0767592612ec337a8ff5e71e373f96d7e5b5c4066427ceb89a8acbb13bd5092327e92f7802b0afc2e64ee83e58780c8a
```

The release-engineering builder consumes exact pinned versions of Debian's
`wamerican` and `wbritish` word files, `tdd-ai/hunspell-tr`'s Turkish dictionary,
and NAIST-JDIC Japanese readings. It verifies every input's SHA-512 and line
count before processing. English and ASCII Japanese candidates and NFC Turkish
candidates are limited to 4–16 code points. Every exact spelling present in
more than one language pool is removed before selection, producing final exact
overlap counts of zero for `en&tr`, `en&ja`, `tr&ja`, and `en&tr&ja`.

The remaining candidates are assigned their fixed near-equal quotas by
domain-separated SHA3-512 rank, then put in index order with a separate domain
and a documented bytewise tie-breaker. Hash ranking makes the build reproducible
and avoids simply taking a source-order or alphabetical prefix. It does **not**
add entropy, make the vocabulary statistically uniform, or cure linguistic
confusability. Uniform random index selection is what supplies 17 ideal bits per
word.

To independently rebuild the source and manifest from those exact upstream
files:

```sh
python3 extras/build_en_tr_jp_wordlist.py \
  --american /path/to/american-english \
  --british /path/to/british-english \
  --turkish /path/to/tr_TR.dic \
  --naist /path/to/naist-jdic.csv
make regenerate-wordlists
make verify-wordlists
```

The manifest records the source identities and digests, filters, candidate and
collision counts, quotas, domains, framing, tie-breaker, language composition,
and final hashes. A normal build does not fetch upstream data or rerun this
release-engineering selection. Instead, `extras/gen_wordlist_header.py --check`
verifies the committed canonical source, manifest, fixed golden indices, and
generated embedding before C++ compilation. Embedded lookup has no runtime file
or integrity-hash cost. Source licenses and notices are retained under
`third_party/` and summarized in `THIRD_PARTY_NOTICES.md`.

## Master phrases

A master phrase may use any validated wordlist containing at least two unique
entries. Each word is mapped to its zero-based line number. ArborKDF frames the
wordlist length, word count, and indices before password hardening, so no index
bits are discarded and non-power-of-two list lengths are supported.

The `ArborKDF/master-phrase/v1` frame deliberately binds only those three
numeric properties: list length, phrase length, and ordered indices. It does
**not** bind the selector, source path, file digest, word spellings, or complete
wordlist order. Consequently, supplying a different same-size list can decode
the same numeric frame to different visible words, while the numeric frame
itself derives the same key. The exact list and its order are therefore required
public recovery metadata and should be backed up with a SHA-512 digest. A future
protocol can bind a canonical list identifier or digest only under a new frame
version; v1 recovery semantics will not be changed silently.

For `W` independently and uniformly selected words from a list of `N` entries, the
ideal code-space entropy is:

```text
H = W * log2(N) bits
```

This is code-space entropy, not a measurement of the physical random source. For
example, 10 words from 2,048 entries provide 110 ideal bits. Twelve unrestricted
words provide 132 bits; standard 12-word BIP39 instead contains 128 random bits and
4 checksum bits. ArborKDF master phrases have no BIP39 checksum.

Generation uses unbiased rejection sampling. It never uses `random % N` when that
would introduce modulo bias.

Because ArborKDF phrases have no checksum, an unknown word is rejected, but
deleting or reordering words—or substituting another valid list entry—is accepted
as a different phrase and derives a different key. Backups therefore need an
independent integrity/redundancy strategy.

## Larger-wordlist security and usability tradeoff

Larger lists reduce the number of independently sampled words, but they do not
automatically strengthen a master or improve human usability. For uniformly and
independently machine-selected master words:

| List | Entries | Ideal bits/word | ≥128 ideal bits | ≥256 ideal bits | ≥512 ideal bits |
|---|---:|---:|---:|---:|---:|
| BIP-39 English | 2,048 | 11.000 | 12 (132 bits) | 24 (264 bits) | 47 (517 bits) |
| `embedded_en_tr_jp_131072` | 131,072 | 17.000 | 8 (136 bits) | 16 (272 bits) | 31 (527 bits) |
| `american-english` | 104,334 | 16.671 | 8 (133.37 bits) | 16 (266.73 bits) | 31 (516.80 bits) |
| `british-english` | 103,494 | 16.659 | 8 (133.27 bits) | 16 (266.55 bits) | 31 (516.43 bits) |

Those figures assume independent uniform machine selection with replacement.
They do not apply to a person choosing memorable words. The two system-list rows
also assume those exact files pass ArborKDF's blank-line and duplicate checks;
`wc -l` alone does not establish the usable entry count.

Thus the 131,072-entry codebook carries exactly 17 ideal index bits per generated
word and can represent a given ideal entropy target in fewer words than the
2,048-entry vocabulary. That is its narrow mathematical advantage. It does not
increase the entropy of bytes merely encoded into words, and it does not turn a
human-chosen phrase into a 17-bits-per-word secret. Choosing familiar words,
rejecting awkward samples, or following a memorable pattern changes the
distribution and can reduce entropy substantially.

Under an idealized generic quantum search, an `H`-bit uniformly sampled master
offers at most an `H/2` query exponent. Therefore 256 ideal source bits correspond
to at most a 128-bit generic-quantum margin, while a 256-bit margin requires at
least 512 bits of master entropy. ArborKDF's built-in SHAKE256-based master
generator truthfully reports a ceiling of 256 classical / 128 generic-quantum
bits regardless of extra output words. The `--security-target 256` keyed-output
profile can only be fully exercised by supplying an external master whose source
and conditioning genuinely support at least 512 bits; output length alone does
not create that entropy.

Files under `/usr/share/dict` are package-, release-, locale-, and
administrator-dependent spelling dictionaries rather than stable mnemonic
standards. They commonly include obscure words, proper names, capitalization or
apostrophe variants, inflections, homophones, and visually similar entries.
Consequently, fewer words can still be harder to memorize, speak, and transcribe
reliably. BIP-39 English was curated so every entry has a unique first four
characters and confusing pairs are reduced.

The combined embedded codebook is stable and reproducible, but it is still much
less mnemonic-oriented than BIP-39 English. It contains Turkish letters,
dictionary-derived stems, unfamiliar vocabulary, potentially sensitive or
offensive terms, and mechanical Japanese ASCII forms. Its construction removes
exact duplicates across language pools; it does not promise unique prefixes,
pronunciation separation, edit-distance separation, or protection against
visually or aurally confusable words. Users should retain the exact exported list
and an independent integrity/redundancy mechanism rather than relying on memory
alone.

Both example system-list sizes are non-powers of two. ArborKDF can sample them
without bias for generated master phrases, but `wordlist-bits-v1` must reject
them for arbitrary-byte encoding. Its fixed-width losslessness requirement is
a mathematical consequence of this codec's fixed-width design, not a limitation
on all possible word codecs. Preserve the exact custom list, ordering, and a
cryptographic digest as public recovery material; replacing the file with a
later package version can derive a different key.

## `wordlist-bits-v1` byte encoding

Encoding arbitrary derived bytes as bare words has no in-band length header. The
v1 codec therefore uses deliberately strict fixed-width rules:

1. The list length must be `N = 2^k`.
2. Input bits are split MSB-first into `k`-bit indices.
3. The input bit count `B` must satisfy `B mod k = 0`.
4. No checksum, padding, truncation, modulo operation, or fallback is permitted.

The word count fixes the total bit length, preserving leading zero bytes.

For `embedded_bip39`, `k = 11`. Consequently, byte-aligned output lengths must
be multiples of 88 bits. A 256-bit value is rejected; 264 bits encodes as 24
words and is the smallest compatible length meeting the 128 security profile's
minimum. For the 256 profile, 528 bits encodes as 48 words and is the smallest
compatible length at or above its 512-bit minimum.

For `embedded_en_tr_jp_131072`, `k = 17`, so byte-aligned input and whole-word
boundaries coincide only every 136 bits. These are exact codec vectors and
boundary cases:

| Input | `B mod 17` | Result |
|---:|---:|---|
| 128 bits (16 bytes) | 9 | Rejected; nine bits would remain |
| 136 bits (17 bytes), all zero | 0 | Eight copies of index-0 word `kyounenji` |
| 256 bits (32 bytes) | 1 | Rejected; one bit would remain |
| 272 bits (34 bytes), all zero | 0 | Sixteen copies of `kyounenji` |
| 512 bits (64 bytes) | 2 | Rejected; two bits would remain |
| 544 bits (68 bytes), all zero | 0 | Thirty-two copies of `kyounenji` |

Decoding each accepted all-zero phrase returns the original exact byte length,
including every leading zero. Because the 128 security profile requires at least
256 output bits, 272 bits (16 words) is its smallest compatible output with this
list. Because the 256 profile requires at least 512 output bits, its smallest
compatible output is 544 bits (32 words). The 31-word, 527-bit figure in the
master-phrase table is valid for independently generated phrase indices, whose
framing does not require byte alignment; it is not a valid bare byte encoding.

If a list is incompatible, ArborKDF emits no partial output. For a nonempty
`B`-bit input, compatible list sizes are exactly:

```text
S_B = { 2^d | d is a positive divisor of B }
```

The error reports the closest lower and upper members that fit the implementation's
1,048,576-entry resource limit when they exist. If the mathematically nearest
upper member exceeds that limit, the diagnostic says that no supported upper size
exists. It also reports nearby byte-aligned input lengths compatible with the
current list.

Example: a 2,048-entry list has 11-bit words. A 256-bit value leaves 3 bits, so
encoding fails. The nearest compatible list sizes are 256 (`2^8`) and 65,536
(`2^16`). With the 2,048-entry list, nearby compatible byte-aligned input lengths
are 176 and 264 bits.

An exact arbitrary-radix format would need a separately specified canonical radix
and length/framing rule. If added later, it will receive a new codec identifier
and will never be silently substituted for `wordlist-bits-v1`.

## Validation

Wordlist order is semantic. ArborKDF rejects:

- invalid UTF-8 or a UTF-8 BOM;
- blank lines, ASCII whitespace, or C0/C1 control bytes inside an entry;
- Unicode control/format characters, including bidi controls and zero-width
  format characters;
- Unicode line, paragraph, and space separators (including non-breaking space),
  as well as Unicode noncharacters;
- Unicode combining marks;
- duplicate entries;
- resource-limit violations.

Only the line ending is removed. Entries are not trimmed, normalized, or
case-folded. ArborKDF has no Unicode normalization dependency, so custom lists
must use exact precomposed spellings: combining-mark sequences are rejected
rather than accepted alongside visually equivalent precomposed entries.
Ordinary precomposed multilingual letters and visible symbols remain literal
UTF-8 bytes. This intentionally excludes writing systems or spellings that
require combining marks; use a stable list whose entries satisfy this policy
instead of relying on locale-dependent normalization. The v1 implementation
limits a file to 64 MiB, 1,048,576 entries, and 1,024 UTF-8 bytes per entry.
