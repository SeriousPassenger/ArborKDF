# Wordlist formats

ArborKDF separates two jobs that have different mathematical requirements.

## Selecting a wordlist

Every wordlist option accepts either a custom file path or the reserved selector
`embedded_bip39`:

```text
--wordlist embedded_bip39
--input-wordlist embedded_bip39
--output-wordlist embedded_bip39
```

There is no default. Any other value is interpreted strictly as a file path. A
custom file literally named `embedded_bip39` can be selected as
`./embedded_bip39` or with an absolute path. Unknown values beginning with
`embedded_` fail as unknown selectors instead of falling back to a file.

The built-in list is the exact 2,048-entry BIP-39 English vocabulary. ArborKDF
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

## Master phrases

A master phrase may use any validated wordlist containing at least two unique
entries. Each word is mapped to its zero-based line number. ArborKDF frames the
wordlist length, word count, and indices before password hardening, so no index
bits are discarded and non-power-of-two list lengths are supported.

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

## Large spelling dictionaries

Larger lists reduce the number of independently sampled words, but they do not
automatically improve human usability. For the example Debian/Ubuntu files in
the question:

| List | Entries | Ideal bits/word | ≥128 ideal bits | ≥256 ideal bits | ≥512 ideal bits |
|---|---:|---:|---:|---:|---:|
| BIP-39 English | 2,048 | 11.000 | 12 (132 bits) | 24 (264 bits) | 47 (517 bits) |
| `american-english` | 104,334 | 16.671 | 8 (133.37 bits) | 16 (266.73 bits) | 31 (516.80 bits) |
| `british-english` | 103,494 | 16.659 | 8 (133.27 bits) | 16 (266.55 bits) | 31 (516.43 bits) |

Those figures assume independent uniform machine selection with replacement.
They do not apply to a person choosing memorable words. The two system-list rows
also assume those exact files pass ArborKDF's blank-line and duplicate checks;
`wc -l` alone does not establish the usable entry count.

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
- duplicate entries;
- resource-limit violations.

Only the line ending is removed. Entries are not trimmed, normalized, or
case-folded. Other valid non-ASCII code points are treated as literal word bytes.
The v1 implementation limits a file to 64 MiB, 1,048,576 entries, and 1,024 UTF-8
bytes per entry.
