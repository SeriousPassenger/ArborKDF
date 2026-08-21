# Wordlist formats

ArborKDF separates two jobs that have different mathematical requirements.

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

## `wordlist-bits-v1` byte encoding

Encoding arbitrary derived bytes as bare words has no in-band length header. The
v1 codec therefore uses deliberately strict fixed-width rules:

1. The list length must be `N = 2^k`.
2. Input bits are split MSB-first into `k`-bit indices.
3. The input bit count `B` must satisfy `B mod k = 0`.
4. No checksum, padding, truncation, modulo operation, or fallback is permitted.

The word count fixes the total bit length, preserving leading zero bytes.

If a list is incompatible, ArborKDF emits no partial output. Compatible list sizes
for a `B`-bit input are exactly:

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

An exact arbitrary-radix format would need an explicit length header or a mandatory
external bit length. If added later, it will receive a new codec identifier and
will never be silently substituted for `wordlist-bits-v1`.

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
