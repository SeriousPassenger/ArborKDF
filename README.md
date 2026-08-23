# ArborKDF

ArborKDF is an offline, deterministic, path-based key derivation CLI. It combines
explicit password-hardening parameters, versioned public salt/path framing, strict
lossless encodings, and OS randomness with supplemental mouse-event input.

> **Security status:** early, unaudited development. Do not use this revision to
> protect cryptocurrency, production credentials, or irreplaceable data. The file
> format and derivation suite may change before the first stable release.

Suggested GitHub description:

> Offline path-based key derivation with Argon2id, PBKDF2-HMAC-SHA3-512, KMAC,
> explicit symmetric post-quantum margins, and strict lossless wordlists.

## Design highlights

- CLI only; no colors, network access, configuration files, or hidden defaults.
- Master input type is mandatory: validated UTF-8, raw bytes transported as
  strict hex or canonical padded Base64, or an explicitly selected wordlist
  phrase. Raw-byte hex and Base64 inputs are domain-separated from UTF-8 text.
- Argon2id memory, iterations, and parallelism are all mandatory.
- PBKDF2 iteration count is mandatory.
- The public salt and virtual path are length-framed and bound into every subkey.
- Output encoding is mandatory: lowercase hex, canonical RFC 4648 Base64, or an
  explicitly selected wordlist.
- Wordlist output is exact: it fails instead of padding, truncating, or discarding
  even one bit.
- Linux `/dev/urandom` is mandatory and, after a blocking kernel-CSPRNG readiness
  check, supplies at least 512 input bits. When the mouse diagnostic exceeds 512
  bits, the OS input is increased to the same byte-rounded length; an OS RNG
  failure is always fatal.
- OS, mouse, and combined input diagnostics are printed as three separate compact
  tables. Mouse estimates are never averaged or presented as validated entropy.

The v1 suite deliberately uses two structurally different primitive families:
SHA-3/KMAC and Argon2id's internal BLAKE2b. It does not add an unreviewed hash
cascade merely to count more algorithms.

## Build

Requirements:

- Linux with `<sys/random.h>` and a working `getrandom(2)` system call. This
  version deliberately fails compilation on other operating systems because its
  randomness backend is not implemented there; an unavailable readiness system
  call also fails closed at runtime.
- C++17 compiler (GCC or Clang)
- GNU Make
- Python 3.10 or newer (build-time verification of generated embedded wordlists only)
- OpenSSL 3.x development files
- libargon2 development files
- zlib development files

```sh
make
make test
```

Warnings are errors. A Linux static build is requested explicitly:

```sh
make clean
make static
```

Static linking requires static archives for OpenSSL, libargon2, zlib, and their
Linux dependencies and produces `arborkdf-static`. The separate name and object
directory prevent a prior dynamic executable from being mistaken for a static
rebuild.

For static builds, ArborKDF downloads the official OpenSSL 3.5.5 release archive
from GitHub on first use and verifies its pinned SHA-256 before extracting it:

```text
b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89
```

This is a reproducibility pin, not an automatic "latest" selector. Static
linking freezes that patch level, so maintainers must review OpenSSL security
releases and update both the version and digest before rebuilding when needed.

It then builds a private static `libcrypto.a` without shared modules, DSO,
socket, compression, or jitter-entropy dependencies. This avoids silently using
a differently configured system `libcrypto.a`. The static bootstrap additionally
requires `curl`, `sha256sum`, `tar`, and Perl. Static libargon2 and zlib archives
must still be provided by the system toolchain.

Use `make static-check` to build and run the complete static test suite. The
download, source, build tree, and installation are cached below `.deps/`; normal
`make clean` preserves that cache. `make clean-static-deps` removes only the
managed OpenSSL 3.5.5 cache. To prepare for an offline build, run
`make fetch-static-deps` on a connected machine and transfer
`.deps/downloads/openssl-3.5.5.tar.gz` with the source tree before running
`make static` or `make static-check` on the offline machine.

Advanced builds can bypass the managed OpenSSL build by explicitly setting
`OPENSSL_LIBS` and supplying matching headers through `CPPFLAGS`; no fallback to
the system OpenSSL occurs unless that override is requested.

Do not distribute a bare static executable. A binary distribution must include
the applicable wordlist and dependency notices/license materials, and must meet
the relevant source-availability obligations described in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Commands

```text
arborkdf --help
arborkdf --version
arborkdf subkey generate --help
arborkdf masterkey generate --help
arborkdf salt generate --help
arborkdf encoding encode --help
arborkdf encoding decode --help
arborkdf wordlist list
arborkdf wordlist export --help
```

Every wordlist option accepts either a custom file path or an explicitly named
embedded selector. There is no default. Discover and export the exact compiled
lists with:

```text
arborkdf wordlist list
arborkdf wordlist export --wordlist embedded_en_tr_jp_131072 --output en_tr_jp_131072.txt
```

Export creates a new canonical UTF-8/LF file and refuses to overwrite an existing
file, directory, or symlink. The available selectors are `embedded_bip39` and the
immutable `embedded_en_tr_jp_131072`. For example:

```text
arborkdf encoding encode --input-hex 0000000000000000000000 --wordlist embedded_bip39
```

The BIP-39 selector uses only the canonical English vocabulary; ArborKDF does not
claim BIP-39 checksum or seed-derivation compatibility. The 131,072-entry selector
contains fixed near-equal English, Turkish, and ASCII-romanized Japanese quotas.
It supplies exactly 17 index bits per uniformly sampled word, but its larger and
less curated vocabulary is not automatically safer or easier for people to
memorize. See [Wordlist formats](docs/WORDLISTS.md) for its exact hash,
reproducibility procedure, byte-alignment rules, and usability caveats.

A custom file whose name matches a selector remains addressable by making it an
unambiguous path, such as `./embedded_bip39`, or by using an absolute path.

Use each command's help because cryptographic inputs and tunable costs are
intentionally explicit. Interactive master entry is hidden and confirmed twice;
the explicit `--master-stdin` mode is single-read for automation. Secrets are
written only to standard output. Reports are written to standard error, while
interactive prompts/progress use the Linux controlling terminal (`/dev/tty`) so
redirected secret output stays clean.

Generated material is accepted without a lossy manual conversion. A generated
hex or Base64 master is read with the matching `--input-encoding`; both decode
to the same versioned raw-byte master domain. A generated salt is supplied with
`--salt VALUE --salt-encoding hex|base64|wordlist` and `--salt-wordlist SOURCE`
when wordlist-encoded. The legacy `--salt-hex HEX` spelling remains accepted.
`arborkdf --version` prints deterministic derivation-suite, random-conditioner,
and mouse-transcript compatibility identifiers.

## Documentation

- [Cryptographic design](docs/CRYPTOGRAPHY.md)
- [Mouse input and entropy reporting](docs/ENTROPY.md)
- [Wordlist formats](docs/WORDLISTS.md)
- [Versioned derivation specification](docs/SPECIFICATION.md)
- [Security policy](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

ArborKDF's original program code is available under the [MIT License](LICENSE).
The complete composite embedded wordlist source and generated embedding are
available under MPL-2.0 and retain all applicable source notices. Linked
components retain their own licenses. See [Third-party notices](THIRD_PARTY_NOTICES.md).
