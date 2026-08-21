# ArborKDF derivation specification (draft v1)

This document describes the byte-level behavior implemented by the pre-release v1
suite. Multibyte integers are unsigned big-endian. `frame(x)` is `u64(len(x)) || x`.
Domain strings are exact UTF-8/ASCII without an implicit NUL terminator.

## Inputs

- Public salt: 16 through 1,024 bytes.
- Path: 8 through 64 ASCII bytes drawn from
  `abcdefghijklmnopqrstuvwxyz0123456789+-/.@#_:`.
- Master UTF-8: strictly valid UTF-8, framed with its encoding identifier and byte
  length; CLI input is limited to 4,096 bytes. No Unicode normalization or
  case-folding is performed, so byte-distinct spellings derive distinct keys.
- Master wordlist phrase: validated list length, word count, and zero-based indices
  are framed; no checksum is present; CLI phrase input is limited to 8 MiB.
- PBKDF2 iterations, Argon2id memory KiB, Argon2id iterations, Argon2id
  parallelism, security target, output bit length, input encoding, and output
  encoding are mandatory CLI inputs.

## Root derivation

```text
pbkdf2_salt = frame("ArborKDF/PBKDF2-HMAC-SHA3-512/v1") || frame(public_salt)

intermediate = PBKDF2-HMAC-SHA3-512(
    password = framed_master,
    salt = pbkdf2_salt,
    iterations = user value,
    dkLen = 64
)

argon_salt = frame("ArborKDF/Argon2id-v1.3/v1") || frame(public_salt)

root = Argon2id-v1.3(
    password = intermediate,
    salt = argon_salt,
    m = user KiB,
    t = user iterations,
    p = user parallelism,
    tagLen = 64
)
```

Intermediate secret buffers are cleansed after use.

## Public path context

```text
context = frame("ArborKDF/public-context/v1")
       || frame(public_salt)
       || frame(path)
```

The path is not parsed as a filesystem path and has no hidden normalization.

## Path profiles

For `pq128`, output must be at least 256 bits:

```text
subkey = KMAC256(
    K = root,
    X = context,
    L = requested output bits,
    S = "ArborKDF/subkey/kmac256/v1"
)
```

This is fixed-output KMAC, not KMACXOF.

For `pq256`, output must be at least 512 bits. SP 800-108 counter mode uses
HMAC-SHA3-512, a 32-bit counter, and:

```text
K(i) = HMAC-SHA3-512(
    root,
    u32(i) || "ArborKDF/subkey/hmac-sha3-512/v1" || 0x00
           || context || u32(requested_output_bits)
)

subkey = leftmost requested_output_bits of K(1) || K(2) || ...
```

Maximum CLI output is 4,096 bits and lengths must be byte-aligned.

## Output encodings

Encoding is applied only after derivation and never changes the KDF context:

- `hex`: lowercase, no `0x`, no whitespace;
- `base64`: RFC 4648 standard alphabet, required canonical padding, no wrapping;
- `wordlist`: `wordlist-bits-v1`, with exact compatibility checks.
