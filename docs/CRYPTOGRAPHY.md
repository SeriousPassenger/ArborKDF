# Cryptographic design rationale

## SHA-3, Keccak, HMAC, and KMAC

“Keccak-256” and standardized SHA3-256 are not interchangeable: their domain
suffixes differ, so the same message produces different output. ArborKDF uses the
standardized SHA-3 family, not Ethereum-style raw Keccak-256.

HMAC-SHA3-512 is a standardized and conservative keyed construction. KMAC256 is a
native keyed Keccak construction with an explicit customization string and
variable fixed output. KMAC is cleaner for a SHA-3-native path KDF, but it is not a
universal proof that every HMAC construction is weaker.

| Candidate for path derivation | Advantages | Limits | v1 use |
|---|---|---|---|
| KMAC256 | Native keyed sponge; customization; output length is bound | Maximum 256-bit security strength | Conservative 128-bit quantum-search-margin profile |
| SP 800-108 HMAC-SHA3-512 counter KDF | Mature HMAC analysis; 512-bit digest/key path | More framing and counter logic | Conservative 256-bit quantum-search-margin profile |
| HKDF-HMAC-SHA3-512 | Excellent extract-then-expand interface | The root is already extracted/password-hardened; path labeling is less direct | Not selected |
| Raw SHA3/SHAKE over secret data | Simple | Easy to invent ambiguous framing or misuse keyed hashing | Rejected |
| PBKDF2 for every subkey block | Standard password KDF | Not a clean hierarchy/expansion interface | Used only before Argon2id |

The profile name describes a conservative generic key-search margin, not a claim
that the master input contains that much entropy or that a particular NIST PQC
category has been certified.

## Password-hardening pipeline

```text
framed master
    -> PBKDF2-HMAC-SHA3-512 (mandatory iteration count, 64-byte result)
    -> Argon2id v1.3 (mandatory memory/time/parallelism, 64-byte root)
    -> versioned path KDF over framed public salt + path
```

The public salt is independently domain-separated for PBKDF2 and Argon2id. The
path KDF context contains both public salt and path with explicit lengths. Output
length and suite identity are cryptographically bound.

There are no cost defaults. The CLI accepts implementation-supported RFC-valid
values and deliberately caps parallelism at 256. It warns unless the complete
tuple exactly matches one of RFC 9106's named profiles (`m=2 GiB,t=1,p=4` or the
memory-constrained `m=64 MiB,t=3,p=4`). The warning is not a benchmark: users
must calibrate both Argon2id and PBKDF2 on the actual air-gapped target and
record the exact public parameters for recovery.

Argon2id uses BLAKE2b internally. This supplies structural diversity from Keccak
without adding another dependency solely for appearances.

## Post-quantum scope

This is a symmetric derivation tool; it performs no public-key encryption,
signature, or key exchange, so ML-KEM/ML-DSA are not applicable. Known generic
quantum search affects symmetric work factors rather than breaking SHA-3 in the
way Shor's algorithm breaks RSA or elliptic curves. ArborKDF therefore enforces a
minimum 256-bit output for its lower profile and 512 bits for its higher profile.

No output length compensates for a low-entropy human password. Generated master
phrases report ideal code-space entropy and a conservative half-exponent quantum
search figure so that limitation is visible.

## Why no extra national hash cascade

Serially computing `H2(H1(x))` is not a generic “secure if either survives”
combiner. If the inner function collapses inputs, the outer function cannot
restore them; a compromised outer function can also destroy good inner output.
Bitcoin's RIPEMD160(SHA256(x)) is an address construction whose outer digest caps
the result at 160 bits, not a proof for arbitrary KDF composition.

| Candidate | Provenance/output | Engineering/security issue | Decision |
|---|---|---|---|
| Streebog-512 | Russian GOST R 34.11-2012, 512 bits | Not in OpenSSL's default provider; undisclosed S-box structure is an awkward backdoor hedge | Do not add |
| SM3 | Chinese GB/T 32905 / ISO, 256 bits | Easy OpenSSL support, but only a 128-bit generic collision ceiling | Possible future reviewed diversity profile |
| Kupyna-512 | Ukrainian DSTU 7564, 512 bits | Narrow audited-library availability | Do not add in minimal v1 |
| Ascon-Hash256 | NIST SP 800-232, 256 bits | Standardized at a 128-bit security level and another permutation/sponge family | Not a 256-bit hedge |
| Whirlpool | ISO/IEC 10118-3, 512 bits | OpenSSL legacy provider; poor new-deployment fit | Reject |

A future diversity profile would need parallel independently keyed PRFs, explicit
property goals, a reviewed combiner, published vectors, and specialist review. It
will not be enabled merely by nationality.

Primary references:

- [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)
- [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final)
- [NIST SP 800-108 Rev. 1 Update 1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final)
- [RFC 8018 (PBKDF2)](https://www.rfc-editor.org/rfc/rfc8018)
- [RFC 9106 (Argon2)](https://www.rfc-editor.org/rfc/rfc9106)
- [RFC 6986 (Streebog)](https://www.rfc-editor.org/rfc/rfc6986)
- [RFC 8998 (SM3 use)](https://www.rfc-editor.org/rfc/rfc8998)
- [NIST SP 800-232 (Ascon)](https://csrc.nist.gov/pubs/sp/800/232/final)
- [NIST post-quantum FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
