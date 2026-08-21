# Mouse input and entropy reporting

## Security model

This version is Linux-only. It first performs a blocking one-byte `getrandom(2)`
readiness check, which must complete before any counted OS input is read. It
then opens `/dev/urandom` with close-on-exec and no-follow protections, verifies
that the opened object is a character device, and completes partial reads with
interruption handling. Unexpected end-of-file or any other source failure aborts
generation. The readiness byte is discarded and cleansed; every counted OS byte
is read directly from `/dev/urandom`. Non-Linux builds fail at compile time
because their randomness backends have not been implemented.

This fail-closed readiness check requires a Linux kernel and C library exposing
`getrandom(2)` through `<sys/random.h>`; an unavailable system call is fatal.

The v2 conditioner always reads at least 64 bytes (512 input bits) from
`/dev/urandom`. Before that read, it analyzes the mouse transcript:

- if the mouse diagnostic is unavailable or at most 512 bits, it reads 64 OS
  bytes;
- if the mouse diagnostic exceeds 512 bits, it reads enough OS bytes to match
  it, rounded upward to a whole byte.

The conditioner unambiguously frames its version, purpose, complete mouse
transcript, Linux OS source and bytes, and requested output length into SHAKE256.
The requested output is generated only after all inputs have been absorbed.
Each operation performs a fresh OS read; random bytes are not cached or reused.
Sensitive OS buffers are cleansed on success and failure paths.

The 50/50 display above 512 mouse diagnostic bits is a *policy weighting*: the
unrounded diagnostic remains visible, the OS read is rounded up to whole bytes,
and the mouse display weight is set equal to that actual OS length. Below that
point, the policy-weighted display is 512 OS input bits plus the unrounded mouse
diagnostic. The mouse weight is not a raw transcript length. These values and
percentages are not certified entropy or cryptographic security-strength claims.
Hashing distributes existing entropy; it does not create entropy.

The OS source is the only source credited by the security model. Supplemental
mouse input can help if it contains unpredictability, and cannot weaken an
independent uniform OS value, but a short interactive session is not enough to
validate a physical entropy source.

NIST SP 800-90B validation normally requires at least 1,000,000 samples, restart
testing, source-specific analysis, and health-test thresholds. ArborKDF's live
mouse estimate is therefore a diagnostic input quantity, never source
certification or credited security entropy.

## Live diagnostics

Every physical event, including repeated patterns, remains in the estimator input.
Deduplicating would make deterministic repetition look more random. The collector
uses separate motion and timing symbol streams and never adds their results.

The online diagnostic set reports each method separately:

- most-common-value min-entropy, including a conservative confidence adjustment;
- Wilson-bounded first-order transition guessing diagnostic;
- exact repeated-prefix anomaly gate;
- Renyi-2 collision entropy;
- Shannon entropy, explicitly marked descriptive rather than min-entropy;
- raw DEFLATE compressed size and ratio, never converted into entropy; only a
  compressed bit rate at or below 25% of the same stream's marginal Shannon
  rate acts as a conservative zero-valued structural anomaly gate.

The relative compression comparison avoids treating a genuinely unpredictable
small-alphabet stream as repetition merely because its zero-order symbols are
compactly encodable.

No average is calculated. The diagnostic minimum is the smallest eligible MCV or
first-order transition projection across both symbol views, capped at zero when
the anomaly gates detect an exact repeated prefix or strong compressibility.
Positive aggregation waits until the first-order model has at least 128 samples,
so a short balanced cycle cannot rely on MCV alone. Deterministic first-order
cycles, exact repeated higher-order prefixes, and strongly compressible repeated
tails therefore do not accumulate projected bits merely by running longer. These
gates do not detect every deterministic generator. The display may move backward
when repetition changes the fitted model. Collection is capped at
1,000,000 events to bound memory, CPU time, and the matching OS read; reaching
the cap before Enter is an error. Insufficient samples are printed as `N/A`.

After conditioning, output is split into three terminal-width tables, each at
most 79 columns:

1. OS randomness source and exact byte/bit length;
2. mouse estimator rows and the diagnostic minimum;
3. OS supplied length plus mouse diagnostic/policy weights and policy shares.

Long status prose is kept in short notes below the tables.

This online subset is not represented as the complete SP 800-90B non-IID battery.
Before a stable release, estimator ports should be differentially tested against
NIST's official EntropyAssessment implementation, including MCV, Collision,
Markov, Maurer Compression, t-Tuple, LRS, MultiMCW, Lag, MultiMMC, and LZ78Y.

## Repeated movement

Software cannot determine whether two human gestures were intentionally “the
same.” Exact and periodic event symbols remain visible rather than being
deduplicated, because deleting repetitions would make deterministic input look
more random. MCV, transition, repetition, collision, and compression diagnostics
then penalize those samples. In particular, a long two-symbol alternation has a
zero first-order projected rate, while exact higher-order repetition is forced to
zero by the prefix gate or, when surrounded by a small amount of other input, by
the conservative compression gate. The display shows both total observations
and distinct motion/timing symbol pairs. Neither count is credited entropy.

References:

- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final)
- [NIST EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
