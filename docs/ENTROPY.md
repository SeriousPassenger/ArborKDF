# Mouse input and entropy reporting

## Security model

ArborKDF obtains the full requested output length from the operating system CSPRNG
and aborts if that operation fails. Separately, a versioned, length-framed mouse
transcript is expanded through SHAKE256 to the same length; the two independent
streams are XORed. Thus predictable mouse input cannot reduce uniform OS output.
Hashing distributes existing entropy; it does not create entropy.

The OS source is the only source credited by the security model. Supplemental
mouse input can help if it contains unpredictability, and cannot weaken an
independent uniform OS value, but a short interactive session is not enough to
validate a physical entropy source.

NIST SP 800-90B validation normally requires at least 1,000,000 samples and restart
testing, plus source-specific analysis and health-test thresholds. ArborKDF thus
prints:

```text
mouse security credit: 0 bits
```

until a separately characterized, versioned platform/backend/device profile
exists.

## Live diagnostics

Every physical event, including repeated patterns, remains in the estimator input.
Deduplicating would make deterministic repetition look more random. The collector
uses separate motion and timing symbol streams and never adds their results.

The initial online diagnostic set reports each method separately:

- most-common-value min-entropy, including a conservative confidence adjustment;
- first-order Markov fitted-path diagnostic;
- Renyi-2 collision entropy;
- Shannon entropy, explicitly marked descriptive rather than min-entropy;
- raw DEFLATE compressed size and ratio, explicitly not converted into entropy.

No average is calculated. The progress bar uses the minimum eligible diagnostic
projection across both symbol views, may move backward when repetition appears,
fills visually at 256 bits, and continues numerically past 256 until Enter is
pressed. Collection is capped at 1,000,000 events to bound memory and CPU use;
reaching the cap before Enter is an error. Insufficient sample sizes are printed
as `N/A` with a reason.

This online subset is not represented as the complete SP 800-90B non-IID battery.
Before a stable release, estimator ports should be differentially tested against
NIST's official EntropyAssessment implementation, including MCV, Collision,
Markov, Maurer Compression, t-Tuple, LRS, MultiMCW, Lag, MultiMMC, and LZ78Y.

## Repeated movement

Software cannot determine whether two human gestures were intentionally “the
same.” Exact and periodic event symbols remain visible, so MCV, Markov, collision,
and compression diagnostics penalize them. A UI novelty gate may stop an exact
repeat from advancing the bar, but is only a heuristic and never a security claim.

References:

- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final)
- [NIST EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
