# Security policy

ArborKDF is pre-release and has not received an independent cryptographic or
implementation audit. Its current output must be treated as experimental.

Report vulnerabilities through the repository's GitHub Security Advisory
"Report a vulnerability" form. If that form is unavailable, open a public issue
titled `Private security contact requested` without vulnerability details; the
maintainer must establish a private channel before technical disclosure. Do not
include real master keys, salts derived from private material, or production
outputs in either route. A minimal synthetic reproducer and affected commit are
preferred once a private channel exists.

## Non-claims

- A memory-hard KDF cannot add entropy to a weak password.
- Hash functions used here are believed to resist known practical quantum attacks,
  but are not unaffected by generic quantum search.
- Live mouse statistics are not a NIST SP 800-90B entropy-source validation.
- Combining algorithms from different countries is not, by itself, a robust
  cryptographic combiner or a backdoor defense.
- A successful build and passing known-answer tests are not an audit.
- Buffer cleansing is best effort: this pre-release does not yet use a locked
  secure allocator, suppress process dumps, or guarantee that libraries and OS
  paging never copy secret material.
- `--master-stdin` avoids an argument, but the encoding utility's command-line
  inputs can be exposed through shell history and process inspection. Do not put
  a production master secret in an argument.
