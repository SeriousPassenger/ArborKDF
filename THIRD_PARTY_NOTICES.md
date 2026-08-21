# Third-party notices

`third_party/argon2/argon2.h` is a minimal public-ABI subset of the Argon2
reference implementation header. The original header is copyright 2015 Daniel
Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves, and is
dual-licensed under CC0 1.0 or Apache License 2.0, at the recipient's option.

Upstream source:
<https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h>

Recorded upstream Git blob: `3980bb352f2312520c9be0fb3f739ced75e2cd33`.

`third_party/bip39/english.txt` is the English vocabulary published with BIP 39,
authored by Marek Palatinus, Pavol Rusnak, Aaron Voisine, and Sean Bowe. BIP 39
declares the MIT License. The exact upstream source is:
<https://github.com/bitcoin/bips/blob/b9f9a8d6e854fa0b0c8f818753420b0aa6e875aa/bip-0039/english.txt>

The pinned revision contains BIP 39's explicit MIT license declaration as well as
the unchanged English-list blob. Recorded upstream commit:
`b9f9a8d6e854fa0b0c8f818753420b0aa6e875aa`.
Recorded upstream Git blob: `942040ed50f7205cafc465496229128ba4f78e75`.

Project-pinned SHA-512 of the raw source including its final LF:
`416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8baed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123`.
The corresponding license text is retained in `third_party/bip39/LICENSE`.

`third_party/arborkdf-wordlists/en_tr_jp_131072.txt` and its generated C++
header form the composite ArborKDF English/Turkish/Japanese 131072 v1
vocabulary. They contain modified data derived from Debian SCOWL American and
British dictionaries, tdd-ai/hunspell-tr, and the NAIST Japanese Dictionary;
the Japanese reading conversion implements pinned jaconv behavior. Full source
identities, hashes, modification details, and applicable notices are in
`third_party/arborkdf-wordlists/NOTICE.md`. Verbatim license/notice texts are
retained under `third_party/scowl`, `third_party/hunspell-tr`,
`third_party/mecab-naist-jdic`, and `third_party/jaconv`. The Turkish-derived
data makes the complete composite canonical text and generated embedding
MPL-2.0-covered files; the English and Japanese source notices also remain
applicable. ArborKDF's original program code remains separately MIT-licensed.

ArborKDF links to, but does not vendor, OpenSSL, libargon2, and zlib. Their
respective licenses apply to built distributions, especially statically linked
artifacts. Do not distribute a standalone binary without the required notices,
license materials, and any applicable source offer or source availability.
