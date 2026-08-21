#include "arborkdf/cli.hpp"

#include "arborkdf/bytes.hpp"
#include "arborkdf/codec.hpp"
#include "arborkdf/crypto.hpp"
#include "arborkdf/entropy.hpp"
#include "arborkdf/error.hpp"
#include "arborkdf/file.hpp"
#include "arborkdf/platform.hpp"
#include "arborkdf/wordlist.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <sstream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace arborkdf {
namespace {

constexpr std::size_t kMaximumMasterBytes = 4096U;
constexpr std::size_t kMaximumMasterPhraseBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaximumGeneratedBits = 4096U;
constexpr std::size_t kMaximumGeneratedWords = 4096U;
constexpr std::size_t kMaximumSaltBits = 8192U;
constexpr std::size_t kMinimumSaltBits = 128U;
constexpr std::size_t kMaximumHexMasterCharacters = kMaximumMasterBytes * 2U;
constexpr std::size_t kMaximumBase64MasterCharacters =
    ((kMaximumMasterBytes + 2U) / 3U) * 4U;
constexpr std::size_t kMaximumBase64SaltCharacters =
    (((kMaximumSaltBits / 8U) + 2U) / 3U) * 4U;

const char* const kVersion =
    "ArborKDF experimental-pre-release; derivation-suite=draft-v1; "
    "random-conditioner=ArborKDF/random-conditioner/v2; "
    "mouse-transcript=ArborKDF/mouse-transcript/v1\n";

const char* const kGlobalHelp = R"HELP(ArborKDF - offline, deterministic, path-based key derivation

Usage:
  arborkdf --help
  arborkdf --version
  arborkdf subkey generate [options]
  arborkdf masterkey generate [options]
  arborkdf salt generate [options]
  arborkdf encoding encode [options]
  arborkdf encoding decode [options]
  arborkdf wordlist list
  arborkdf wordlist export [options]

Run a command with --help for every required option and security note. ArborKDF
has no GUI, no network behavior, no color output, and no cryptographic defaults.
)HELP";

const char* const kSubkeyHelp = R"HELP(Usage: arborkdf subkey generate [options]

Required unless using the legacy `--salt-hex` spelling:
  --salt VALUE                   Public salt in the selected encoding
  --salt-encoding hex|base64|wordlist

Always required:
  --input-encoding utf8|hex|base64|wordlist
  --path PATH                    8..64 chars from [a-z0-9+-/.@#_:]
  --pbkdf2-iterations N          No default
  --argon2-memory-kib N          No default; at least 8 * parallelism
  --argon2-iterations N          No default
  --argon2-parallelism N         No default
  --security-target 128|256      Keyed-output quantum-search margin only
  --output-bits N                Byte-aligned; >=256 or >=512 for target
  --output-encoding hex|base64|wordlist

Conditional:
  --input-wordlist SOURCE        Custom file or embedded selector; required for
                                 wordlist master input
  --output-wordlist SOURCE       Custom file or embedded selector; required for
                                 wordlist output
  --salt-wordlist SOURCE         Required for wordlist salt input
  --master-stdin                 Read one master line from stdin instead of a
                                 hidden, twice-confirmed interactive prompt;
                                 stdin mode is deliberately single-read

Compatibility:
  --salt-hex HEX                 Legacy strict-hex spelling; cannot be combined
                                 with --salt or --salt-encoding

Run `arborkdf wordlist list` for embedded selectors. embedded_bip39 is the
canonical English vocabulary only. ArborKDF phrases have no BIP-39 checksum and
do not use BIP-39's mnemonic-to-seed procedure.

Hex and Base64 master text are strict transport encodings of raw bytes. They
share the versioned raw-byte master domain and therefore derive the same key
from the same bytes; UTF-8 text uses a distinct domain. Master input is 1..4096
decoded bytes. Public salt input is 16..1024 decoded bytes.

The public salt and path are length-framed. The 128 target uses fixed-output
KMAC256; the 256 target uses SP 800-108 counter mode with HMAC-SHA3-512.
RFC 9106's named Argon2id profiles are 2 GiB/t=1/p=4 and 64 MiB/t=3/p=4;
selections meeting neither are accepted only as an explicit choice and warned.
Diagnostics go to stderr and the encoded subkey alone goes to stdout.
)HELP";

const char* const kMasterkeyHelp = R"HELP(Usage: arborkdf masterkey generate [options]

Required:
  --output-encoding hex|base64|wordlist

For hex or base64:
  --bits N                       Byte-aligned, 8..4096

For wordlist:
  --wordlist SOURCE              Custom file or embedded selector
  --words N                      1..4096 independently sampled words

Run `arborkdf wordlist list` for embedded selectors. embedded_bip39 is the
canonical English vocabulary only. Generated phrases have no BIP-39 checksum
and are not BIP-39 wallet mnemonics.

Linux /dev/urandom is mandatory and supplies at least 512 input bits. Move the
mouse to add supplemental input; Enter stops collection. If the mouse diagnostic
exceeds 512 bits, the OS input length is increased to the same byte-rounded size.
Final OS, mouse, and combined input diagnostics are separate compact tables.
Mouse estimates are never averaged or treated as validated security entropy.
The generated secret alone is written to stdout.
)HELP";

const char* const kSaltHelp = R"HELP(Usage: arborkdf salt generate [options]

Required:
  --bits N                       Byte-aligned, 128..8192
  --output-encoding hex|base64|wordlist

Conditional:
  --output-wordlist SOURCE       Custom file or embedded selector; required for
                                 wordlist output

The salt is public. Linux /dev/urandom supplies at least 512 input bits; mouse
input is supplemental and reported with the same three-table diagnostic display
as master-key generation.
)HELP";

const char* const kEncodingEncodeHelp = R"HELP(Usage: arborkdf encoding encode [options]

Required:
  --input-hex HEX                Strict hex: no 0x, whitespace, or odd nibble;
                                 maximum 1024 characters (4096 bits)
  --wordlist SOURCE              Custom file or embedded selector

The list must contain 2^k unique entries and the input bit count must be divisible
by k. No bit is padded, discarded, or truncated. Failure reports the reason and
closest lower/upper compatible wordlist sizes when they exist.
Run `arborkdf wordlist list` for embedded selectors. embedded_bip39 selects only
the vocabulary, not BIP-39 mnemonic semantics.
)HELP";

const char* const kEncodingDecodeHelp = R"HELP(Usage: arborkdf encoding decode [options]

Required:
  --input-words "WORDS ..."      Bare wordlist-bits-v1 phrase
  --wordlist SOURCE              Custom file or embedded selector; exact list
                                 and ordering used for encoding

Output is canonical lowercase hex. Unknown words and non-byte-aligned phrases are
rejected; there is no fallback interpretation.
embedded_bip39 selects only the vocabulary, not BIP-39 mnemonic semantics.
)HELP";

const char* const kWordlistGroupHelp = R"HELP(ArborKDF embedded wordlist tools

Usage:
  arborkdf wordlist list
  arborkdf wordlist export --wordlist SELECTOR --output FILE

`list` reports every compiled selector and its recovery metadata. `export`
writes the selector's canonical UTF-8 text to a new file without overwriting any
existing filesystem object. Custom wordlist files remain accepted by commands
that consume wordlists, but are not copied by `wordlist export`.
)HELP";

const char* const kWordlistListHelp = R"HELP(Usage: arborkdf wordlist list

Lists every embedded selector with its entry count, bit width, byte-aligned
encoding block, language membership and overlap counts, canonical byte count,
and SHA-512 over the exported bytes including the final LF.
)HELP";

const char* const kWordlistExportHelp = R"HELP(Usage: arborkdf wordlist export [options]

Required:
  --wordlist SELECTOR            Embedded selector from `wordlist list`
  --output FILE                  New output path; must not already exist

The output is the exact canonical UTF-8 wordlist with LF line endings and a
final LF. Existing files, directories, and symlinks are never overwritten.
Custom file paths and standard-output export are deliberately not supported.
)HELP";

class Options final {
public:
    explicit Options(const std::vector<std::string>& arguments) {
        for (std::size_t index = 0U; index < arguments.size();) {
            const std::string& name = arguments[index];
            if (name == "--help" || name == "-h" || name == "--master-stdin") {
                if (!flags_.emplace(name).second) {
                    throw Error("duplicate option: " + name);
                }
                ++index;
                continue;
            }
            if (name.size() < 3U || name[0] != '-' || name[1] != '-') {
                throw Error("unexpected positional argument: " + name);
            }
            if (index + 1U >= arguments.size()) {
                throw Error("missing value for option: " + name);
            }
            if (!values_.emplace(name, arguments[index + 1U]).second) {
                throw Error("duplicate option: " + name);
            }
            index += 2U;
        }
    }

    [[nodiscard]] bool flag(const std::string& name) const {
        return flags_.find(name) != flags_.end();
    }

    [[nodiscard]] bool help() const { return flag("--help") || flag("-h"); }

    [[nodiscard]] std::string required(const std::string& name) const {
        const auto iterator = values_.find(name);
        if (iterator == values_.end()) {
            throw Error("missing required option: " + name);
        }
        return iterator->second;
    }

    [[nodiscard]] std::optional<std::string> optional(const std::string& name) const {
        const auto iterator = values_.find(name);
        if (iterator == values_.end()) {
            return std::nullopt;
        }
        return iterator->second;
    }

    void reject_unknown(const std::vector<std::string>& allowed_values,
                        const std::vector<std::string>& allowed_flags) const {
        for (const auto& item : values_) {
            if (std::find(allowed_values.begin(), allowed_values.end(), item.first) ==
                allowed_values.end()) {
                throw Error("unknown option: " + item.first);
            }
        }
        for (const std::string& item : flags_) {
            if (item == "--help" || item == "-h") {
                continue;
            }
            if (std::find(allowed_flags.begin(), allowed_flags.end(), item) ==
                allowed_flags.end()) {
                throw Error("unknown flag: " + item);
            }
        }
    }

private:
    std::map<std::string, std::string> values_;
    std::set<std::string> flags_;
};

class SensitiveBytesGuard final {
public:
    explicit SensitiveBytesGuard(Bytes& value) noexcept : value_(value) {}
    ~SensitiveBytesGuard() {
        if (active_) {
            secure_clear(value_);
        }
    }

    SensitiveBytesGuard(const SensitiveBytesGuard&) = delete;
    SensitiveBytesGuard& operator=(const SensitiveBytesGuard&) = delete;

    void release() noexcept { active_ = false; }

private:
    Bytes& value_;
    bool active_{true};
};

class SensitiveStringGuard final {
public:
    explicit SensitiveStringGuard(std::string& value) noexcept : value_(value) {}
    ~SensitiveStringGuard() {
        if (active_) {
            secure_clear(value_);
        }
    }

    SensitiveStringGuard(const SensitiveStringGuard&) = delete;
    SensitiveStringGuard& operator=(const SensitiveStringGuard&) = delete;

    void release() noexcept { active_ = false; }

private:
    std::string& value_;
    bool active_{true};
};

class SensitiveIndicesGuard final {
public:
    explicit SensitiveIndicesGuard(std::vector<std::size_t>& value) noexcept
        : value_(value) {}
    ~SensitiveIndicesGuard() {
        if (active_ && !value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size() * sizeof(value_[0]));
        }
    }

    SensitiveIndicesGuard(const SensitiveIndicesGuard&) = delete;
    SensitiveIndicesGuard& operator=(const SensitiveIndicesGuard&) = delete;

    void release() noexcept { active_ = false; }

private:
    std::vector<std::size_t>& value_;
    bool active_{true};
};

class SensitiveMouseEventsGuard final {
public:
    explicit SensitiveMouseEventsGuard(std::vector<MouseEvent>& value) noexcept
        : value_(value) {}
    ~SensitiveMouseEventsGuard() {
        if (!value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size() * sizeof(value_[0]));
        }
    }

    SensitiveMouseEventsGuard(const SensitiveMouseEventsGuard&) = delete;
    SensitiveMouseEventsGuard& operator=(const SensitiveMouseEventsGuard&) = delete;

private:
    std::vector<MouseEvent>& value_;
};

void write_stdout(const std::string_view value, const bool append_newline) {
    if (value.size() > static_cast<std::size_t>(
                           std::numeric_limits<std::streamsize>::max())) {
        throw Error("output is too large for the standard stream API");
    }
    std::cout.write(value.data(), static_cast<std::streamsize>(value.size()));
    if (append_newline) {
        std::cout.put('\n');
    }
    std::cout.flush();
    if (!std::cout.good()) {
        throw Error("failed to write complete output to stdout");
    }
}

template <typename UInt>
[[nodiscard]] UInt parse_unsigned(const std::string& value, const std::string& name) {
    static_assert(std::numeric_limits<UInt>::is_integer, "UInt must be integral");
    static_assert(!std::numeric_limits<UInt>::is_signed, "UInt must be unsigned");
    UInt parsed = 0U;
    const char* const begin = value.data();
    const char* const end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed, 10);
    if (value.empty() || result.ec != std::errc{} || result.ptr != end) {
        throw Error(name + " must be a base-10 unsigned integer");
    }
    return parsed;
}

[[nodiscard]] SecurityTarget parse_security_target(const std::string& value) {
    if (value == "128") {
        return SecurityTarget::pq128;
    }
    if (value == "256") {
        return SecurityTarget::pq256;
    }
    throw Error("--security-target must be exactly 128 or 256");
}

void validate_path(const std::string& path) {
    constexpr std::string_view allowed = "abcdefghijklmnopqrstuvwxyz0123456789+-/.@#_:";
    if (path.size() < 8U || path.size() > 64U) {
        throw Error("path must contain between 8 and 64 ASCII characters");
    }
    for (const char value : path) {
        if (allowed.find(value) == std::string_view::npos) {
            throw Error("path contains a disallowed character; allowed set is [a-z0-9+-/.@#_:]");
        }
    }
}

void append_framed_string(Bytes& output, const std::string_view value) {
    append_u64_be(output, static_cast<std::uint64_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

void append_framed_bytes(Bytes& output, const Bytes& value) {
    append_u64_be(output, static_cast<std::uint64_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

[[nodiscard]] Bytes frame_utf8_master(const std::string_view master) {
    if (master.empty()) {
        throw Error("UTF-8 master input must not be empty");
    }
    if (master.size() > kMaximumMasterBytes) {
        throw Error("UTF-8 master input exceeds 4096 bytes");
    }
    require_valid_utf8(master, "master input");
    Bytes output;
    SensitiveBytesGuard output_guard(output);
    const std::string tag = "ArborKDF/master/utf8/v1";
    output.reserve(tag.size() + master.size() + 16U);
    append_framed_string(output, tag);
    append_framed_string(output, master);
    output_guard.release();
    return output;
}

[[nodiscard]] Bytes frame_raw_master(Bytes raw) {
    const SensitiveBytesGuard raw_guard(raw);
    if (raw.empty()) {
        throw Error("raw-byte master input must not be empty");
    }
    if (raw.size() > kMaximumMasterBytes) {
        throw Error("raw-byte master input exceeds 4096 decoded bytes");
    }
    Bytes output;
    SensitiveBytesGuard output_guard(output);
    constexpr std::string_view tag = "ArborKDF/master/raw-bytes/v1";
    output.reserve(tag.size() + raw.size() + 16U);
    append_framed_string(output, tag);
    append_framed_bytes(output, raw);
    output_guard.release();
    return output;
}

[[nodiscard]] std::string read_bounded_stdin_line(const std::size_t maximum_bytes) {
    std::string value;
    const SensitiveStringGuard value_guard(value);
    if (maximum_bytes > value.max_size()) {
        throw Error("master input limit exceeds this platform's string capacity");
    }
    try {
        value.reserve(maximum_bytes);
    } catch (const std::bad_alloc&) {
        throw Error("unable to allocate the bounded master-input buffer");
    } catch (const std::length_error&) {
        throw Error("master input limit exceeds this platform's string capacity");
    }
    bool read_anything = false;
    for (;;) {
        const std::istream::int_type next = std::cin.get();
        if (next == std::istream::traits_type::eof()) {
            if (std::cin.bad() || !read_anything) {
                throw Error("failed to read master input from stdin");
            }
            break;
        }
        read_anything = true;
        const char character = std::istream::traits_type::to_char_type(next);
        if (character == '\n') {
            break;
        }
        if (value.size() >= maximum_bytes) {
            throw Error("master input exceeds the selected encoding's byte limit");
        }
        value.push_back(character);
    }
    if (!value.empty() && value.back() == '\r') {
        value.back() = '\0';
        value.pop_back();
    }
    std::string result;
    result.swap(value);
    return result;
}

[[nodiscard]] std::string read_master_line(const bool from_stdin,
                                           const std::size_t maximum_bytes) {
    if (from_stdin) {
        return read_bounded_stdin_line(maximum_bytes);
    }

    std::string first = read_hidden_line("Master input: ", maximum_bytes);
    const SensitiveStringGuard first_guard(first);
    std::string confirmation =
        read_hidden_line("Confirm master input: ", maximum_bytes);
    const SensitiveStringGuard confirmation_guard(confirmation);
    const bool equal = first.size() == confirmation.size() &&
                       (first.empty() ||
                        CRYPTO_memcmp(first.data(), confirmation.data(), first.size()) == 0);
    if (!equal) {
        throw Error("master input confirmation does not match");
    }
    std::string result;
    result.swap(first);
    return result;
}

class MasterInputDecoder final {
public:
    explicit MasterInputDecoder(const Options& options) {
        const std::string encoding = options.required("--input-encoding");
        if (encoding == "utf8") {
            if (options.optional("--input-wordlist").has_value()) {
                throw Error("--input-wordlist is only valid with wordlist input");
            }
            kind_ = Kind::utf8;
            maximum_bytes_ = kMaximumMasterBytes;
            return;
        }
        if (encoding == "hex" || encoding == "base64") {
            if (options.optional("--input-wordlist").has_value()) {
                throw Error("--input-wordlist is only valid with wordlist input");
            }
            kind_ = encoding == "hex" ? Kind::hex : Kind::base64;
            maximum_bytes_ = encoding == "hex"
                                 ? kMaximumHexMasterCharacters
                                 : kMaximumBase64MasterCharacters;
            return;
        }
        if (encoding == "wordlist") {
            const std::optional<std::string> source =
                options.optional("--input-wordlist");
            if (!source.has_value()) {
                throw Error("--input-wordlist is required for wordlist input");
            }
            wordlist_.emplace(Wordlist::from_source(*source));
            kind_ = Kind::wordlist;
            maximum_bytes_ = kMaximumMasterPhraseBytes;
            return;
        }
        throw Error(
            "--input-encoding must be exactly utf8, hex, base64, or wordlist");
    }

    [[nodiscard]] std::size_t maximum_bytes() const noexcept {
        return maximum_bytes_;
    }

    [[nodiscard]] Bytes frame(const std::string_view master) const {
        switch (kind_) {
            case Kind::utf8:
                return frame_utf8_master(master);
            case Kind::hex:
                return frame_raw_master(
                    decode_hex(master, kMaximumHexMasterCharacters));
            case Kind::base64:
                return frame_raw_master(
                    decode_base64(master, kMaximumBase64MasterCharacters));
            case Kind::wordlist:
                if (!wordlist_.has_value()) {
                    throw Error("internal input wordlist state is missing");
                }
                return frame_master_phrase_v1(master, *wordlist_);
        }
        throw Error("internal input encoding state is invalid");
    }

private:
    enum class Kind { utf8, hex, base64, wordlist };

    Kind kind_{Kind::utf8};
    std::size_t maximum_bytes_{kMaximumMasterBytes};
    std::optional<Wordlist> wordlist_;
};

[[nodiscard]] Bytes read_and_frame_master(const Options& options,
                                          const MasterInputDecoder& decoder) {
    std::string master = read_master_line(
        options.flag("--master-stdin"), decoder.maximum_bytes());
    const SensitiveStringGuard master_guard(master);
    return decoder.frame(master);
}

[[nodiscard]] std::vector<std::string> split_words(
    const std::string& phrase,
    const std::optional<std::size_t> maximum_words = std::nullopt) {
    if (phrase.empty()) {
        return {};
    }
    require_valid_utf8(phrase, "wordlist phrase");
    std::vector<std::string> words;
    const auto append_word = [&words, maximum_words](
                                 const std::string& word) {
        if (maximum_words.has_value() && words.size() >= *maximum_words) {
            throw Error(
                "wordlist salt exceeds the 8192-bit decoded-size limit");
        }
        words.push_back(word);
    };
    std::size_t start = 0U;
    for (std::size_t offset = 0U; offset < phrase.size(); ++offset) {
        const unsigned char byte = static_cast<unsigned char>(phrase[offset]);
        if (byte == static_cast<unsigned char>(' ')) {
            if (offset == start) {
                throw Error("wordlist phrase must use exactly one ASCII space between words");
            }
            append_word(phrase.substr(start, offset - start));
            start = offset + 1U;
        } else if (byte <= 0x20U || byte == 0x7fU) {
            throw Error("wordlist phrase contains ASCII whitespace or a control byte");
        }
    }
    if (start == phrase.size()) {
        throw Error("wordlist phrase may not end with a space");
    }
    append_word(phrase.substr(start));
    return words;
}

[[nodiscard]] Bytes decode_public_salt(const Options& options) {
    const std::optional<std::string> legacy_hex = options.optional("--salt-hex");
    const std::optional<std::string> encoded = options.optional("--salt");
    const std::optional<std::string> encoding = options.optional("--salt-encoding");
    const std::optional<std::string> wordlist_source =
        options.optional("--salt-wordlist");

    Bytes salt;
    if (legacy_hex.has_value()) {
        if (encoded.has_value() || encoding.has_value() || wordlist_source.has_value()) {
            throw Error(
                "--salt-hex cannot be combined with --salt, --salt-encoding, "
                "or --salt-wordlist");
        }
        salt = decode_hex(*legacy_hex, 2048U);
    } else {
        if (!encoded.has_value()) {
            throw Error("missing required option: --salt");
        }
        if (!encoding.has_value()) {
            throw Error("missing required option: --salt-encoding");
        }
        if (*encoding == "hex") {
            if (wordlist_source.has_value()) {
                throw Error("--salt-wordlist is only valid with wordlist salt input");
            }
            salt = decode_hex(*encoded, 2048U);
        } else if (*encoding == "base64") {
            if (wordlist_source.has_value()) {
                throw Error("--salt-wordlist is only valid with wordlist salt input");
            }
            salt = decode_base64(*encoded, kMaximumBase64SaltCharacters);
        } else if (*encoding == "wordlist") {
            if (!wordlist_source.has_value()) {
                throw Error("--salt-wordlist is required for wordlist salt input");
            }
            if (encoded->size() > kMaximumMasterPhraseBytes) {
                throw Error("wordlist salt input exceeds 8 MiB");
            }
            const Wordlist wordlist = Wordlist::from_source(*wordlist_source);
            const WordlistBitsCompatibility list_diagnostic =
                analyze_wordlist_bits_compatibility(0U, wordlist.size());
            if (!list_diagnostic.bits_per_word.has_value()) {
                throw WordlistCodecError(list_diagnostic);
            }
            const std::size_t maximum_words =
                kMaximumSaltBits / *list_diagnostic.bits_per_word;
            salt = decode_wordlist_bits_v1(
                split_words(*encoded, maximum_words), wordlist);
        } else {
            throw Error(
                "--salt-encoding must be exactly hex, base64, or wordlist");
        }
    }

    if (salt.size() < 16U || salt.size() > 1024U) {
        secure_clear(salt);
        throw Error("public salt must contain between 16 and 1024 decoded bytes");
    }
    return salt;
}

class OutputEncoder final {
public:
    OutputEncoder(const std::string& encoding,
                  const std::optional<std::string>& wordlist_source,
                  const std::size_t output_bytes) {
        if (output_bytes > std::numeric_limits<std::size_t>::max() / 8U) {
            throw Error("output length cannot be expressed in bits");
        }
        if (encoding == "hex") {
            reject_wordlist_source(wordlist_source);
            kind_ = Kind::hex;
            return;
        }
        if (encoding == "base64") {
            reject_wordlist_source(wordlist_source);
            kind_ = Kind::base64;
            return;
        }
        if (encoding != "wordlist") {
            throw Error("--output-encoding must be exactly hex, base64, or wordlist");
        }
        if (!wordlist_source.has_value()) {
            throw Error("--output-wordlist is required for wordlist output");
        }
        kind_ = Kind::wordlist;
        wordlist_.emplace(Wordlist::from_source(*wordlist_source));
        const WordlistBitsCompatibility diagnostic =
            analyze_wordlist_bits_compatibility(output_bytes * 8U, wordlist_->size());
        if (!diagnostic.compatible) {
            throw WordlistCodecError(diagnostic);
        }
    }

    [[nodiscard]] std::string encode(const Bytes& bytes) const {
        switch (kind_) {
            case Kind::hex:
                return encode_hex(bytes);
            case Kind::base64:
                return encode_base64(bytes);
            case Kind::wordlist:
                if (!wordlist_.has_value()) {
                    throw Error("internal output wordlist state is missing");
                }
                return join_words(encode_wordlist_bits_v1(bytes, *wordlist_));
        }
        throw Error("internal output encoding state is invalid");
    }

private:
    enum class Kind { hex, base64, wordlist };

    static void reject_wordlist_source(
        const std::optional<std::string>& wordlist_source) {
        if (wordlist_source.has_value()) {
            throw Error("--output-wordlist is only valid with wordlist output");
        }
    }

    Kind kind_{Kind::hex};
    std::optional<Wordlist> wordlist_;
};

[[nodiscard]] KdfParameters parse_kdf_parameters(const Options& options) {
    KdfParameters parameters{};
    parameters.pbkdf2_iterations =
        parse_unsigned<std::uint32_t>(options.required("--pbkdf2-iterations"),
                                      "--pbkdf2-iterations");
    parameters.argon2_memory_kib =
        parse_unsigned<std::uint32_t>(options.required("--argon2-memory-kib"),
                                      "--argon2-memory-kib");
    parameters.argon2_iterations =
        parse_unsigned<std::uint32_t>(options.required("--argon2-iterations"),
                                      "--argon2-iterations");
    parameters.argon2_parallelism =
        parse_unsigned<std::uint32_t>(options.required("--argon2-parallelism"),
                                      "--argon2-parallelism");
    parameters.output_bits =
        parse_unsigned<std::size_t>(options.required("--output-bits"), "--output-bits");
    parameters.security_target =
        parse_security_target(options.required("--security-target"));
    validate_kdf_parameters(parameters);
    return parameters;
}

void print_parameter_advisory(const KdfParameters& parameters) {
    const bool is_first_rfc_profile =
        parameters.argon2_memory_kib == 2097152U &&
        parameters.argon2_iterations == 1U &&
        parameters.argon2_parallelism == 4U;
    const bool is_second_rfc_profile =
        parameters.argon2_memory_kib == 65536U &&
        parameters.argon2_iterations == 3U &&
        parameters.argon2_parallelism == 4U;
    if (!is_first_rfc_profile && !is_second_rfc_profile) {
        std::cerr <<
            "Warning: selected Argon2id tuple is not exactly either named RFC "
            "9106 profile (2 GiB/t=1/p=4 or 64 MiB/t=3/p=4). Custom explicit "
            "values are accepted; calibrate them for the target machine and "
            "threat model.\n";
    }
}

int command_subkey_generate(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kSubkeyHelp, false);
        return 0;
    }
    options.reject_unknown(
        {"--input-encoding",
         "--input-wordlist",
         "--salt",
         "--salt-encoding",
         "--salt-wordlist",
         "--salt-hex",
         "--path",
         "--pbkdf2-iterations",
         "--argon2-memory-kib",
         "--argon2-iterations",
         "--argon2-parallelism",
         "--security-target",
         "--output-bits",
         "--output-encoding",
         "--output-wordlist"},
        {"--master-stdin"});

    const std::string path = options.required("--path");
    validate_path(path);
    Bytes salt = decode_public_salt(options);
    const SensitiveBytesGuard salt_guard(salt);
    const KdfParameters parameters = parse_kdf_parameters(options);
    const OutputEncoder output_encoder(options.required("--output-encoding"),
                                       options.optional("--output-wordlist"),
                                       parameters.output_bits / 8U);
    const MasterInputDecoder input_decoder(options);
    print_parameter_advisory(parameters);
    std::cerr << "Security target selects the keyed-derivation/output margin only; "
                 "effective security is capped by master entropy and the user-selected "
                 "password-hardening costs.\n";
    Bytes master = read_and_frame_master(options, input_decoder);
    const SensitiveBytesGuard master_guard(master);
    Bytes subkey = derive_subkey(master, salt, path, parameters);
    const SensitiveBytesGuard subkey_guard(subkey);
    std::string encoded = output_encoder.encode(subkey);
    const SensitiveStringGuard encoded_guard(encoded);
    write_stdout(encoded, true);
    return 0;
}

[[nodiscard]] std::uint64_t load_u64(const Bytes& bytes, const std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 8U) {
        throw Error("internal random stream exhausted");
    }
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 8U; ++index) {
        value = (value << 8U) | static_cast<std::uint64_t>(bytes[offset + index]);
    }
    return value;
}

struct WordSamplingResult final {
    std::vector<std::size_t> indices;
    ConditioningDiagnostics diagnostics;
};

void accumulate_conditioning_diagnostics(
    ConditioningDiagnostics& aggregate,
    const ConditioningDiagnostics& next) {
    if (aggregate.os.source != next.os.source ||
        aggregate.os.path != next.os.path) {
        throw Error("random sampler received inconsistent OS source diagnostics");
    }
    if (next.os.bytes_read >
            std::numeric_limits<std::size_t>::max() - aggregate.os.bytes_read ||
        next.os.input_bits >
            std::numeric_limits<std::size_t>::max() - aggregate.os.input_bits) {
        throw Error("random sampler diagnostic length overflow");
    }
    aggregate.os.bytes_read += next.os.bytes_read;
    aggregate.os.input_bits += next.os.input_bits;
    aggregate.combined.os_supplied_input_bits +=
        next.combined.os_supplied_input_bits;
    // Every rejection-sampling batch gets a fresh independent OS read, but it
    // reuses the same mouse transcript. Count that mouse evidence only once.
    aggregate.combined.policy_weighted_total_bits =
        aggregate.combined.os_supplied_input_bits +
        aggregate.combined.mouse_policy_weight_bits;
    const double total = aggregate.combined.policy_weighted_total_bits;
    if (total > 0.0) {
        aggregate.combined.os_policy_percent =
            (aggregate.combined.os_supplied_input_bits / total) * 100.0;
        aggregate.combined.mouse_policy_percent =
            (aggregate.combined.mouse_policy_weight_bits / total) * 100.0;
    }
}

[[nodiscard]] WordSamplingResult sample_word_indices(
    const std::vector<MouseEvent>& events,
    const std::size_t word_count,
    const std::size_t wordlist_size) {
    if (word_count == 0U) {
        throw Error("word sampler requires at least one word");
    }
    if (wordlist_size < 2U ||
        wordlist_size > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
        throw Error("wordlist size is outside the unbiased sampler range");
    }
    const std::uint64_t modulus = static_cast<std::uint64_t>(wordlist_size);
    const std::uint64_t rejection_floor = (UINT64_C(0) - modulus) % modulus;
    WordSamplingResult result{};
    SensitiveIndicesGuard indices_guard(result.indices);
    result.indices.reserve(word_count);
    bool have_diagnostics = false;
    std::uint64_t batch = 0U;
    while (result.indices.size() < word_count) {
        const std::size_t remaining = word_count - result.indices.size();
        const std::size_t values_to_request = remaining + 16U;
        if (values_to_request > std::numeric_limits<std::size_t>::max() / 8U) {
            throw Error("word count is too large");
        }
        const std::string purpose =
            "ArborKDF/masterkey/wordlist/v1/batch/" + std::to_string(batch);
        ConditionedRandomResult conditioned =
            condition_random(events, purpose, values_to_request * 8U);
        SensitiveBytesGuard random_guard(conditioned.bytes);
        if (!have_diagnostics) {
            result.diagnostics = std::move(conditioned.diagnostics);
            have_diagnostics = true;
        } else {
            accumulate_conditioning_diagnostics(result.diagnostics,
                                                 conditioned.diagnostics);
        }
        for (std::size_t offset = 0U;
             offset + 8U <= conditioned.bytes.size() &&
                 result.indices.size() < word_count;
             offset += 8U) {
            const std::uint64_t candidate = load_u64(conditioned.bytes, offset);
            if (candidate >= rejection_floor) {
                result.indices.push_back(
                    static_cast<std::size_t>(candidate % modulus));
            }
        }
        if (batch == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("unbiased word sampler counter exhausted");
        }
        ++batch;
    }
    indices_guard.release();
    return result;
}

int command_masterkey_generate(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kMasterkeyHelp, false);
        return 0;
    }
    options.reject_unknown({"--output-encoding", "--bits", "--wordlist", "--words"}, {});
    const std::string encoding = options.required("--output-encoding");

    if (encoding == "wordlist") {
        if (options.optional("--bits").has_value()) {
            throw Error("--bits is not used for a generated wordlist master; use --words");
        }
        const Wordlist wordlist = Wordlist::from_source(options.required("--wordlist"));
        const std::size_t words =
            parse_unsigned<std::size_t>(options.required("--words"), "--words");
        if (words == 0U || words > kMaximumGeneratedWords) {
            throw Error("--words must be between 1 and 4096");
        }
        std::vector<MouseEvent> events = collect_mouse_events();
        const SensitiveMouseEventsGuard events_guard(events);
        WordSamplingResult sampled =
            sample_word_indices(events, words, wordlist.size());
        const SensitiveIndicesGuard indices_guard(sampled.indices);
        std::cerr << '\n'
                  << format_conditioning_diagnostics(sampled.diagnostics);
        const long double entropy = master_phrase_entropy_bits(words, wordlist.size());
        std::cerr << "Master phrase ideal code-space entropy: " <<
            static_cast<double>(entropy) << " bits (" << words << " * log2(" <<
            wordlist.size() << "))\n";
        const long double security_ceiling = std::min(entropy, 256.0L);
        std::cerr << "Generator security-strength ceiling: " <<
            static_cast<double>(security_ceiling) <<
            " classical bits (SHAKE256 ceiling; mouse is diagnostic only)\n";
        std::cerr << "Conservative generic quantum-search exponent: at most " <<
            static_cast<double>(security_ceiling / 2.0L) <<
            " bits; this is not a certification\n";
        std::string phrase =
            format_master_phrase_indices(sampled.indices, wordlist);
        const SensitiveStringGuard phrase_guard(phrase);
        write_stdout(phrase, true);
        return 0;
    }

    if (encoding != "hex" && encoding != "base64") {
        throw Error("--output-encoding must be exactly hex, base64, or wordlist");
    }
    if (options.optional("--wordlist").has_value() || options.optional("--words").has_value()) {
        throw Error("--wordlist and --words are only valid with wordlist output");
    }
    const std::size_t bits =
        parse_unsigned<std::size_t>(options.required("--bits"), "--bits");
    if (bits == 0U || bits > kMaximumGeneratedBits || bits % 8U != 0U) {
        throw Error("--bits must be a byte-aligned value between 8 and 4096");
    }
    std::vector<MouseEvent> events = collect_mouse_events();
    const SensitiveMouseEventsGuard events_guard(events);
    ConditionedRandomResult conditioned =
        condition_random(events, "ArborKDF/masterkey/bytes/v1", bits / 8U);
    Bytes secret = std::move(conditioned.bytes);
    const SensitiveBytesGuard secret_guard(secret);
    std::cerr << '\n' << format_conditioning_diagnostics(conditioned.diagnostics);
    std::string encoded = encoding == "hex" ? encode_hex(secret) : encode_base64(secret);
    const SensitiveStringGuard encoded_guard(encoded);
    const std::size_t security_ceiling = std::min(bits, std::size_t{256U});
    std::cerr << "Generated master code-space size: " << bits << " bits\n";
    std::cerr << "Generator security-strength ceiling: " << security_ceiling <<
        " classical bits (SHAKE256 ceiling; mouse is diagnostic only)\n";
    std::cerr << "Conservative generic quantum-search exponent: at most " <<
        security_ceiling / 2U << " bits; this is not a certification\n";
    write_stdout(encoded, true);
    return 0;
}

int command_salt_generate(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kSaltHelp, false);
        return 0;
    }
    options.reject_unknown({"--bits", "--output-encoding", "--output-wordlist"}, {});
    const std::size_t bits =
        parse_unsigned<std::size_t>(options.required("--bits"), "--bits");
    if (bits < kMinimumSaltBits || bits > kMaximumSaltBits || bits % 8U != 0U) {
        throw Error("--bits must be byte-aligned and between 128 and 8192 for a salt");
    }
    const OutputEncoder output_encoder(options.required("--output-encoding"),
                                       options.optional("--output-wordlist"),
                                       bits / 8U);
    std::vector<MouseEvent> events = collect_mouse_events();
    const SensitiveMouseEventsGuard events_guard(events);
    ConditionedRandomResult conditioned =
        condition_random(events, "ArborKDF/salt/v1", bits / 8U);
    Bytes salt = std::move(conditioned.bytes);
    const SensitiveBytesGuard salt_guard(salt);
    std::cerr << '\n' << format_conditioning_diagnostics(conditioned.diagnostics);
    std::string output = output_encoder.encode(salt);
    const SensitiveStringGuard output_guard(output);
    write_stdout(output, true);
    return 0;
}

int command_encoding_encode(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kEncodingEncodeHelp, false);
        return 0;
    }
    options.reject_unknown({"--input-hex", "--wordlist"}, {});
    Bytes input = decode_hex(options.required("--input-hex"));
    const SensitiveBytesGuard input_guard(input);
    const Wordlist wordlist = Wordlist::from_source(options.required("--wordlist"));
    std::string output = join_words(encode_wordlist_bits_v1(input, wordlist));
    const SensitiveStringGuard output_guard(output);
    write_stdout(output, true);
    return 0;
}

int command_encoding_decode(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kEncodingDecodeHelp, false);
        return 0;
    }
    options.reject_unknown({"--input-words", "--wordlist"}, {});
    const Wordlist wordlist = Wordlist::from_source(options.required("--wordlist"));
    const std::vector<std::string> words = split_words(options.required("--input-words"));
    Bytes decoded = decode_wordlist_bits_v1(words, wordlist);
    const SensitiveBytesGuard decoded_guard(decoded);
    if (decoded.size() > 512U) {
        throw Error("decoded value exceeds the 4096-bit encoding limit");
    }
    std::string output = encode_hex(decoded);
    const SensitiveStringGuard output_guard(output);
    write_stdout(output, true);
    return 0;
}

void append_named_counts(
    std::ostringstream& output,
    const std::vector<EmbeddedWordlistCount>& counts) {
    if (counts.empty()) {
        output << "none";
        return;
    }
    for (std::size_t index = 0U; index < counts.size(); ++index) {
        if (index != 0U) {
            output << ',';
        }
        output << counts[index].label << '=' << counts[index].count;
    }
}

int command_wordlist_list(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kWordlistListHelp, false);
        return 0;
    }
    options.reject_unknown({}, {});

    std::ostringstream output;
    const auto& catalog = embedded_wordlist_catalog();
    for (std::size_t index = 0U; index < catalog.size(); ++index) {
        const EmbeddedWordlistMetadata& metadata = catalog[index];
        if (index != 0U) {
            output << '\n';
        }
        output << "selector: " << metadata.selector << '\n'
               << "name: " << metadata.display_name << '\n'
               << "standard-id: " << metadata.standard_id << '\n'
               << "entries: " << metadata.word_count << '\n'
               << "bits-per-word: " << metadata.bits_per_word << '\n'
               << "byte-aligned-block-bits: "
               << metadata.byte_aligned_block_bits << '\n'
               << "languages: " << metadata.languages << '\n'
               << "language-memberships: ";
        append_named_counts(output, metadata.language_memberships);
        output << '\n' << "exact-overlaps: ";
        append_named_counts(output, metadata.exact_overlaps);
        output << '\n'
               << "canonical-bytes: " << metadata.canonical_text_bytes << '\n'
               << "sha512: " << metadata.sha512_hex << '\n';
    }
    write_stdout(output.str(), false);
    return 0;
}

int command_wordlist_export(const std::vector<std::string>& arguments) {
    const Options options(arguments);
    if (options.help()) {
        write_stdout(kWordlistExportHelp, false);
        return 0;
    }
    options.reject_unknown({"--wordlist", "--output"}, {});

    const std::string selector = options.required("--wordlist");
    const std::string output_path = options.required("--output");
    if (output_path == "-") {
        throw Error("--output must name a new file; standard output is not supported");
    }
    const std::string canonical =
        canonical_embedded_wordlist_text(selector);
    write_new_binary_file(output_path, canonical);

    const auto& catalog = embedded_wordlist_catalog();
    const auto found = std::find_if(
        catalog.begin(), catalog.end(),
        [&selector](const EmbeddedWordlistMetadata& metadata) {
            return metadata.selector == selector;
        });
    if (found == catalog.end()) {
        throw Error("internal embedded wordlist catalog mismatch");
    }
    std::ostringstream confirmation;
    confirmation << "exported " << found->selector << " (" << found->word_count
                 << " entries, " << found->canonical_text_bytes
                 << " bytes, SHA-512 " << found->sha512_hex << ')';
    write_stdout(confirmation.str(), true);
    return 0;
}

[[nodiscard]] std::vector<std::string> tail_arguments(const int argc,
                                                       char* argv[],
                                                       const int offset) {
    std::vector<std::string> result;
    for (int index = offset; index < argc; ++index) {
        result.emplace_back(argv[index]);
    }
    return result;
}

}  // namespace

int run_cli(const int argc, char* argv[]) {
    try {
        if (argc == 1) {
            write_stdout(kGlobalHelp, false);
            return 0;
        }
        const std::string first(argv[1]);
        if ((first == "--help" || first == "-h") && argc == 2) {
            write_stdout(kGlobalHelp, false);
            return 0;
        }
        if (first == "--version" && argc == 2) {
            write_stdout(kVersion, false);
            return 0;
        }
        if (first == "--gui" || first == "-g") {
            throw Error("GUI support was deliberately removed from the current scope; use the CLI");
        }
        if (argc == 3 && (std::string(argv[2]) == "--help" ||
                          std::string(argv[2]) == "-h")) {
            if (first == "subkey") {
                write_stdout(kSubkeyHelp, false);
                return 0;
            }
            if (first == "masterkey") {
                write_stdout(kMasterkeyHelp, false);
                return 0;
            }
            if (first == "salt") {
                write_stdout(kSaltHelp, false);
                return 0;
            }
            if (first == "encoding") {
                const std::string help = std::string("ArborKDF encoding tools\n\n") +
                                         kEncodingEncodeHelp + '\n' +
                                         kEncodingDecodeHelp;
                write_stdout(help, false);
                return 0;
            }
            if (first == "wordlist") {
                write_stdout(kWordlistGroupHelp, false);
                return 0;
            }
        }
        if (first == "subkey" && argc >= 3 && std::string(argv[2]) == "generate") {
            return command_subkey_generate(tail_arguments(argc, argv, 3));
        }
        if (first == "masterkey" && argc >= 3 && std::string(argv[2]) == "generate") {
            return command_masterkey_generate(tail_arguments(argc, argv, 3));
        }
        if (first == "salt" && argc >= 3 && std::string(argv[2]) == "generate") {
            return command_salt_generate(tail_arguments(argc, argv, 3));
        }
        if (first == "encoding" && argc >= 3) {
            const std::string operation(argv[2]);
            if (operation == "encode") {
                return command_encoding_encode(tail_arguments(argc, argv, 3));
            }
            if (operation == "decode") {
                return command_encoding_decode(tail_arguments(argc, argv, 3));
            }
        }
        if (first == "wordlist" && argc >= 3) {
            const std::string operation(argv[2]);
            if (operation == "list") {
                return command_wordlist_list(tail_arguments(argc, argv, 3));
            }
            if (operation == "export") {
                return command_wordlist_export(tail_arguments(argc, argv, 3));
            }
        }
        throw Error("unknown or incomplete command; run arborkdf --help");
    } catch (const std::exception& exception) {
        std::cerr << "error: " << exception.what() << '\n';
        return 2;
    }
}

}  // namespace arborkdf
