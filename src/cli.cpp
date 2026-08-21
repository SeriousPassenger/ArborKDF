#include "arborkdf/cli.hpp"

#include "arborkdf/bytes.hpp"
#include "arborkdf/codec.hpp"
#include "arborkdf/crypto.hpp"
#include "arborkdf/entropy.hpp"
#include "arborkdf/error.hpp"
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

const char* const kGlobalHelp = R"HELP(ArborKDF - offline, deterministic, path-based key derivation

Usage:
  arborkdf --help
  arborkdf subkey generate [options]
  arborkdf masterkey generate [options]
  arborkdf salt generate [options]
  arborkdf encoding encode [options]
  arborkdf encoding decode [options]

Run a command with --help for every required option and security note. ArborKDF
has no GUI, no network behavior, no color output, and no cryptographic defaults.
)HELP";

const char* const kSubkeyHelp = R"HELP(Usage: arborkdf subkey generate [options]

Required:
  --input-encoding utf8|wordlist
  --salt-hex HEX                 Public salt, strict hex, 16..1024 bytes
  --path PATH                    8..64 chars from [a-z0-9+-/.@#_:]
  --pbkdf2-iterations N          No default
  --argon2-memory-kib N          No default; at least 8 * parallelism
  --argon2-iterations N          No default
  --argon2-parallelism N         No default
  --security-target 128|256      Keyed-output quantum-search margin only
  --output-bits N                Byte-aligned; >=256 or >=512 for target
  --output-encoding hex|base64|wordlist

Conditional:
  --input-wordlist SOURCE        File path or embedded_bip39; required for
                                 wordlist master input
  --output-wordlist SOURCE       File path or embedded_bip39; required for
                                 wordlist output
  --master-stdin                 Read one master line from stdin instead of a
                                 hidden, twice-confirmed interactive prompt;
                                 stdin mode is deliberately single-read

embedded_bip39 is the canonical English vocabulary only. ArborKDF phrases have
no BIP-39 checksum and do not use BIP-39's mnemonic-to-seed procedure.

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
  --wordlist SOURCE              File path or embedded_bip39
  --words N                      1..4096 independently sampled words

embedded_bip39 is the canonical English vocabulary only. Generated phrases have
no BIP-39 checksum and are not BIP-39 wallet mnemonics.

OS randomness is mandatory. Move the mouse to collect supplemental input; the
256-bit progress bar is a diagnostic minimum, can move backward, can exceed 100%,
and stops only when Enter is pressed. Estimators are shown individually and are
never averaged. Mouse security credit remains 0 without offline source validation.
The generated secret alone is written to stdout.
)HELP";

const char* const kSaltHelp = R"HELP(Usage: arborkdf salt generate [options]

Required:
  --bits N                       Byte-aligned, 128..8192
  --output-encoding hex|base64|wordlist

Conditional:
  --output-wordlist SOURCE       File path or embedded_bip39; required for
                                 wordlist output

The salt is public. OS randomness is mandatory; mouse input is supplemental and
reported with the same non-averaged diagnostic display as master-key generation.
)HELP";

const char* const kEncodingEncodeHelp = R"HELP(Usage: arborkdf encoding encode [options]

Required:
  --input-hex HEX                Strict hex: no 0x, whitespace, or odd nibble;
                                 maximum 1024 characters (4096 bits)
  --wordlist SOURCE              File path or embedded_bip39

The list must contain 2^k unique entries and the input bit count must be divisible
by k. No bit is padded, discarded, or truncated. Failure reports the reason and
closest lower/upper compatible wordlist sizes when they exist.
embedded_bip39 selects only the vocabulary, not BIP-39 mnemonic semantics.
)HELP";

const char* const kEncodingDecodeHelp = R"HELP(Usage: arborkdf encoding decode [options]

Required:
  --input-words "WORDS ..."      Bare wordlist-bits-v1 phrase
  --wordlist SOURCE              File path or embedded_bip39; exact list and
                                 ordering used for encoding

Output is canonical lowercase hex. Unknown words and non-byte-aligned phrases are
rejected; there is no fallback interpretation.
embedded_bip39 selects only the vocabulary, not BIP-39 mnemonic semantics.
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
    ~SensitiveBytesGuard() { secure_clear(value_); }

    SensitiveBytesGuard(const SensitiveBytesGuard&) = delete;
    SensitiveBytesGuard& operator=(const SensitiveBytesGuard&) = delete;

private:
    Bytes& value_;
};

class SensitiveStringGuard final {
public:
    explicit SensitiveStringGuard(std::string& value) noexcept : value_(value) {}
    ~SensitiveStringGuard() { secure_clear(value_); }

    SensitiveStringGuard(const SensitiveStringGuard&) = delete;
    SensitiveStringGuard& operator=(const SensitiveStringGuard&) = delete;

private:
    std::string& value_;
};

class SensitiveIndicesGuard final {
public:
    explicit SensitiveIndicesGuard(std::vector<std::size_t>& value) noexcept
        : value_(value) {}
    ~SensitiveIndicesGuard() {
        if (!value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size() * sizeof(value_[0]));
        }
    }

    SensitiveIndicesGuard(const SensitiveIndicesGuard&) = delete;
    SensitiveIndicesGuard& operator=(const SensitiveIndicesGuard&) = delete;

private:
    std::vector<std::size_t>& value_;
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

[[nodiscard]] Bytes frame_utf8_master(const std::string_view master) {
    if (master.empty()) {
        throw Error("UTF-8 master input must not be empty");
    }
    if (master.size() > kMaximumMasterBytes) {
        throw Error("UTF-8 master input exceeds 4096 bytes");
    }
    require_valid_utf8(master, "master input");
    Bytes output;
    const std::string tag = "ArborKDF/master/utf8/v1";
    output.reserve(tag.size() + master.size() + 16U);
    append_framed_string(output, tag);
    append_framed_string(output, master);
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
        throw Error("--input-encoding must be exactly utf8 or wordlist");
    }

    [[nodiscard]] std::size_t maximum_bytes() const noexcept {
        return maximum_bytes_;
    }

    [[nodiscard]] Bytes frame(const std::string_view master) const {
        switch (kind_) {
            case Kind::utf8:
                return frame_utf8_master(master);
            case Kind::wordlist:
                if (!wordlist_.has_value()) {
                    throw Error("internal input wordlist state is missing");
                }
                return frame_master_phrase_v1(master, *wordlist_);
        }
        throw Error("internal input encoding state is invalid");
    }

private:
    enum class Kind { utf8, wordlist };

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

[[nodiscard]] std::vector<std::string> split_words(const std::string& phrase) {
    if (phrase.empty()) {
        return {};
    }
    require_valid_utf8(phrase, "wordlist phrase");
    std::vector<std::string> words;
    std::size_t start = 0U;
    for (std::size_t offset = 0U; offset < phrase.size(); ++offset) {
        const unsigned char byte = static_cast<unsigned char>(phrase[offset]);
        if (byte == static_cast<unsigned char>(' ')) {
            if (offset == start) {
                throw Error("wordlist phrase must use exactly one ASCII space between words");
            }
            words.emplace_back(phrase.substr(start, offset - start));
            start = offset + 1U;
        } else if (byte <= 0x20U || byte == 0x7fU) {
            throw Error("wordlist phrase contains ASCII whitespace or a control byte");
        }
    }
    if (start == phrase.size()) {
        throw Error("wordlist phrase may not end with a space");
    }
    words.emplace_back(phrase.substr(start));
    return words;
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
    const bool meets_first_rfc_profile =
        parameters.argon2_memory_kib >= 2097152U &&
        parameters.argon2_iterations >= 1U &&
        parameters.argon2_parallelism >= 4U;
    const bool meets_second_rfc_profile =
        parameters.argon2_memory_kib >= 65536U &&
        parameters.argon2_iterations >= 3U &&
        parameters.argon2_parallelism >= 4U;
    if (!meets_first_rfc_profile && !meets_second_rfc_profile) {
        std::cerr <<
            "Warning: selected Argon2id costs meet neither named RFC 9106 "
            "profiles (2 GiB/t=1/p=4 and 64 MiB/t=3/p=4). The explicit values "
            "are accepted, but may be test-grade; calibrate for the target "
            "machine and threat model.\n";
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
    const Bytes salt = decode_hex(options.required("--salt-hex"), 2048U);
    if (salt.size() < 16U || salt.size() > 1024U) {
        throw Error("public salt must contain between 16 and 1024 bytes");
    }
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

[[nodiscard]] std::vector<std::size_t> sample_word_indices(
    const std::vector<MouseEvent>& events,
    const std::size_t word_count,
    const std::size_t wordlist_size) {
    if (wordlist_size < 2U ||
        wordlist_size > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
        throw Error("wordlist size is outside the unbiased sampler range");
    }
    const std::uint64_t modulus = static_cast<std::uint64_t>(wordlist_size);
    const std::uint64_t rejection_floor = (UINT64_C(0) - modulus) % modulus;
    std::vector<std::size_t> output;
    output.reserve(word_count);
    std::uint64_t batch = 0U;
    while (output.size() < word_count) {
        const std::size_t remaining = word_count - output.size();
        const std::size_t values_to_request = remaining + 16U;
        if (values_to_request > std::numeric_limits<std::size_t>::max() / 8U) {
            throw Error("word count is too large");
        }
        const std::string purpose =
            "ArborKDF/masterkey/wordlist/v1/batch/" + std::to_string(batch);
        Bytes random = condition_random(events, purpose, values_to_request * 8U);
        for (std::size_t offset = 0U;
             offset + 8U <= random.size() && output.size() < word_count;
             offset += 8U) {
            const std::uint64_t candidate = load_u64(random, offset);
            if (candidate >= rejection_floor) {
                output.push_back(static_cast<std::size_t>(candidate % modulus));
            }
        }
        secure_clear(random);
        if (batch == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("unbiased word sampler counter exhausted");
        }
        ++batch;
    }
    return output;
}

void print_entropy_summary(const std::vector<MouseEvent>& events) {
    const EntropyReport report = analyze_mouse_events(events);
    std::cerr << '\n' << format_entropy_report(report);
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
        const std::vector<MouseEvent> events = collect_mouse_events();
        print_entropy_summary(events);
        std::vector<std::size_t> indices =
            sample_word_indices(events, words, wordlist.size());
        const SensitiveIndicesGuard indices_guard(indices);
        const long double entropy = master_phrase_entropy_bits(words, wordlist.size());
        std::cerr << "Master phrase ideal code-space entropy: " <<
            static_cast<double>(entropy) << " bits (" << words << " * log2(" <<
            wordlist.size() << "))\n";
        const long double security_ceiling = std::min(entropy, 256.0L);
        std::cerr << "Generator security-strength ceiling: " <<
            static_cast<double>(security_ceiling) <<
            " classical bits (SHAKE256 ceiling; mouse credit is 0)\n";
        std::cerr << "Conservative generic quantum-search exponent: at most " <<
            static_cast<double>(security_ceiling / 2.0L) <<
            " bits; this is not a certification\n";
        std::string phrase = format_master_phrase_indices(indices, wordlist);
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
    const std::vector<MouseEvent> events = collect_mouse_events();
    print_entropy_summary(events);
    Bytes secret = condition_random(events, "ArborKDF/masterkey/bytes/v1", bits / 8U);
    const SensitiveBytesGuard secret_guard(secret);
    std::string encoded = encoding == "hex" ? encode_hex(secret) : encode_base64(secret);
    const SensitiveStringGuard encoded_guard(encoded);
    const std::size_t security_ceiling = std::min(bits, std::size_t{256U});
    std::cerr << "Generated master code-space size: " << bits << " bits\n";
    std::cerr << "Generator security-strength ceiling: " << security_ceiling <<
        " classical bits (SHAKE256 ceiling; mouse credit is 0)\n";
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
    const std::vector<MouseEvent> events = collect_mouse_events();
    print_entropy_summary(events);
    Bytes salt = condition_random(events, "ArborKDF/salt/v1", bits / 8U);
    const SensitiveBytesGuard salt_guard(salt);
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
        throw Error("unknown or incomplete command; run arborkdf --help");
    } catch (const std::exception& exception) {
        std::cerr << "error: " << exception.what() << '\n';
        return 2;
    }
}

}  // namespace arborkdf
