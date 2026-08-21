#include "arborkdf/wordlist.hpp"

#include "arborkdf/generated/bip39_english_wordlist.hpp"

#include "arborkdf/codec.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace arborkdf {
namespace {

constexpr std::string_view kMasterPhraseFrameTag =
    "ArborKDF/master-phrase/v1";
constexpr std::size_t kMaximumWordlistBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaximumWordCount = 1024U * 1024U;
constexpr std::size_t kMaximumWordBytes = 1024U;
constexpr std::size_t kMaximumSupportedBitsPerWord = 20U;

std::string location(const std::string& source_name,
                     const std::size_t line_number) {
    std::ostringstream output;
    output << source_name << ':' << line_number;
    return output.str();
}

bool contains_utf8_bom(const std::string_view text) noexcept {
    constexpr std::string_view bom = "\xef\xbb\xbf";
    return text.find(bom) != std::string_view::npos;
}

bool is_forbidden_ascii_word_byte(const unsigned char byte) noexcept {
    return byte <= 0x20U || byte == 0x7fU;
}

bool contains_c1_control(const std::string_view text) noexcept {
    for (std::size_t offset = 0U; (offset + 1U) < text.size(); ++offset) {
        const auto first = static_cast<unsigned char>(text[offset]);
        const auto second = static_cast<unsigned char>(text[offset + 1U]);
        if (first == 0xc2U && second >= 0x80U && second <= 0x9fU) {
            return true;
        }
    }
    return false;
}

void validate_word(const std::string_view word, const std::string& source_name,
                   const std::size_t line_number) {
    const std::string where = location(source_name, line_number);
    if (word.empty()) {
        throw WordlistError(where + ": blank word is not allowed");
    }
    if (word.size() > kMaximumWordBytes) {
        throw WordlistError(where + ": word exceeds the 1024-byte limit");
    }
    if (!is_valid_utf8(word)) {
        throw WordlistError(where + ": word is not valid UTF-8");
    }
    if (contains_utf8_bom(word)) {
        throw WordlistError(where + ": UTF-8 BOM (U+FEFF) is not allowed");
    }
    if (contains_c1_control(word)) {
        throw WordlistError(where + ": Unicode control characters are not allowed");
    }
    for (const char character : word) {
        const auto byte = static_cast<unsigned char>(character);
        if (is_forbidden_ascii_word_byte(byte)) {
            throw WordlistError(
                where +
                ": words may not contain ASCII whitespace or control bytes");
        }
    }
}

std::optional<std::size_t> exact_log2(const std::size_t value) noexcept {
    if (value < 2U || (value & (value - 1U)) != 0U) {
        return std::nullopt;
    }

    std::size_t exponent = 0U;
    std::size_t remaining = value;
    while (remaining > 1U) {
        remaining >>= 1U;
        ++exponent;
    }
    return exponent;
}

std::vector<std::size_t> positive_divisors(const std::size_t value) {
    std::vector<std::size_t> divisors;
    if (value == 0U) {
        return divisors;
    }

    for (std::size_t candidate = 1U;
         candidate <= (value / candidate); ++candidate) {
        if ((value % candidate) == 0U) {
            divisors.push_back(candidate);
            const std::size_t paired = value / candidate;
            if (paired != candidate) {
                divisors.push_back(paired);
            }
        }
    }
    std::sort(divisors.begin(), divisors.end());
    return divisors;
}

std::string power_of_two_decimal(const std::size_t exponent) {
    std::string decimal = "1";
    for (std::size_t iteration = 0U; iteration < exponent; ++iteration) {
        unsigned int carry = 0U;
        for (auto position = decimal.rbegin(); position != decimal.rend();
             ++position) {
            const unsigned int digit =
                static_cast<unsigned int>(*position - '0');
            const unsigned int doubled = (digit * 2U) + carry;
            *position = static_cast<char>('0' + (doubled % 10U));
            carry = doubled / 10U;
        }
        if (carry != 0U) {
            decimal.insert(decimal.begin(), static_cast<char>('0' + carry));
        }
    }
    return decimal;
}

bool power_of_two_is_less_than(const std::size_t exponent,
                               const std::size_t value) noexcept {
    constexpr std::size_t digits =
        std::numeric_limits<std::size_t>::digits;
    if (exponent >= digits) {
        return false;
    }
    return (std::size_t{1U} << exponent) < value;
}

bool power_of_two_is_greater_than(const std::size_t exponent,
                                  const std::size_t value) noexcept {
    constexpr std::size_t digits =
        std::numeric_limits<std::size_t>::digits;
    if (exponent >= digits) {
        return true;
    }
    return (std::size_t{1U} << exponent) > value;
}

WordlistSizeSuggestion make_size_suggestion(const std::size_t exponent) {
    return WordlistSizeSuggestion{exponent, power_of_two_decimal(exponent)};
}

void add_size_suggestions(WordlistBitsCompatibility& diagnostic) {
    if (diagnostic.input_bits == 0U) {
        for (std::size_t exponent = 1U;
             exponent <= kMaximumSupportedBitsPerWord; ++exponent) {
            if (power_of_two_is_less_than(exponent,
                                          diagnostic.wordlist_size)) {
                diagnostic.closest_lower_wordlist_size =
                    make_size_suggestion(exponent);
            } else if (power_of_two_is_greater_than(
                           exponent, diagnostic.wordlist_size)) {
                diagnostic.closest_upper_wordlist_size =
                    make_size_suggestion(exponent);
                return;
            }
        }
        return;
    }

    const std::vector<std::size_t> divisors =
        positive_divisors(diagnostic.input_bits);
    for (const std::size_t exponent : divisors) {
        if (exponent > kMaximumSupportedBitsPerWord) {
            break;
        }
        if (power_of_two_is_less_than(exponent,
                                      diagnostic.wordlist_size)) {
            diagnostic.closest_lower_wordlist_size =
                make_size_suggestion(exponent);
        } else if (power_of_two_is_greater_than(
                       exponent, diagnostic.wordlist_size)) {
            diagnostic.closest_upper_wordlist_size =
                make_size_suggestion(exponent);
            return;
        }
    }
}

void add_input_size_suggestions(WordlistBitsCompatibility& diagnostic,
                                const std::size_t bits_per_word) {
    const std::size_t divisor = std::gcd(bits_per_word, std::size_t{8U});
    const std::size_t period = (bits_per_word / divisor) * 8U;
    const std::size_t remainder = diagnostic.input_bits % period;

    if (remainder == 0U) {
        if (diagnostic.input_bits >= period) {
            diagnostic.closest_lower_byte_aligned_input_bits =
                diagnostic.input_bits - period;
        }
        if (diagnostic.input_bits <=
            (std::numeric_limits<std::size_t>::max() - period)) {
            diagnostic.closest_upper_byte_aligned_input_bits =
                diagnostic.input_bits + period;
        }
        return;
    }

    diagnostic.closest_lower_byte_aligned_input_bits =
        diagnostic.input_bits - remainder;
    const std::size_t increment = period - remainder;
    if (diagnostic.input_bits <=
        (std::numeric_limits<std::size_t>::max() - increment)) {
        diagnostic.closest_upper_byte_aligned_input_bits =
            diagnostic.input_bits + increment;
    }
}

std::string suggestion_text(const WordlistSizeSuggestion& suggestion) {
    std::ostringstream output;
    output << suggestion.wordlist_size_decimal << " (2^"
           << suggestion.bits_per_word << ')';
    return output.str();
}

void finish_diagnostic_message(WordlistBitsCompatibility& diagnostic) {
    std::ostringstream output;
    output << "wordlist-bits-v1 cannot encode " << diagnostic.input_bits
           << " bits with a " << diagnostic.wordlist_size
           << "-entry wordlist: " << diagnostic.reason
           << ". It refuses to discard or pad any bit.";

    if (diagnostic.input_bits != 0U) {
        output << " Compatible wordlist sizes are 2^d where d is a positive "
                  "divisor of "
               << diagnostic.input_bits << '.';
    } else {
        output << " For an empty input, any power-of-two wordlist size is "
                  "bit-compatible.";
    }

    if (diagnostic.closest_lower_wordlist_size.has_value()) {
        output << " Closest lower compatible wordlist size: "
               << suggestion_text(
                      *diagnostic.closest_lower_wordlist_size)
               << '.';
    } else {
        output << " No smaller compatible wordlist size exists.";
    }
    if (diagnostic.closest_upper_wordlist_size.has_value()) {
        output << " Closest upper compatible wordlist size: "
               << suggestion_text(
                      *diagnostic.closest_upper_wordlist_size)
               << '.';
    } else {
        output << " No larger compatible wordlist size exists within the "
                  "supported 1,048,576-entry limit.";
    }

    if (diagnostic.bits_per_word.has_value()) {
        output << " This wordlist uses " << *diagnostic.bits_per_word
               << " bits per word and would leave "
               << diagnostic.trailing_bits << " trailing bit";
        if (diagnostic.trailing_bits != 1U) {
            output << 's';
        }
        output << '.';
        if (diagnostic.closest_lower_byte_aligned_input_bits.has_value()) {
            output << " Closest lower compatible byte-aligned input: "
                   << *diagnostic.closest_lower_byte_aligned_input_bits
                   << " bits.";
        }
        if (diagnostic.closest_upper_byte_aligned_input_bits.has_value()) {
            output << " Closest upper compatible byte-aligned input: "
                   << *diagnostic.closest_upper_byte_aligned_input_bits
                   << " bits.";
        }
    }
    diagnostic.message = output.str();
}

std::size_t checked_bit_length(const Bytes& input) {
    if (input.size() > (std::numeric_limits<std::size_t>::max() / 8U)) {
        throw WordlistError("input is too large to express its bit length");
    }
    return input.size() * 8U;
}

std::vector<std::size_t> words_to_indices(
    const std::vector<std::string>& words, const Wordlist& wordlist) {
    std::vector<std::size_t> indices;
    indices.reserve(words.size());
    for (std::size_t position = 0U; position < words.size(); ++position) {
        const std::string& word = words[position];
        const std::optional<std::size_t> index = wordlist.find_index(word);
        if (!index.has_value()) {
            throw WordlistError("word at position " +
                                std::to_string(position + 1U) +
                                " is not present in " +
                                wordlist.source_name());
        }
        indices.push_back(*index);
    }
    return indices;
}

std::vector<std::string> split_master_phrase(const std::string_view phrase) {
    if (phrase.empty()) {
        throw WordlistError("master phrase must contain at least one word");
    }
    if (!is_valid_utf8(phrase)) {
        throw WordlistError("master phrase is not valid UTF-8");
    }

    std::vector<std::string> words;
    std::size_t start = 0U;
    for (std::size_t offset = 0U; offset < phrase.size(); ++offset) {
        const auto byte = static_cast<unsigned char>(phrase[offset]);
        if (byte == static_cast<unsigned char>(' ')) {
            if (offset == start) {
                throw WordlistError(
                    "master phrase must use one ASCII space between words");
            }
            words.emplace_back(phrase.substr(start, offset - start));
            start = offset + 1U;
        } else if (is_forbidden_ascii_word_byte(byte)) {
            throw WordlistError(
                "master phrase may contain only word bytes and single ASCII "
                "space separators");
        }
    }
    if (start == phrase.size()) {
        throw WordlistError("master phrase may not end with a space");
    }
    words.emplace_back(phrase.substr(start));
    return words;
}

std::uint64_t size_as_u64(const std::size_t value,
                          const std::string_view field_name) {
    if constexpr (std::numeric_limits<std::size_t>::digits > 64) {
        if (value > static_cast<std::size_t>(
                        std::numeric_limits<std::uint64_t>::max())) {
            throw WordlistError(std::string(field_name) +
                                " does not fit the v1 u64 frame field");
        }
    }
    return static_cast<std::uint64_t>(value);
}

void append_tag(Bytes& frame) {
    frame.reserve(frame.size() + kMasterPhraseFrameTag.size());
    for (const char character : kMasterPhraseFrameTag) {
        frame.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(character)));
    }
}

bool frame_has_tag(const Bytes& frame) noexcept {
    if (frame.size() < kMasterPhraseFrameTag.size()) {
        return false;
    }
    for (std::size_t offset = 0U; offset < kMasterPhraseFrameTag.size();
         ++offset) {
        const std::uint8_t expected = static_cast<std::uint8_t>(
            static_cast<unsigned char>(kMasterPhraseFrameTag[offset]));
        if (frame[offset] != expected) {
            return false;
        }
    }
    return true;
}

}  // namespace

Wordlist::Wordlist(std::vector<std::string> words, std::string source_name)
    : words_(std::move(words)), source_name_(std::move(source_name)) {
    indices_.reserve(words_.size());
    for (std::size_t index = 0U; index < words_.size(); ++index) {
        indices_.emplace(words_[index], index);
    }
}

Wordlist Wordlist::from_source(const std::string& source) {
    const std::string_view source_view(source);
    if (source_view == generated::kBip39EnglishSelector) {
        std::vector<std::string> words;
        words.reserve(generated::kBip39EnglishWords.size());
        for (const std::string_view word : generated::kBip39EnglishWords) {
            words.emplace_back(word);
        }
        return Wordlist(std::move(words), source);
    }
    constexpr std::string_view kEmbeddedPrefix{"embedded_"};
    if (source_view.substr(0U, kEmbeddedPrefix.size()) == kEmbeddedPrefix) {
        throw WordlistError("unknown embedded wordlist selector: " + source +
                            "; available selector: embedded_bip39");
    }
    return from_file(source);
}

Wordlist Wordlist::from_file(const std::string& path) {
    std::ifstream input(std::filesystem::u8path(path), std::ios::binary);
    if (!input) {
        throw WordlistError("cannot open wordlist file: " + path);
    }

    std::string contents;
    std::array<char, 16384U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count < 0) {
            throw WordlistError("failed while reading wordlist file: " + path);
        }
        const std::size_t amount = static_cast<std::size_t>(count);
        if (amount > kMaximumWordlistBytes - contents.size()) {
            throw WordlistError("wordlist file exceeds the 64 MiB limit: " + path);
        }
        contents.append(buffer.data(), amount);
    }
    if (!input.eof()) {
        throw WordlistError("failed while reading wordlist file: " + path);
    }
    return parse(contents, path);
}

Wordlist Wordlist::parse(const std::string_view contents,
                         std::string source_name) {
    if (contents.size() > kMaximumWordlistBytes) {
        throw WordlistError(source_name + ": wordlist exceeds the 64 MiB limit");
    }
    if (!is_valid_utf8(contents)) {
        throw WordlistError(source_name + ": file is not valid UTF-8");
    }
    if (contains_utf8_bom(contents)) {
        throw WordlistError(source_name +
                            ": UTF-8 BOM (U+FEFF) is not allowed");
    }

    std::vector<std::string> words;
    std::unordered_set<std::string> seen;
    std::size_t start = 0U;
    std::size_t line_number = 1U;

    while (start < contents.size()) {
        const std::size_t newline = contents.find('\n', start);
        const std::size_t end =
            (newline == std::string_view::npos) ? contents.size() : newline;
        std::string_view word = contents.substr(start, end - start);
        if (!word.empty() && word.back() == '\r') {
            word.remove_suffix(1U);
        }
        validate_word(word, source_name, line_number);

        std::string owned_word(word);
        if (!seen.emplace(owned_word).second) {
            throw WordlistError(location(source_name, line_number) +
                                ": duplicate word: " + owned_word);
        }
        words.push_back(std::move(owned_word));
        if (words.size() > kMaximumWordCount) {
            throw WordlistError(source_name +
                                ": wordlist exceeds the 1,048,576-entry limit");
        }

        if (newline == std::string_view::npos) {
            break;
        }
        start = newline + 1U;
        ++line_number;
    }

    return from_words(std::move(words), std::move(source_name));
}

Wordlist Wordlist::from_words(std::vector<std::string> words,
                              std::string source_name) {
    if (words.size() < 2U) {
        throw WordlistError(source_name +
                            ": wordlist must contain at least two words");
    }
    if (words.size() > kMaximumWordCount) {
        throw WordlistError(source_name +
                            ": wordlist exceeds the 1,048,576-entry limit");
    }

    std::unordered_set<std::string> seen;
    seen.reserve(words.size());
    for (std::size_t index = 0U; index < words.size(); ++index) {
        validate_word(words[index], source_name, index + 1U);
        if (!seen.emplace(words[index]).second) {
            throw WordlistError(location(source_name, index + 1U) +
                                ": duplicate word: " + words[index]);
        }
    }
    return Wordlist(std::move(words), std::move(source_name));
}

std::size_t Wordlist::size() const noexcept { return words_.size(); }

const std::string& Wordlist::at(const std::size_t index) const {
    if (index >= words_.size()) {
        throw WordlistError("wordlist index is out of range");
    }
    return words_[index];
}

std::optional<std::size_t> Wordlist::find_index(
    const std::string_view word) const {
    const auto found = indices_.find(std::string(word));
    if (found == indices_.end()) {
        return std::nullopt;
    }
    return found->second;
}

const std::string& Wordlist::source_name() const noexcept {
    return source_name_;
}

WordlistCodecError::WordlistCodecError(
    WordlistBitsCompatibility diagnostic)
    : WordlistError(diagnostic.message), diagnostic_(std::move(diagnostic)) {}

const WordlistBitsCompatibility& WordlistCodecError::diagnostic() const
    noexcept {
    return diagnostic_;
}

WordlistBitsCompatibility analyze_wordlist_bits_compatibility(
    const std::size_t input_bits, const std::size_t wordlist_size) {
    WordlistBitsCompatibility diagnostic;
    diagnostic.input_bits = input_bits;
    diagnostic.wordlist_size = wordlist_size;

    const std::optional<std::size_t> bits_per_word =
        exact_log2(wordlist_size);
    diagnostic.bits_per_word = bits_per_word;

    if (wordlist_size < 2U) {
        diagnostic.reason = "the wordlist must contain at least two entries";
    } else if (!bits_per_word.has_value()) {
        diagnostic.reason =
            "the wordlist size is not a power of two, so fixed-width word "
            "indices cannot cover it exactly";
    } else {
        diagnostic.trailing_bits = input_bits % *bits_per_word;
        if (diagnostic.trailing_bits == 0U) {
            diagnostic.compatible = true;
            return diagnostic;
        }
        std::ostringstream reason;
        reason << input_bits << " is not divisible by " << *bits_per_word
               << " bits per word (remainder "
               << diagnostic.trailing_bits << ')';
        diagnostic.reason = reason.str();
        add_input_size_suggestions(diagnostic, *bits_per_word);
    }

    add_size_suggestions(diagnostic);
    finish_diagnostic_message(diagnostic);
    return diagnostic;
}

std::vector<std::string> encode_wordlist_bits_v1(
    const Bytes& input, const Wordlist& wordlist) {
    const std::size_t input_bits = checked_bit_length(input);
    const WordlistBitsCompatibility diagnostic =
        analyze_wordlist_bits_compatibility(input_bits, wordlist.size());
    if (!diagnostic.compatible) {
        throw WordlistCodecError(diagnostic);
    }

    const std::size_t bits_per_word = *diagnostic.bits_per_word;
    const std::size_t word_count = input_bits / bits_per_word;
    std::vector<std::string> encoded;
    encoded.reserve(word_count);

    for (std::size_t word_offset = 0U; word_offset < word_count;
         ++word_offset) {
        std::size_t index = 0U;
        for (std::size_t bit = 0U; bit < bits_per_word; ++bit) {
            const std::size_t absolute_bit =
                (word_offset * bits_per_word) + bit;
            const std::size_t byte_offset = absolute_bit / 8U;
            const std::size_t bit_in_byte = absolute_bit % 8U;
            const std::uint8_t value = static_cast<std::uint8_t>(
                (input[byte_offset] >> (7U - bit_in_byte)) & UINT8_C(1));
            index = (index << 1U) | static_cast<std::size_t>(value);
        }
        encoded.push_back(wordlist.at(index));
    }
    return encoded;
}

Bytes decode_wordlist_bits_v1(const std::vector<std::string>& words,
                              const Wordlist& wordlist) {
    const std::optional<std::size_t> bits_per_word =
        exact_log2(wordlist.size());
    if (!bits_per_word.has_value()) {
        const WordlistBitsCompatibility diagnostic =
            analyze_wordlist_bits_compatibility(0U, wordlist.size());
        throw WordlistCodecError(diagnostic);
    }
    if (words.size() >
        (std::numeric_limits<std::size_t>::max() / *bits_per_word)) {
        throw WordlistError("word sequence is too large to decode");
    }

    const std::size_t total_bits = words.size() * *bits_per_word;
    if ((total_bits % 8U) != 0U) {
        WordlistBitsCompatibility diagnostic =
            analyze_wordlist_bits_compatibility(total_bits, wordlist.size());
        diagnostic.compatible = false;
        diagnostic.reason =
            "the decoded word indices do not form a whole number of bytes";
        diagnostic.trailing_bits = total_bits % 8U;
        diagnostic.message =
            "wordlist-bits-v1 decoded " + std::to_string(total_bits) +
            " bits, which is not byte-aligned; it refuses to discard or pad "
            "the trailing " + std::to_string(total_bits % 8U) + " bits";
        throw WordlistCodecError(std::move(diagnostic));
    }

    const std::vector<std::size_t> indices =
        words_to_indices(words, wordlist);
    Bytes decoded(total_bits / 8U, UINT8_C(0));
    for (std::size_t word_offset = 0U; word_offset < indices.size();
         ++word_offset) {
        const std::size_t index = indices[word_offset];
        for (std::size_t bit = 0U; bit < *bits_per_word; ++bit) {
            const std::size_t source_shift = *bits_per_word - bit - 1U;
            const std::uint8_t value = static_cast<std::uint8_t>(
                (index >> source_shift) & std::size_t{1U});
            const std::size_t absolute_bit =
                (word_offset * *bits_per_word) + bit;
            const std::size_t byte_offset = absolute_bit / 8U;
            const std::size_t bit_in_byte = absolute_bit % 8U;
            decoded[byte_offset] = static_cast<std::uint8_t>(
                decoded[byte_offset] |
                static_cast<std::uint8_t>(value << (7U - bit_in_byte)));
        }
    }
    return decoded;
}

std::string join_words(const std::vector<std::string>& words) {
    std::size_t size = 0U;
    for (const std::string& word : words) {
        if (size > (std::numeric_limits<std::size_t>::max() - word.size())) {
            throw WordlistError("word sequence is too large to join");
        }
        size += word.size();
    }
    if (!words.empty()) {
        const std::size_t separators = words.size() - 1U;
        if (size >
            (std::numeric_limits<std::size_t>::max() - separators)) {
            throw WordlistError("word sequence is too large to join");
        }
        size += separators;
    }

    std::string phrase;
    phrase.reserve(size);
    for (std::size_t index = 0U; index < words.size(); ++index) {
        if (index != 0U) {
            phrase.push_back(' ');
        }
        phrase += words[index];
    }
    return phrase;
}

std::vector<std::size_t> parse_master_phrase_indices(
    const std::string_view phrase, const Wordlist& wordlist) {
    return words_to_indices(split_master_phrase(phrase), wordlist);
}

std::string format_master_phrase_indices(
    const std::vector<std::size_t>& indices, const Wordlist& wordlist) {
    if (indices.empty()) {
        throw WordlistError("master phrase must contain at least one word");
    }

    std::vector<std::string> words;
    words.reserve(indices.size());
    for (const std::size_t index : indices) {
        words.push_back(wordlist.at(index));
    }
    return join_words(words);
}

Bytes frame_master_phrase_v1(const std::vector<std::size_t>& indices,
                             const Wordlist& wordlist) {
    if (indices.empty()) {
        throw WordlistError("master phrase must contain at least one word");
    }
    if (indices.size() >
        ((std::numeric_limits<std::size_t>::max() -
          kMasterPhraseFrameTag.size() - 16U) /
         8U)) {
        throw WordlistError("master phrase is too large to frame");
    }

    Bytes frame;
    frame.reserve(kMasterPhraseFrameTag.size() + 16U +
                  (indices.size() * 8U));
    append_tag(frame);
    append_u64_be(frame, size_as_u64(wordlist.size(), "wordlist size"));
    append_u64_be(frame, size_as_u64(indices.size(), "word count"));
    for (const std::size_t index : indices) {
        if (index >= wordlist.size()) {
            throw WordlistError("master phrase word index is out of range");
        }
        append_u64_be(frame, size_as_u64(index, "word index"));
    }
    return frame;
}

Bytes frame_master_phrase_v1(const std::string_view phrase,
                             const Wordlist& wordlist) {
    return frame_master_phrase_v1(
        parse_master_phrase_indices(phrase, wordlist), wordlist);
}

std::vector<std::size_t> unframe_master_phrase_v1(
    const Bytes& frame, const Wordlist& wordlist) {
    const std::size_t header_size = kMasterPhraseFrameTag.size() + 16U;
    if (frame.size() < header_size || !frame_has_tag(frame)) {
        throw WordlistError("master phrase frame has an invalid v1 tag");
    }

    const std::size_t size_offset = kMasterPhraseFrameTag.size();
    const std::uint64_t framed_wordlist_size =
        load_u64_be(frame, size_offset);
    if (framed_wordlist_size !=
        size_as_u64(wordlist.size(), "wordlist size")) {
        throw WordlistError(
            "master phrase frame wordlist size does not match the supplied "
            "wordlist");
    }

    const std::uint64_t framed_count =
        load_u64_be(frame, size_offset + 8U);
    if (framed_count == 0U) {
        throw WordlistError("master phrase frame contains zero words");
    }
    if (framed_count > static_cast<std::uint64_t>(
                           std::numeric_limits<std::size_t>::max())) {
        throw WordlistError("master phrase frame word count is too large");
    }
    const std::size_t count = static_cast<std::size_t>(framed_count);
    if (count >
        ((std::numeric_limits<std::size_t>::max() - header_size) / 8U)) {
        throw WordlistError("master phrase frame word count overflows size");
    }
    const std::size_t expected_size = header_size + (count * 8U);
    if (frame.size() != expected_size) {
        throw WordlistError(
            "master phrase frame length does not match its word count");
    }

    std::vector<std::size_t> indices;
    indices.reserve(count);
    for (std::size_t offset = 0U; offset < count; ++offset) {
        const std::uint64_t framed_index =
            load_u64_be(frame, header_size + (offset * 8U));
        if (framed_index >= framed_wordlist_size) {
            throw WordlistError(
                "master phrase frame contains an out-of-range word index");
        }
        if (framed_index > static_cast<std::uint64_t>(
                               std::numeric_limits<std::size_t>::max())) {
            throw WordlistError(
                "master phrase frame word index is too large for this "
                "platform");
        }
        indices.push_back(static_cast<std::size_t>(framed_index));
    }
    return indices;
}

long double master_phrase_entropy_bits(const std::size_t word_count,
                                       const std::size_t wordlist_size) {
    if (wordlist_size < 2U) {
        throw WordlistError(
            "entropy requires a wordlist with at least two entries");
    }
    return static_cast<long double>(word_count) *
           std::log2(static_cast<long double>(wordlist_size));
}

}  // namespace arborkdf
