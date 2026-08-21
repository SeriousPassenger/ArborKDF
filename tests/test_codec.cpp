#include "arborkdf/codec.hpp"
#include "arborkdf/wordlist.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class TestFailure final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

void require(const bool condition, const std::string_view description) {
    if (!condition) {
        throw TestFailure("codec test failed: " + std::string(description));
    }
}

template <typename Exception, typename Operation>
void require_throws(Operation&& operation, const std::string_view message_part) {
    try {
        std::invoke(std::forward<Operation>(operation));
    } catch (const Exception& error) {
        if (std::string_view(error.what()).find(message_part) ==
            std::string_view::npos) {
            throw TestFailure("exception did not contain expected text: " +
                              std::string(message_part) + "; got: " +
                              error.what());
        }
        return;
    } catch (const std::exception& error) {
        throw TestFailure("unexpected exception type: " +
                          std::string(error.what()));
    }
    throw TestFailure("expected exception was not thrown");
}

arborkdf::Bytes bytes_from_ascii(const std::string_view text) {
    arborkdf::Bytes bytes;
    bytes.reserve(text.size());
    for (const char character : text) {
        bytes.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(character)));
    }
    return bytes;
}

void test_hex() {
    const arborkdf::Bytes decoded = arborkdf::decode_hex("0001abcdef7f80ff");
    require(decoded.size() == 8U, "hex decoded byte count");
    require(decoded[0] == UINT8_C(0x00), "hex leading zero");
    require(decoded[3] == UINT8_C(0xcd), "hex middle byte");
    require(decoded[7] == UINT8_C(0xff), "hex final byte");
    require(arborkdf::encode_hex(decoded) == "0001abcdef7f80ff",
            "lowercase canonical hex round trip");
    require(arborkdf::decode_hex("").empty(), "empty hex input");

    require_throws<arborkdf::CodecError>(
        [] { static_cast<void>(arborkdf::decode_hex("0")); },
        "even number");
    require_throws<arborkdf::CodecError>(
        [] { static_cast<void>(arborkdf::decode_hex("0x00")); },
        "digits 0-9");
    require(arborkdf::decode_hex("AB") == arborkdf::Bytes{UINT8_C(0xab)},
            "uppercase hex accepted");
    require_throws<arborkdf::CodecError>(
        [] { static_cast<void>(arborkdf::decode_hex("gg")); },
        "digits 0-9");
    require_throws<arborkdf::CodecError>(
        [] { static_cast<void>(arborkdf::decode_hex("0011", 2U)); },
        "maximum is 2");
}

void test_base64() {
    require(arborkdf::encode_base64(bytes_from_ascii("")) == "",
            "base64 empty vector");
    require(arborkdf::encode_base64(bytes_from_ascii("f")) == "Zg==",
            "base64 one byte and double padding");
    require(arborkdf::encode_base64(bytes_from_ascii("fo")) == "Zm8=",
            "base64 two bytes and padding");
    require(arborkdf::encode_base64(bytes_from_ascii("foo")) == "Zm9v",
            "base64 three bytes");
    require(arborkdf::encode_base64(bytes_from_ascii("foob")) == "Zm9vYg==",
            "base64 four bytes");
    require(arborkdf::encode_base64(bytes_from_ascii("fooba")) == "Zm9vYmE=",
            "base64 five bytes");
    require(arborkdf::encode_base64(bytes_from_ascii("foobar")) == "Zm9vYmFy",
            "base64 six bytes");
}

void test_utf8() {
    require(arborkdf::is_valid_utf8("plain ASCII"), "valid ASCII UTF-8");
    require(arborkdf::is_valid_utf8(u8"日本語/é/😀"),
            "valid multi-byte UTF-8");
    require(arborkdf::is_valid_utf8(std::string_view("\0", 1U)),
            "NUL is structurally valid UTF-8");

    require(!arborkdf::is_valid_utf8(std::string("\xc0\x80", 2U)),
            "reject overlong two-byte UTF-8");
    require(!arborkdf::is_valid_utf8(std::string("\xed\xa0\x80", 3U)),
            "reject UTF-8 surrogate");
    require(!arborkdf::is_valid_utf8(std::string("\xf4\x90\x80\x80", 4U)),
            "reject codepoint above U+10FFFF");
    require(!arborkdf::is_valid_utf8(std::string("\xe2\x82", 2U)),
            "reject truncated UTF-8");
    require_throws<arborkdf::CodecError>(
        [] {
            arborkdf::require_valid_utf8(std::string("\xff", 1U),
                                         "master key");
        },
        "master key is not valid UTF-8");
}

void test_wordlist_validation() {
    const arborkdf::Wordlist list = arborkdf::Wordlist::parse(
        "zero\r\none\r\ntwo\r\nthree\r\n", "crlf-list");
    require(list.size() == 4U, "CRLF wordlist size");
    require(list.at(2U) == "two", "wordlist order is semantic");
    require(list.find_index("three") == std::optional<std::size_t>(3U),
            "wordlist reverse lookup");
    require(!list.find_index("missing").has_value(),
            "unknown word lookup");

    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(arborkdf::Wordlist::parse(
                std::string("\xef\xbb\xbfzero\none", 11U), "bom"));
        },
        "BOM");
    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(
                arborkdf::Wordlist::parse("zero\n\none", "blank"));
        },
        "blank word");
    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(arborkdf::Wordlist::parse(
                "zero\none word", "space"));
        },
        "whitespace or control");
    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(arborkdf::Wordlist::parse(
                std::string("zero\none\xc2\x85", 10U), "c1-control"));
        },
        "control characters");
    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(arborkdf::Wordlist::parse(
                "zero\none\nzero", "duplicate"));
        },
        "duplicate word");
    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(
                arborkdf::Wordlist::parse("only-one", "short"));
        },
        "at least two");
    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(arborkdf::Wordlist::parse(
                std::string("zero\n\xff", 6U), "invalid-utf8"));
        },
        "not valid UTF-8");
}

void test_embedded_bip39_wordlist() {
    const arborkdf::Wordlist embedded =
        arborkdf::Wordlist::from_source("embedded_bip39");
    const arborkdf::Wordlist vendored = arborkdf::Wordlist::from_source(
        "third_party/bip39/english.txt");

    require(embedded.source_name() == "embedded_bip39",
            "embedded BIP39 source name");
    require(embedded.size() == 2048U, "embedded BIP39 word count");
    require(embedded.at(0U) == "abandon", "embedded BIP39 first word");
    require(embedded.at(2047U) == "zoo", "embedded BIP39 last word");
    require(embedded.find_index("satoshi") ==
                std::optional<std::size_t>(1531U),
            "embedded BIP39 canonical middle index");
    require(!embedded.find_index("not-a-bip39-word").has_value(),
            "embedded BIP39 rejects an unknown word");

    require(vendored.size() == embedded.size(),
            "embedded and vendored BIP39 sizes match");
    for (std::size_t index = 0U; index < embedded.size(); ++index) {
        require(embedded.at(index) == vendored.at(index),
                "embedded and vendored BIP39 order match");
    }

    const arborkdf::Bytes zero_bits(11U, UINT8_C(0));
    const std::vector<std::string> encoded =
        arborkdf::encode_wordlist_bits_v1(zero_bits, embedded);
    require(encoded == std::vector<std::string>(8U, "abandon"),
            "88 zero bits encode to eight BIP39 index-zero words");
    require(arborkdf::decode_wordlist_bits_v1(encoded, embedded) == zero_bits,
            "embedded BIP39 exact codec round trip");

    require_throws<arborkdf::WordlistError>(
        [] {
            static_cast<void>(
                arborkdf::Wordlist::from_source("embedded_unknown"));
        },
        "unknown embedded wordlist selector");
}

void test_wordlist_bits_codec() {
    const arborkdf::Wordlist list =
        arborkdf::Wordlist::parse("zero\none\ntwo\nthree\n", "bits");
    const arborkdf::Bytes input{UINT8_C(0x1b)};
    const std::vector<std::string> encoded =
        arborkdf::encode_wordlist_bits_v1(input, list);
    require(encoded ==
                std::vector<std::string>{"zero", "one", "two", "three"},
            "wordlist-bits-v1 is MSB-first");
    require(arborkdf::join_words(encoded) == "zero one two three",
            "canonical word joining");
    require(arborkdf::decode_wordlist_bits_v1(encoded, list) == input,
            "wordlist-bits-v1 exact byte round trip");
    require(arborkdf::encode_wordlist_bits_v1(arborkdf::Bytes{}, list).empty(),
            "empty fixed-bit input is lossless");
    require(arborkdf::decode_wordlist_bits_v1({}, list).empty(),
            "empty fixed-bit output decodes exactly");

    require_throws<arborkdf::WordlistCodecError>(
        [&list] {
            static_cast<void>(arborkdf::decode_wordlist_bits_v1({"one"},
                                                                list));
        },
        "not byte-aligned");
    require_throws<arborkdf::WordlistError>(
        [&list] {
            static_cast<void>(arborkdf::decode_wordlist_bits_v1(
                {"zero", "one", "two", "missing"}, list));
        },
        "not present");
}

void test_compatibility_diagnostics() {
    const arborkdf::WordlistBitsCompatibility diagnostic =
        arborkdf::analyze_wordlist_bits_compatibility(256U, 2048U);
    require(!diagnostic.compatible, "256 bits and 2048 words incompatible");
    require(diagnostic.bits_per_word == std::optional<std::size_t>(11U),
            "2048 words means 11 bits per word");
    require(diagnostic.trailing_bits == 3U, "diagnostic trailing bit count");
    require(diagnostic.closest_lower_wordlist_size.has_value(),
            "lower wordlist size suggestion exists");
    require(diagnostic.closest_lower_wordlist_size->bits_per_word == 8U,
            "closest lower compatible exponent");
    require(diagnostic.closest_lower_wordlist_size->wordlist_size_decimal ==
                "256",
            "closest lower compatible size");
    require(diagnostic.closest_upper_wordlist_size.has_value(),
            "upper wordlist size suggestion exists");
    require(diagnostic.closest_upper_wordlist_size->bits_per_word == 16U,
            "closest upper compatible exponent");
    require(diagnostic.closest_upper_wordlist_size->wordlist_size_decimal ==
                "65536",
            "closest upper compatible size");
    require(diagnostic.closest_lower_byte_aligned_input_bits ==
                std::optional<std::size_t>(176U),
            "closest lower byte-aligned input size");
    require(diagnostic.closest_upper_byte_aligned_input_bits ==
                std::optional<std::size_t>(264U),
            "closest upper byte-aligned input size");
    require(diagnostic.message.find("refuses to discard or pad") !=
                std::string::npos,
            "diagnostic explains loss refusal");

    const arborkdf::WordlistBitsCompatibility non_power =
        arborkdf::analyze_wordlist_bits_compatibility(256U, 1000U);
    require(!non_power.compatible, "non-power-of-two list incompatible");
    require(!non_power.bits_per_word.has_value(),
            "non-power-of-two list has no fixed index width");
    require(non_power.closest_lower_wordlist_size->wordlist_size_decimal ==
                "256",
            "non-power list lower suggestion");
    require(non_power.closest_upper_wordlist_size->wordlist_size_decimal ==
                "65536",
            "non-power list upper suggestion");

    const arborkdf::WordlistBitsCompatibility no_upper =
        arborkdf::analyze_wordlist_bits_compatibility(8U, 65536U);
    require(!no_upper.compatible, "oversized wordlist incompatible");
    require(!no_upper.closest_upper_wordlist_size.has_value(),
            "diagnostic represents impossible upper suggestion");

    const arborkdf::WordlistBitsCompatibility capped_upper =
        arborkdf::analyze_wordlist_bits_compatibility(256U, 1048576U);
    require(!capped_upper.compatible,
            "maximum supported list can still be bit-incompatible");
    require(capped_upper.closest_lower_wordlist_size.has_value() &&
                capped_upper.closest_lower_wordlist_size->wordlist_size_decimal ==
                    "65536",
            "supported lower suggestion is retained");
    require(!capped_upper.closest_upper_wordlist_size.has_value(),
            "unsupported mathematical upper suggestion is omitted");
    require(capped_upper.message.find("supported 1,048,576-entry limit") !=
                std::string::npos,
            "diagnostic explains why no supported upper suggestion exists");
}

void test_master_phrase_framing() {
    const arborkdf::Wordlist list =
        arborkdf::Wordlist::parse("cedar\noak\npine\n", "three-words");
    const std::vector<std::size_t> indices =
        arborkdf::parse_master_phrase_indices("pine cedar oak", list);
    require(indices == std::vector<std::size_t>{2U, 0U, 1U},
            "arbitrary-N phrase indices");
    require(arborkdf::format_master_phrase_indices(indices, list) ==
                "pine cedar oak",
            "canonical phrase formatting");

    const arborkdf::Bytes frame =
        arborkdf::frame_master_phrase_v1(indices, list);
    require(arborkdf::unframe_master_phrase_v1(frame, list) == indices,
            "arbitrary-N u64 phrase frame round trip");
    require(arborkdf::frame_master_phrase_v1("pine cedar oak", list) ==
                frame,
            "text and index phrase frames are identical");

    const long double entropy =
        arborkdf::master_phrase_entropy_bits(10U, 2048U);
    require(std::fabs(entropy - 110.0L) < 1.0e-12L,
            "master phrase entropy W*log2(N)");

    require_throws<arborkdf::WordlistError>(
        [&list] {
            static_cast<void>(
                arborkdf::parse_master_phrase_indices(" pine", list));
        },
        "one ASCII space");
    require_throws<arborkdf::WordlistError>(
        [&list] {
            static_cast<void>(arborkdf::parse_master_phrase_indices(
                "pine  oak", list));
        },
        "one ASCII space");
    require_throws<arborkdf::WordlistError>(
        [&list] {
            static_cast<void>(arborkdf::parse_master_phrase_indices(
                "pine\toak", list));
        },
        "single ASCII space");
    require_throws<arborkdf::WordlistError>(
        [&list] {
            static_cast<void>(
                arborkdf::parse_master_phrase_indices("pine ash", list));
        },
        "not present");

    arborkdf::Bytes malformed = frame;
    malformed.push_back(UINT8_C(0));
    require_throws<arborkdf::WordlistError>(
        [&list, &malformed] {
            static_cast<void>(
                arborkdf::unframe_master_phrase_v1(malformed, list));
        },
        "length does not match");
}

}  // namespace

void run_codec_tests() {
    test_hex();
    test_base64();
    test_utf8();
    test_wordlist_validation();
    test_embedded_bip39_wordlist();
    test_wordlist_bits_codec();
    test_compatibility_diagnostics();
    test_master_phrase_framing();
}
