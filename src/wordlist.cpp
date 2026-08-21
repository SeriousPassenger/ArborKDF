#include "arborkdf/wordlist.hpp"

#include "arborkdf/generated/bip39_english_wordlist.hpp"
#include "arborkdf/generated/en_tr_jp_131072_wordlist.hpp"

#include "arborkdf/codec.hpp"

#include <openssl/crypto.h>

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
constexpr std::string_view kBip39EnglishSha512 =
    "416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8b"
    "aed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123";
constexpr std::size_t kBip39EnglishCanonicalBytes = 13116U;

struct EmbeddedWordlistRecord final {
    EmbeddedWordlistMetadata metadata;
    const std::string_view* words = nullptr;
    std::size_t words_size = 0U;
    const std::string_view* canonical_chunks = nullptr;
    std::size_t canonical_chunks_size = 0U;
};

const std::vector<EmbeddedWordlistRecord>& embedded_wordlist_records() {
    static const std::vector<EmbeddedWordlistRecord> records{
        EmbeddedWordlistRecord{
            EmbeddedWordlistMetadata{
                generated::kBip39EnglishSelector,
                "BIP-39 English vocabulary",
                "bip39-english-vocabulary",
                "en",
                generated::kBip39EnglishWords.size(),
                11U,
                88U,
                kBip39EnglishCanonicalBytes,
                kBip39EnglishSha512,
                {EmbeddedWordlistCount{"en", 2048U}},
                {}},
            generated::kBip39EnglishWords.data(),
            generated::kBip39EnglishWords.size(),
            nullptr,
            0U},
        EmbeddedWordlistRecord{
            EmbeddedWordlistMetadata{
                generated::kEnTrJp131072Selector,
                "ArborKDF English/Turkish/Japanese 131072 v1",
                "ArborKDF-en-tr-jp-131072-v1",
                "en,tr,ja",
                generated::kEnTrJp131072WordCount,
                17U,
                136U,
                generated::kEnTrJp131072CanonicalBytes,
                generated::kEnTrJp131072Sha512,
                {EmbeddedWordlistCount{
                     "en", generated::kEnTrJp131072EnglishCount},
                 EmbeddedWordlistCount{
                     "tr", generated::kEnTrJp131072TurkishCount},
                 EmbeddedWordlistCount{
                     "ja", generated::kEnTrJp131072JapaneseCount}},
                {EmbeddedWordlistCount{
                     "en&tr", generated::kEnTrJp131072EnglishTurkishOverlap},
                 EmbeddedWordlistCount{
                     "en&ja", generated::kEnTrJp131072EnglishJapaneseOverlap},
                 EmbeddedWordlistCount{
                     "tr&ja", generated::kEnTrJp131072TurkishJapaneseOverlap},
                 EmbeddedWordlistCount{
                     "en&tr&ja",
                     generated::kEnTrJp131072EnglishTurkishJapaneseOverlap}}},
            nullptr,
            0U,
            generated::kEnTrJp131072Chunks.data(),
            generated::kEnTrJp131072Chunks.size()}};
    return records;
}

const EmbeddedWordlistRecord* find_embedded_wordlist_record(
    const std::string_view selector) {
    const auto& records = embedded_wordlist_records();
    const auto found = std::find_if(
        records.begin(), records.end(),
        [selector](const EmbeddedWordlistRecord& record) {
            return record.metadata.selector == selector;
        });
    return found == records.end() ? nullptr : &*found;
}

std::string available_embedded_selector_text() {
    std::string result;
    const auto& records = embedded_wordlist_records();
    for (std::size_t index = 0U; index < records.size(); ++index) {
        if (index != 0U) {
            result.append(", ");
        }
        result.append(records[index].metadata.selector);
    }
    return result;
}

std::string canonical_text_from_record(
    const EmbeddedWordlistRecord& record) {
    std::string result;
    result.reserve(record.metadata.canonical_text_bytes);
    if (record.canonical_chunks != nullptr) {
        for (std::size_t index = 0U;
             index < record.canonical_chunks_size; ++index) {
            result.append(record.canonical_chunks[index]);
        }
    } else {
        for (std::size_t index = 0U; index < record.words_size; ++index) {
            result.append(record.words[index]);
            result.push_back('\n');
        }
    }
    if (result.size() != record.metadata.canonical_text_bytes) {
        throw WordlistError(
            "internal embedded wordlist canonical byte count mismatch");
    }
    return result;
}

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

struct CodePointRange final {
    std::uint32_t first;
    std::uint32_t last;
};

template <std::size_t Size>
bool code_point_in_ranges(
    const std::uint32_t code_point,
    const std::array<CodePointRange, Size>& ranges) noexcept {
    std::size_t lower = 0U;
    std::size_t upper = ranges.size();
    while (lower < upper) {
        const std::size_t middle = lower + ((upper - lower) / 2U);
        if (code_point < ranges[middle].first) {
            upper = middle;
        } else if (code_point > ranges[middle].last) {
            lower = middle + 1U;
        } else {
            return true;
        }
    }
    return false;
}

std::uint32_t decode_valid_utf8_code_point(
    const std::string_view text, std::size_t& offset) noexcept {
    const auto first = static_cast<std::uint8_t>(text[offset]);
    if (first <= UINT8_C(0x7f)) {
        ++offset;
        return first;
    }

    std::size_t length = 0U;
    std::uint32_t code_point = 0U;
    if (first <= UINT8_C(0xdf)) {
        length = 2U;
        code_point = static_cast<std::uint32_t>(first & UINT8_C(0x1f));
    } else if (first <= UINT8_C(0xef)) {
        length = 3U;
        code_point = static_cast<std::uint32_t>(first & UINT8_C(0x0f));
    } else {
        length = 4U;
        code_point = static_cast<std::uint32_t>(first & UINT8_C(0x07));
    }
    for (std::size_t index = 1U; index < length; ++index) {
        const auto continuation =
            static_cast<std::uint8_t>(text[offset + index]);
        code_point = (code_point << 6U) |
                     static_cast<std::uint32_t>(continuation & UINT8_C(0x3f));
    }
    offset += length;
    return code_point;
}

bool is_unicode_control_or_format(const std::uint32_t code_point) noexcept {
    // Unicode 16.0 General_Category Cc and Cf ranges. This covers C0/C1,
    // directional overrides/isolates, zero-width format characters, tags, and
    // interlinear annotations. Variation selectors are rejected as marks below.
    static constexpr std::array<CodePointRange, 23U> ranges{{
        {UINT32_C(0x0000), UINT32_C(0x001f)},
        {UINT32_C(0x007f), UINT32_C(0x009f)},
        {UINT32_C(0x00ad), UINT32_C(0x00ad)},
        {UINT32_C(0x0600), UINT32_C(0x0605)},
        {UINT32_C(0x061c), UINT32_C(0x061c)},
        {UINT32_C(0x06dd), UINT32_C(0x06dd)},
        {UINT32_C(0x070f), UINT32_C(0x070f)},
        {UINT32_C(0x0890), UINT32_C(0x0891)},
        {UINT32_C(0x08e2), UINT32_C(0x08e2)},
        {UINT32_C(0x180e), UINT32_C(0x180e)},
        {UINT32_C(0x200b), UINT32_C(0x200f)},
        {UINT32_C(0x202a), UINT32_C(0x202e)},
        {UINT32_C(0x2060), UINT32_C(0x2064)},
        {UINT32_C(0x2066), UINT32_C(0x206f)},
        {UINT32_C(0xfeff), UINT32_C(0xfeff)},
        {UINT32_C(0xfff9), UINT32_C(0xfffb)},
        {UINT32_C(0x110bd), UINT32_C(0x110bd)},
        {UINT32_C(0x110cd), UINT32_C(0x110cd)},
        {UINT32_C(0x13430), UINT32_C(0x1343f)},
        {UINT32_C(0x1bca0), UINT32_C(0x1bca3)},
        {UINT32_C(0x1d173), UINT32_C(0x1d17a)},
        {UINT32_C(0xe0001), UINT32_C(0xe0001)},
        {UINT32_C(0xe0020), UINT32_C(0xe007f)},
    }};
    return code_point_in_ranges(code_point, ranges);
}

bool is_unicode_separator(const std::uint32_t code_point) noexcept {
    return code_point == UINT32_C(0x00a0) ||
           code_point == UINT32_C(0x1680) ||
           (code_point >= UINT32_C(0x2000) &&
            code_point <= UINT32_C(0x200a)) ||
           (code_point >= UINT32_C(0x2028) &&
            code_point <= UINT32_C(0x2029)) ||
           code_point == UINT32_C(0x202f) ||
           code_point == UINT32_C(0x205f) ||
           code_point == UINT32_C(0x3000);
}

bool is_unicode_noncharacter(const std::uint32_t code_point) noexcept {
    return (code_point >= UINT32_C(0xfdd0) &&
            code_point <= UINT32_C(0xfdef)) ||
           (code_point & UINT32_C(0xfffe)) == UINT32_C(0xfffe);
}

bool is_unicode_combining_mark(const std::uint32_t code_point) noexcept {
    // Unicode 16.0 General_Category Mn, Mc, and Me ranges. Rejecting
    // marks enforces the custom-list policy without pretending that this
    // implementation can normalize arbitrary Unicode safely.
    static constexpr std::array<CodePointRange, 321U> ranges{{
        {UINT32_C(0x0300), UINT32_C(0x036f)},
        {UINT32_C(0x0483), UINT32_C(0x0489)},
        {UINT32_C(0x0591), UINT32_C(0x05bd)},
        {UINT32_C(0x05bf), UINT32_C(0x05bf)},
        {UINT32_C(0x05c1), UINT32_C(0x05c2)},
        {UINT32_C(0x05c4), UINT32_C(0x05c5)},
        {UINT32_C(0x05c7), UINT32_C(0x05c7)},
        {UINT32_C(0x0610), UINT32_C(0x061a)},
        {UINT32_C(0x064b), UINT32_C(0x065f)},
        {UINT32_C(0x0670), UINT32_C(0x0670)},
        {UINT32_C(0x06d6), UINT32_C(0x06dc)},
        {UINT32_C(0x06df), UINT32_C(0x06e4)},
        {UINT32_C(0x06e7), UINT32_C(0x06e8)},
        {UINT32_C(0x06ea), UINT32_C(0x06ed)},
        {UINT32_C(0x0711), UINT32_C(0x0711)},
        {UINT32_C(0x0730), UINT32_C(0x074a)},
        {UINT32_C(0x07a6), UINT32_C(0x07b0)},
        {UINT32_C(0x07eb), UINT32_C(0x07f3)},
        {UINT32_C(0x07fd), UINT32_C(0x07fd)},
        {UINT32_C(0x0816), UINT32_C(0x0819)},
        {UINT32_C(0x081b), UINT32_C(0x0823)},
        {UINT32_C(0x0825), UINT32_C(0x0827)},
        {UINT32_C(0x0829), UINT32_C(0x082d)},
        {UINT32_C(0x0859), UINT32_C(0x085b)},
        {UINT32_C(0x0897), UINT32_C(0x089f)},
        {UINT32_C(0x08ca), UINT32_C(0x08e1)},
        {UINT32_C(0x08e3), UINT32_C(0x0903)},
        {UINT32_C(0x093a), UINT32_C(0x093c)},
        {UINT32_C(0x093e), UINT32_C(0x094f)},
        {UINT32_C(0x0951), UINT32_C(0x0957)},
        {UINT32_C(0x0962), UINT32_C(0x0963)},
        {UINT32_C(0x0981), UINT32_C(0x0983)},
        {UINT32_C(0x09bc), UINT32_C(0x09bc)},
        {UINT32_C(0x09be), UINT32_C(0x09c4)},
        {UINT32_C(0x09c7), UINT32_C(0x09c8)},
        {UINT32_C(0x09cb), UINT32_C(0x09cd)},
        {UINT32_C(0x09d7), UINT32_C(0x09d7)},
        {UINT32_C(0x09e2), UINT32_C(0x09e3)},
        {UINT32_C(0x09fe), UINT32_C(0x09fe)},
        {UINT32_C(0x0a01), UINT32_C(0x0a03)},
        {UINT32_C(0x0a3c), UINT32_C(0x0a3c)},
        {UINT32_C(0x0a3e), UINT32_C(0x0a42)},
        {UINT32_C(0x0a47), UINT32_C(0x0a48)},
        {UINT32_C(0x0a4b), UINT32_C(0x0a4d)},
        {UINT32_C(0x0a51), UINT32_C(0x0a51)},
        {UINT32_C(0x0a70), UINT32_C(0x0a71)},
        {UINT32_C(0x0a75), UINT32_C(0x0a75)},
        {UINT32_C(0x0a81), UINT32_C(0x0a83)},
        {UINT32_C(0x0abc), UINT32_C(0x0abc)},
        {UINT32_C(0x0abe), UINT32_C(0x0ac5)},
        {UINT32_C(0x0ac7), UINT32_C(0x0ac9)},
        {UINT32_C(0x0acb), UINT32_C(0x0acd)},
        {UINT32_C(0x0ae2), UINT32_C(0x0ae3)},
        {UINT32_C(0x0afa), UINT32_C(0x0aff)},
        {UINT32_C(0x0b01), UINT32_C(0x0b03)},
        {UINT32_C(0x0b3c), UINT32_C(0x0b3c)},
        {UINT32_C(0x0b3e), UINT32_C(0x0b44)},
        {UINT32_C(0x0b47), UINT32_C(0x0b48)},
        {UINT32_C(0x0b4b), UINT32_C(0x0b4d)},
        {UINT32_C(0x0b55), UINT32_C(0x0b57)},
        {UINT32_C(0x0b62), UINT32_C(0x0b63)},
        {UINT32_C(0x0b82), UINT32_C(0x0b82)},
        {UINT32_C(0x0bbe), UINT32_C(0x0bc2)},
        {UINT32_C(0x0bc6), UINT32_C(0x0bc8)},
        {UINT32_C(0x0bca), UINT32_C(0x0bcd)},
        {UINT32_C(0x0bd7), UINT32_C(0x0bd7)},
        {UINT32_C(0x0c00), UINT32_C(0x0c04)},
        {UINT32_C(0x0c3c), UINT32_C(0x0c3c)},
        {UINT32_C(0x0c3e), UINT32_C(0x0c44)},
        {UINT32_C(0x0c46), UINT32_C(0x0c48)},
        {UINT32_C(0x0c4a), UINT32_C(0x0c4d)},
        {UINT32_C(0x0c55), UINT32_C(0x0c56)},
        {UINT32_C(0x0c62), UINT32_C(0x0c63)},
        {UINT32_C(0x0c81), UINT32_C(0x0c83)},
        {UINT32_C(0x0cbc), UINT32_C(0x0cbc)},
        {UINT32_C(0x0cbe), UINT32_C(0x0cc4)},
        {UINT32_C(0x0cc6), UINT32_C(0x0cc8)},
        {UINT32_C(0x0cca), UINT32_C(0x0ccd)},
        {UINT32_C(0x0cd5), UINT32_C(0x0cd6)},
        {UINT32_C(0x0ce2), UINT32_C(0x0ce3)},
        {UINT32_C(0x0cf3), UINT32_C(0x0cf3)},
        {UINT32_C(0x0d00), UINT32_C(0x0d03)},
        {UINT32_C(0x0d3b), UINT32_C(0x0d3c)},
        {UINT32_C(0x0d3e), UINT32_C(0x0d44)},
        {UINT32_C(0x0d46), UINT32_C(0x0d48)},
        {UINT32_C(0x0d4a), UINT32_C(0x0d4d)},
        {UINT32_C(0x0d57), UINT32_C(0x0d57)},
        {UINT32_C(0x0d62), UINT32_C(0x0d63)},
        {UINT32_C(0x0d81), UINT32_C(0x0d83)},
        {UINT32_C(0x0dca), UINT32_C(0x0dca)},
        {UINT32_C(0x0dcf), UINT32_C(0x0dd4)},
        {UINT32_C(0x0dd6), UINT32_C(0x0dd6)},
        {UINT32_C(0x0dd8), UINT32_C(0x0ddf)},
        {UINT32_C(0x0df2), UINT32_C(0x0df3)},
        {UINT32_C(0x0e31), UINT32_C(0x0e31)},
        {UINT32_C(0x0e34), UINT32_C(0x0e3a)},
        {UINT32_C(0x0e47), UINT32_C(0x0e4e)},
        {UINT32_C(0x0eb1), UINT32_C(0x0eb1)},
        {UINT32_C(0x0eb4), UINT32_C(0x0ebc)},
        {UINT32_C(0x0ec8), UINT32_C(0x0ece)},
        {UINT32_C(0x0f18), UINT32_C(0x0f19)},
        {UINT32_C(0x0f35), UINT32_C(0x0f35)},
        {UINT32_C(0x0f37), UINT32_C(0x0f37)},
        {UINT32_C(0x0f39), UINT32_C(0x0f39)},
        {UINT32_C(0x0f3e), UINT32_C(0x0f3f)},
        {UINT32_C(0x0f71), UINT32_C(0x0f84)},
        {UINT32_C(0x0f86), UINT32_C(0x0f87)},
        {UINT32_C(0x0f8d), UINT32_C(0x0f97)},
        {UINT32_C(0x0f99), UINT32_C(0x0fbc)},
        {UINT32_C(0x0fc6), UINT32_C(0x0fc6)},
        {UINT32_C(0x102b), UINT32_C(0x103e)},
        {UINT32_C(0x1056), UINT32_C(0x1059)},
        {UINT32_C(0x105e), UINT32_C(0x1060)},
        {UINT32_C(0x1062), UINT32_C(0x1064)},
        {UINT32_C(0x1067), UINT32_C(0x106d)},
        {UINT32_C(0x1071), UINT32_C(0x1074)},
        {UINT32_C(0x1082), UINT32_C(0x108d)},
        {UINT32_C(0x108f), UINT32_C(0x108f)},
        {UINT32_C(0x109a), UINT32_C(0x109d)},
        {UINT32_C(0x135d), UINT32_C(0x135f)},
        {UINT32_C(0x1712), UINT32_C(0x1715)},
        {UINT32_C(0x1732), UINT32_C(0x1734)},
        {UINT32_C(0x1752), UINT32_C(0x1753)},
        {UINT32_C(0x1772), UINT32_C(0x1773)},
        {UINT32_C(0x17b4), UINT32_C(0x17d3)},
        {UINT32_C(0x17dd), UINT32_C(0x17dd)},
        {UINT32_C(0x180b), UINT32_C(0x180d)},
        {UINT32_C(0x180f), UINT32_C(0x180f)},
        {UINT32_C(0x1885), UINT32_C(0x1886)},
        {UINT32_C(0x18a9), UINT32_C(0x18a9)},
        {UINT32_C(0x1920), UINT32_C(0x192b)},
        {UINT32_C(0x1930), UINT32_C(0x193b)},
        {UINT32_C(0x1a17), UINT32_C(0x1a1b)},
        {UINT32_C(0x1a55), UINT32_C(0x1a5e)},
        {UINT32_C(0x1a60), UINT32_C(0x1a7c)},
        {UINT32_C(0x1a7f), UINT32_C(0x1a7f)},
        {UINT32_C(0x1ab0), UINT32_C(0x1ace)},
        {UINT32_C(0x1b00), UINT32_C(0x1b04)},
        {UINT32_C(0x1b34), UINT32_C(0x1b44)},
        {UINT32_C(0x1b6b), UINT32_C(0x1b73)},
        {UINT32_C(0x1b80), UINT32_C(0x1b82)},
        {UINT32_C(0x1ba1), UINT32_C(0x1bad)},
        {UINT32_C(0x1be6), UINT32_C(0x1bf3)},
        {UINT32_C(0x1c24), UINT32_C(0x1c37)},
        {UINT32_C(0x1cd0), UINT32_C(0x1cd2)},
        {UINT32_C(0x1cd4), UINT32_C(0x1ce8)},
        {UINT32_C(0x1ced), UINT32_C(0x1ced)},
        {UINT32_C(0x1cf4), UINT32_C(0x1cf4)},
        {UINT32_C(0x1cf7), UINT32_C(0x1cf9)},
        {UINT32_C(0x1dc0), UINT32_C(0x1dff)},
        {UINT32_C(0x20d0), UINT32_C(0x20f0)},
        {UINT32_C(0x2cef), UINT32_C(0x2cf1)},
        {UINT32_C(0x2d7f), UINT32_C(0x2d7f)},
        {UINT32_C(0x2de0), UINT32_C(0x2dff)},
        {UINT32_C(0x302a), UINT32_C(0x302f)},
        {UINT32_C(0x3099), UINT32_C(0x309a)},
        {UINT32_C(0xa66f), UINT32_C(0xa672)},
        {UINT32_C(0xa674), UINT32_C(0xa67d)},
        {UINT32_C(0xa69e), UINT32_C(0xa69f)},
        {UINT32_C(0xa6f0), UINT32_C(0xa6f1)},
        {UINT32_C(0xa802), UINT32_C(0xa802)},
        {UINT32_C(0xa806), UINT32_C(0xa806)},
        {UINT32_C(0xa80b), UINT32_C(0xa80b)},
        {UINT32_C(0xa823), UINT32_C(0xa827)},
        {UINT32_C(0xa82c), UINT32_C(0xa82c)},
        {UINT32_C(0xa880), UINT32_C(0xa881)},
        {UINT32_C(0xa8b4), UINT32_C(0xa8c5)},
        {UINT32_C(0xa8e0), UINT32_C(0xa8f1)},
        {UINT32_C(0xa8ff), UINT32_C(0xa8ff)},
        {UINT32_C(0xa926), UINT32_C(0xa92d)},
        {UINT32_C(0xa947), UINT32_C(0xa953)},
        {UINT32_C(0xa980), UINT32_C(0xa983)},
        {UINT32_C(0xa9b3), UINT32_C(0xa9c0)},
        {UINT32_C(0xa9e5), UINT32_C(0xa9e5)},
        {UINT32_C(0xaa29), UINT32_C(0xaa36)},
        {UINT32_C(0xaa43), UINT32_C(0xaa43)},
        {UINT32_C(0xaa4c), UINT32_C(0xaa4d)},
        {UINT32_C(0xaa7b), UINT32_C(0xaa7d)},
        {UINT32_C(0xaab0), UINT32_C(0xaab0)},
        {UINT32_C(0xaab2), UINT32_C(0xaab4)},
        {UINT32_C(0xaab7), UINT32_C(0xaab8)},
        {UINT32_C(0xaabe), UINT32_C(0xaabf)},
        {UINT32_C(0xaac1), UINT32_C(0xaac1)},
        {UINT32_C(0xaaeb), UINT32_C(0xaaef)},
        {UINT32_C(0xaaf5), UINT32_C(0xaaf6)},
        {UINT32_C(0xabe3), UINT32_C(0xabea)},
        {UINT32_C(0xabec), UINT32_C(0xabed)},
        {UINT32_C(0xfb1e), UINT32_C(0xfb1e)},
        {UINT32_C(0xfe00), UINT32_C(0xfe0f)},
        {UINT32_C(0xfe20), UINT32_C(0xfe2f)},
        {UINT32_C(0x101fd), UINT32_C(0x101fd)},
        {UINT32_C(0x102e0), UINT32_C(0x102e0)},
        {UINT32_C(0x10376), UINT32_C(0x1037a)},
        {UINT32_C(0x10a01), UINT32_C(0x10a03)},
        {UINT32_C(0x10a05), UINT32_C(0x10a06)},
        {UINT32_C(0x10a0c), UINT32_C(0x10a0f)},
        {UINT32_C(0x10a38), UINT32_C(0x10a3a)},
        {UINT32_C(0x10a3f), UINT32_C(0x10a3f)},
        {UINT32_C(0x10ae5), UINT32_C(0x10ae6)},
        {UINT32_C(0x10d24), UINT32_C(0x10d27)},
        {UINT32_C(0x10d69), UINT32_C(0x10d6d)},
        {UINT32_C(0x10eab), UINT32_C(0x10eac)},
        {UINT32_C(0x10efc), UINT32_C(0x10eff)},
        {UINT32_C(0x10f46), UINT32_C(0x10f50)},
        {UINT32_C(0x10f82), UINT32_C(0x10f85)},
        {UINT32_C(0x11000), UINT32_C(0x11002)},
        {UINT32_C(0x11038), UINT32_C(0x11046)},
        {UINT32_C(0x11070), UINT32_C(0x11070)},
        {UINT32_C(0x11073), UINT32_C(0x11074)},
        {UINT32_C(0x1107f), UINT32_C(0x11082)},
        {UINT32_C(0x110b0), UINT32_C(0x110ba)},
        {UINT32_C(0x110c2), UINT32_C(0x110c2)},
        {UINT32_C(0x11100), UINT32_C(0x11102)},
        {UINT32_C(0x11127), UINT32_C(0x11134)},
        {UINT32_C(0x11145), UINT32_C(0x11146)},
        {UINT32_C(0x11173), UINT32_C(0x11173)},
        {UINT32_C(0x11180), UINT32_C(0x11182)},
        {UINT32_C(0x111b3), UINT32_C(0x111c0)},
        {UINT32_C(0x111c9), UINT32_C(0x111cc)},
        {UINT32_C(0x111ce), UINT32_C(0x111cf)},
        {UINT32_C(0x1122c), UINT32_C(0x11237)},
        {UINT32_C(0x1123e), UINT32_C(0x1123e)},
        {UINT32_C(0x11241), UINT32_C(0x11241)},
        {UINT32_C(0x112df), UINT32_C(0x112ea)},
        {UINT32_C(0x11300), UINT32_C(0x11303)},
        {UINT32_C(0x1133b), UINT32_C(0x1133c)},
        {UINT32_C(0x1133e), UINT32_C(0x11344)},
        {UINT32_C(0x11347), UINT32_C(0x11348)},
        {UINT32_C(0x1134b), UINT32_C(0x1134d)},
        {UINT32_C(0x11357), UINT32_C(0x11357)},
        {UINT32_C(0x11362), UINT32_C(0x11363)},
        {UINT32_C(0x11366), UINT32_C(0x1136c)},
        {UINT32_C(0x11370), UINT32_C(0x11374)},
        {UINT32_C(0x113b8), UINT32_C(0x113c0)},
        {UINT32_C(0x113c2), UINT32_C(0x113c2)},
        {UINT32_C(0x113c5), UINT32_C(0x113c5)},
        {UINT32_C(0x113c7), UINT32_C(0x113ca)},
        {UINT32_C(0x113cc), UINT32_C(0x113d0)},
        {UINT32_C(0x113d2), UINT32_C(0x113d2)},
        {UINT32_C(0x113e1), UINT32_C(0x113e2)},
        {UINT32_C(0x11435), UINT32_C(0x11446)},
        {UINT32_C(0x1145e), UINT32_C(0x1145e)},
        {UINT32_C(0x114b0), UINT32_C(0x114c3)},
        {UINT32_C(0x115af), UINT32_C(0x115b5)},
        {UINT32_C(0x115b8), UINT32_C(0x115c0)},
        {UINT32_C(0x115dc), UINT32_C(0x115dd)},
        {UINT32_C(0x11630), UINT32_C(0x11640)},
        {UINT32_C(0x116ab), UINT32_C(0x116b7)},
        {UINT32_C(0x1171d), UINT32_C(0x1172b)},
        {UINT32_C(0x1182c), UINT32_C(0x1183a)},
        {UINT32_C(0x11930), UINT32_C(0x11935)},
        {UINT32_C(0x11937), UINT32_C(0x11938)},
        {UINT32_C(0x1193b), UINT32_C(0x1193e)},
        {UINT32_C(0x11940), UINT32_C(0x11940)},
        {UINT32_C(0x11942), UINT32_C(0x11943)},
        {UINT32_C(0x119d1), UINT32_C(0x119d7)},
        {UINT32_C(0x119da), UINT32_C(0x119e0)},
        {UINT32_C(0x119e4), UINT32_C(0x119e4)},
        {UINT32_C(0x11a01), UINT32_C(0x11a0a)},
        {UINT32_C(0x11a33), UINT32_C(0x11a39)},
        {UINT32_C(0x11a3b), UINT32_C(0x11a3e)},
        {UINT32_C(0x11a47), UINT32_C(0x11a47)},
        {UINT32_C(0x11a51), UINT32_C(0x11a5b)},
        {UINT32_C(0x11a8a), UINT32_C(0x11a99)},
        {UINT32_C(0x11c2f), UINT32_C(0x11c36)},
        {UINT32_C(0x11c38), UINT32_C(0x11c3f)},
        {UINT32_C(0x11c92), UINT32_C(0x11ca7)},
        {UINT32_C(0x11ca9), UINT32_C(0x11cb6)},
        {UINT32_C(0x11d31), UINT32_C(0x11d36)},
        {UINT32_C(0x11d3a), UINT32_C(0x11d3a)},
        {UINT32_C(0x11d3c), UINT32_C(0x11d3d)},
        {UINT32_C(0x11d3f), UINT32_C(0x11d45)},
        {UINT32_C(0x11d47), UINT32_C(0x11d47)},
        {UINT32_C(0x11d8a), UINT32_C(0x11d8e)},
        {UINT32_C(0x11d90), UINT32_C(0x11d91)},
        {UINT32_C(0x11d93), UINT32_C(0x11d97)},
        {UINT32_C(0x11ef3), UINT32_C(0x11ef6)},
        {UINT32_C(0x11f00), UINT32_C(0x11f01)},
        {UINT32_C(0x11f03), UINT32_C(0x11f03)},
        {UINT32_C(0x11f34), UINT32_C(0x11f3a)},
        {UINT32_C(0x11f3e), UINT32_C(0x11f42)},
        {UINT32_C(0x11f5a), UINT32_C(0x11f5a)},
        {UINT32_C(0x13440), UINT32_C(0x13440)},
        {UINT32_C(0x13447), UINT32_C(0x13455)},
        {UINT32_C(0x1611e), UINT32_C(0x1612f)},
        {UINT32_C(0x16af0), UINT32_C(0x16af4)},
        {UINT32_C(0x16b30), UINT32_C(0x16b36)},
        {UINT32_C(0x16f4f), UINT32_C(0x16f4f)},
        {UINT32_C(0x16f51), UINT32_C(0x16f87)},
        {UINT32_C(0x16f8f), UINT32_C(0x16f92)},
        {UINT32_C(0x16fe4), UINT32_C(0x16fe4)},
        {UINT32_C(0x16ff0), UINT32_C(0x16ff1)},
        {UINT32_C(0x1bc9d), UINT32_C(0x1bc9e)},
        {UINT32_C(0x1cf00), UINT32_C(0x1cf2d)},
        {UINT32_C(0x1cf30), UINT32_C(0x1cf46)},
        {UINT32_C(0x1d165), UINT32_C(0x1d169)},
        {UINT32_C(0x1d16d), UINT32_C(0x1d172)},
        {UINT32_C(0x1d17b), UINT32_C(0x1d182)},
        {UINT32_C(0x1d185), UINT32_C(0x1d18b)},
        {UINT32_C(0x1d1aa), UINT32_C(0x1d1ad)},
        {UINT32_C(0x1d242), UINT32_C(0x1d244)},
        {UINT32_C(0x1da00), UINT32_C(0x1da36)},
        {UINT32_C(0x1da3b), UINT32_C(0x1da6c)},
        {UINT32_C(0x1da75), UINT32_C(0x1da75)},
        {UINT32_C(0x1da84), UINT32_C(0x1da84)},
        {UINT32_C(0x1da9b), UINT32_C(0x1da9f)},
        {UINT32_C(0x1daa1), UINT32_C(0x1daaf)},
        {UINT32_C(0x1e000), UINT32_C(0x1e006)},
        {UINT32_C(0x1e008), UINT32_C(0x1e018)},
        {UINT32_C(0x1e01b), UINT32_C(0x1e021)},
        {UINT32_C(0x1e023), UINT32_C(0x1e024)},
        {UINT32_C(0x1e026), UINT32_C(0x1e02a)},
        {UINT32_C(0x1e08f), UINT32_C(0x1e08f)},
        {UINT32_C(0x1e130), UINT32_C(0x1e136)},
        {UINT32_C(0x1e2ae), UINT32_C(0x1e2ae)},
        {UINT32_C(0x1e2ec), UINT32_C(0x1e2ef)},
        {UINT32_C(0x1e4ec), UINT32_C(0x1e4ef)},
        {UINT32_C(0x1e5ee), UINT32_C(0x1e5ef)},
        {UINT32_C(0x1e8d0), UINT32_C(0x1e8d6)},
        {UINT32_C(0x1e944), UINT32_C(0x1e94a)},
        {UINT32_C(0xe0100), UINT32_C(0xe01ef)},
    }};
    return code_point_in_ranges(code_point, ranges);
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
    for (const char character : word) {
        const auto byte = static_cast<unsigned char>(character);
        if (is_forbidden_ascii_word_byte(byte)) {
            throw WordlistError(
                where +
                ": words may not contain ASCII whitespace or control bytes");
        }
    }

    std::size_t offset = 0U;
    while (offset < word.size()) {
        const std::uint32_t code_point =
            decode_valid_utf8_code_point(word, offset);
        if (is_unicode_control_or_format(code_point)) {
            throw WordlistError(
                where +
                ": Unicode control characters and format characters are not "
                "allowed");
        }
        if (is_unicode_separator(code_point)) {
            throw WordlistError(
                where + ": Unicode separator characters are not allowed");
        }
        if (is_unicode_noncharacter(code_point)) {
            throw WordlistError(where +
                                ": Unicode noncharacters are not allowed");
        }
        if (is_unicode_combining_mark(code_point)) {
            throw WordlistError(
                where +
                ": combining marks are not allowed; use exact precomposed "
                "Unicode characters");
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

class SensitiveIndicesGuard final {
  public:
    explicit SensitiveIndicesGuard(
        std::vector<std::size_t>& value) noexcept
        : value_(value) {}

    ~SensitiveIndicesGuard() {
        if (active_ && !value_.empty()) {
            OPENSSL_cleanse(value_.data(),
                            value_.size() * sizeof(value_[0]));
            value_.clear();
        }
    }

    void release() noexcept { active_ = false; }

    SensitiveIndicesGuard(const SensitiveIndicesGuard&) = delete;
    SensitiveIndicesGuard& operator=(const SensitiveIndicesGuard&) = delete;

  private:
    std::vector<std::size_t>& value_;
    bool active_ = true;
};

class SensitiveBytesGuard final {
  public:
    explicit SensitiveBytesGuard(Bytes& value) noexcept : value_(value) {}

    ~SensitiveBytesGuard() {
        if (active_ && !value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size());
            value_.clear();
        }
    }

    void release() noexcept { active_ = false; }

    SensitiveBytesGuard(const SensitiveBytesGuard&) = delete;
    SensitiveBytesGuard& operator=(const SensitiveBytesGuard&) = delete;

  private:
    Bytes& value_;
    bool active_ = true;
};

class SensitiveStringGuard final {
  public:
    explicit SensitiveStringGuard(std::string& value) noexcept
        : value_(value) {}

    ~SensitiveStringGuard() {
        if (active_ && !value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size());
            value_.clear();
        }
    }

    void release() noexcept { active_ = false; }

    SensitiveStringGuard(const SensitiveStringGuard&) = delete;
    SensitiveStringGuard& operator=(const SensitiveStringGuard&) = delete;

  private:
    std::string& value_;
    bool active_ = true;
};

class SensitiveStringsGuard final {
  public:
    explicit SensitiveStringsGuard(std::vector<std::string>& value) noexcept
        : value_(value) {}

    ~SensitiveStringsGuard() {
        if (!active_) {
            return;
        }
        for (std::string& word : value_) {
            if (!word.empty()) {
                OPENSSL_cleanse(word.data(), word.size());
                word.clear();
            }
        }
        value_.clear();
    }

    void release() noexcept { active_ = false; }

    SensitiveStringsGuard(const SensitiveStringsGuard&) = delete;
    SensitiveStringsGuard& operator=(const SensitiveStringsGuard&) = delete;

  private:
    std::vector<std::string>& value_;
    bool active_ = true;
};

template <typename Words>
std::vector<std::size_t> words_to_indices(
    const Words& words, const Wordlist& wordlist) {
    std::vector<std::size_t> indices;
    SensitiveIndicesGuard guard(indices);
    indices.reserve(words.size());
    for (std::size_t position = 0U; position < words.size(); ++position) {
        const std::string_view word(words[position]);
        const std::optional<std::size_t> index = wordlist.find_index(word);
        if (!index.has_value()) {
            throw WordlistError("word at position " +
                                std::to_string(position + 1U) +
                                " is not present in " +
                                wordlist.source_name());
        }
        indices.push_back(*index);
    }
    guard.release();
    return indices;
}

std::vector<std::string_view> split_master_phrase(
    const std::string_view phrase) {
    if (phrase.empty()) {
        throw WordlistError("master phrase must contain at least one word");
    }
    if (!is_valid_utf8(phrase)) {
        throw WordlistError("master phrase is not valid UTF-8");
    }

    // Views point directly into the caller-owned master buffer. This validates
    // the phrase grammar without making additional plaintext word copies.
    std::vector<std::string_view> words;
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
    rebuild_indices();
}

Wordlist::Wordlist(const Wordlist& other)
    : words_(other.words_), source_name_(other.source_name_) {
    rebuild_indices();
}

Wordlist& Wordlist::operator=(const Wordlist& other) {
    if (this != &other) {
        Wordlist replacement(other);
        swap(replacement);
    }
    return *this;
}

Wordlist::Wordlist(Wordlist&& other)
    : words_(std::move(other.words_)),
      source_name_(std::move(other.source_name_)) {
    // The old lookup views referred to storage now owned by this object.
    // Rebuild explicitly so correctness does not depend on container move
    // details, and leave the moved-from object with no dangling views.
    other.indices_.clear();
    rebuild_indices();
}

Wordlist& Wordlist::operator=(Wordlist&& other) {
    if (this != &other) {
        Wordlist replacement(std::move(other));
        swap(replacement);
    }
    return *this;
}

void Wordlist::rebuild_indices() {
    indices_.clear();
    indices_.reserve(words_.size());
    for (std::size_t index = 0U; index < words_.size(); ++index) {
        indices_.emplace(std::string_view(words_[index]), index);
    }
}

void Wordlist::swap(Wordlist& other) noexcept {
    words_.swap(other.words_);
    indices_.swap(other.indices_);
    source_name_.swap(other.source_name_);
}

Wordlist Wordlist::from_source(const std::string& source) {
    const std::string_view source_view(source);
    const EmbeddedWordlistRecord* const embedded =
        find_embedded_wordlist_record(source_view);
    if (embedded != nullptr) {
        if (embedded->canonical_chunks != nullptr) {
            const std::string canonical =
                canonical_text_from_record(*embedded);
            return parse(canonical, source);
        }
        std::vector<std::string> words;
        words.reserve(embedded->words_size);
        for (std::size_t index = 0U; index < embedded->words_size; ++index) {
            words.emplace_back(embedded->words[index]);
        }
        return Wordlist(std::move(words), source);
    }
    constexpr std::string_view kEmbeddedPrefix{"embedded_"};
    if (source_view.substr(0U, kEmbeddedPrefix.size()) == kEmbeddedPrefix) {
        throw WordlistError("unknown embedded wordlist selector: " + source +
                            "; available selectors: " +
                            available_embedded_selector_text());
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
    const auto found = indices_.find(word);
    if (found == indices_.end()) {
        return std::nullopt;
    }
    return found->second;
}

const std::string& Wordlist::source_name() const noexcept {
    return source_name_;
}

const std::vector<EmbeddedWordlistMetadata>& embedded_wordlist_catalog() {
    static const std::vector<EmbeddedWordlistMetadata> catalog = [] {
        std::vector<EmbeddedWordlistMetadata> result;
        const auto& records = embedded_wordlist_records();
        result.reserve(records.size());
        for (const EmbeddedWordlistRecord& record : records) {
            result.push_back(record.metadata);
        }
        return result;
    }();
    return catalog;
}

std::string canonical_embedded_wordlist_text(
    const std::string_view selector) {
    const EmbeddedWordlistRecord* const record =
        find_embedded_wordlist_record(selector);
    if (record == nullptr) {
        throw WordlistError(
            "unknown embedded wordlist selector: " + std::string(selector) +
            "; available selectors: " + available_embedded_selector_text());
    }

    return canonical_text_from_record(*record);
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
    SensitiveStringsGuard encoded_guard(encoded);
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
    encoded_guard.release();
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

    std::vector<std::size_t> indices = words_to_indices(words, wordlist);
    const SensitiveIndicesGuard indices_guard(indices);
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
    SensitiveStringGuard phrase_guard(phrase);
    phrase.reserve(size);
    for (std::size_t index = 0U; index < words.size(); ++index) {
        if (index != 0U) {
            phrase.push_back(' ');
        }
        phrase += words[index];
    }
    phrase_guard.release();
    return phrase;
}

std::string join_words(std::vector<std::string>&& words) {
    const SensitiveStringsGuard words_guard(words);
    return join_words(static_cast<const std::vector<std::string>&>(words));
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

    std::size_t phrase_size = indices.size() - 1U;
    for (const std::size_t index : indices) {
        const std::size_t word_size = wordlist.at(index).size();
        if (phrase_size >
            (std::numeric_limits<std::size_t>::max() - word_size)) {
            throw WordlistError("master phrase is too large to format");
        }
        phrase_size += word_size;
    }

    std::string phrase;
    SensitiveStringGuard phrase_guard(phrase);
    phrase.reserve(phrase_size);
    for (std::size_t position = 0U; position < indices.size(); ++position) {
        if (position != 0U) {
            phrase.push_back(' ');
        }
        phrase.append(wordlist.at(indices[position]));
    }
    phrase_guard.release();
    return phrase;
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
    SensitiveBytesGuard frame_guard(frame);
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
    frame_guard.release();
    return frame;
}

Bytes frame_master_phrase_v1(const std::string_view phrase,
                             const Wordlist& wordlist) {
    std::vector<std::size_t> indices =
        parse_master_phrase_indices(phrase, wordlist);
    const SensitiveIndicesGuard indices_guard(indices);
    return frame_master_phrase_v1(indices, wordlist);
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
    SensitiveIndicesGuard indices_guard(indices);
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
    indices_guard.release();
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
