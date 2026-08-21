#pragma once

#include "arborkdf/bytes.hpp"

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace arborkdf {

class WordlistError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class Wordlist final {
  public:
    Wordlist(const Wordlist& other);
    Wordlist& operator=(const Wordlist& other);
    Wordlist(Wordlist&& other);
    Wordlist& operator=(Wordlist&& other);

    static Wordlist from_source(const std::string& source);
    static Wordlist from_file(const std::string& path);
    static Wordlist parse(std::string_view contents,
                          std::string source_name = "<memory>");
    static Wordlist from_words(std::vector<std::string> words,
                               std::string source_name = "<words>");

    std::size_t size() const noexcept;
    const std::string& at(std::size_t index) const;
    std::optional<std::size_t> find_index(std::string_view word) const;
    const std::string& source_name() const noexcept;

  private:
    Wordlist(std::vector<std::string> words, std::string source_name);
    void rebuild_indices();
    void swap(Wordlist& other) noexcept;

    std::vector<std::string> words_;
    // Every key is a non-owning view into words_. Wordlist is immutable after
    // construction, and the explicit copy/move operations rebuild or transfer
    // the lookup together with its backing storage.
    std::unordered_map<std::string_view, std::size_t> indices_;
    std::string source_name_;
};

struct EmbeddedWordlistCount final {
    std::string_view label;
    std::size_t count = 0U;
};

struct EmbeddedWordlistMetadata final {
    std::string_view selector;
    std::string_view display_name;
    std::string_view standard_id;
    std::string_view languages;
    std::size_t word_count = 0U;
    std::size_t bits_per_word = 0U;
    std::size_t byte_aligned_block_bits = 0U;
    std::size_t canonical_text_bytes = 0U;
    std::string_view sha512_hex;
    std::vector<EmbeddedWordlistCount> language_memberships;
    std::vector<EmbeddedWordlistCount> exact_overlaps;
};

const std::vector<EmbeddedWordlistMetadata>& embedded_wordlist_catalog();

std::string canonical_embedded_wordlist_text(std::string_view selector);

struct WordlistSizeSuggestion final {
    std::size_t bits_per_word = 0U;
    std::string wordlist_size_decimal;
};

struct WordlistBitsCompatibility final {
    bool compatible = false;
    std::size_t input_bits = 0U;
    std::size_t wordlist_size = 0U;
    std::optional<std::size_t> bits_per_word;
    std::size_t trailing_bits = 0U;
    std::optional<WordlistSizeSuggestion> closest_lower_wordlist_size;
    std::optional<WordlistSizeSuggestion> closest_upper_wordlist_size;
    std::optional<std::size_t> closest_lower_byte_aligned_input_bits;
    std::optional<std::size_t> closest_upper_byte_aligned_input_bits;
    std::string reason;
    std::string message;
};

class WordlistCodecError final : public WordlistError {
  public:
    explicit WordlistCodecError(WordlistBitsCompatibility diagnostic);

    const WordlistBitsCompatibility& diagnostic() const noexcept;

  private:
    WordlistBitsCompatibility diagnostic_;
};

WordlistBitsCompatibility analyze_wordlist_bits_compatibility(
    std::size_t input_bits, std::size_t wordlist_size);

std::vector<std::string> encode_wordlist_bits_v1(const Bytes& input,
                                                  const Wordlist& wordlist);

Bytes decode_wordlist_bits_v1(const std::vector<std::string>& words,
                              const Wordlist& wordlist);

std::string join_words(const std::vector<std::string>& words);
// Cleanses the owned word copies after joining them. Prefer this overload for
// encoded secret material.
std::string join_words(std::vector<std::string>&& words);

std::vector<std::size_t> parse_master_phrase_indices(
    std::string_view phrase, const Wordlist& wordlist);

std::string format_master_phrase_indices(
    const std::vector<std::size_t>& indices, const Wordlist& wordlist);

Bytes frame_master_phrase_v1(const std::vector<std::size_t>& indices,
                             const Wordlist& wordlist);

Bytes frame_master_phrase_v1(std::string_view phrase,
                             const Wordlist& wordlist);

std::vector<std::size_t> unframe_master_phrase_v1(
    const Bytes& frame, const Wordlist& wordlist);

long double master_phrase_entropy_bits(std::size_t word_count,
                                       std::size_t wordlist_size);

}  // namespace arborkdf
