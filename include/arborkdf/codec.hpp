#pragma once

#include "arborkdf/bytes.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace arborkdf {

inline constexpr std::size_t kDefaultMaximumHexCharacters = 1024U;

class CodecError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

Bytes decode_hex(
    std::string_view encoded,
    std::size_t maximum_characters = kDefaultMaximumHexCharacters);

std::string encode_hex(const Bytes& bytes);

std::string encode_base64(const Bytes& bytes);

bool is_valid_utf8(std::string_view text) noexcept;

void require_valid_utf8(std::string_view text,
                        std::string_view field_name = "text");

}  // namespace arborkdf
