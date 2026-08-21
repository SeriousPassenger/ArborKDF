#include "arborkdf/codec.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <sstream>

namespace arborkdf {
namespace {

std::uint8_t decode_hex_digit(const char character) {
    if (character >= '0' && character <= '9') {
        return static_cast<std::uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return static_cast<std::uint8_t>(10 + (character - 'a'));
    }
    if (character >= 'A' && character <= 'F') {
        return static_cast<std::uint8_t>(10 + (character - 'A'));
    }
    throw CodecError(
        "hex input must contain only digits 0-9, a-f, or A-F");
}

std::uint8_t decode_base64_digit(const char character) {
    if (character >= 'A' && character <= 'Z') {
        return static_cast<std::uint8_t>(character - 'A');
    }
    if (character >= 'a' && character <= 'z') {
        return static_cast<std::uint8_t>(26 + (character - 'a'));
    }
    if (character >= '0' && character <= '9') {
        return static_cast<std::uint8_t>(52 + (character - '0'));
    }
    if (character == '+') {
        return UINT8_C(62);
    }
    if (character == '/') {
        return UINT8_C(63);
    }
    throw CodecError(
        "base64 input must use only the RFC 4648 standard alphabet and "
        "canonical '=' padding");
}

bool is_continuation(const std::uint8_t byte) noexcept {
    return byte >= UINT8_C(0x80) && byte <= UINT8_C(0xbf);
}

}  // namespace

Bytes decode_hex(const std::string_view encoded,
                 const std::size_t maximum_characters) {
    if (encoded.size() > maximum_characters) {
        std::ostringstream message;
        message << "hex input is " << encoded.size()
                << " characters; maximum is " << maximum_characters;
        throw CodecError(message.str());
    }
    if ((encoded.size() % 2U) != 0U) {
        throw CodecError(
            "hex input must contain an even number of characters (whole bytes)");
    }

    // Validate before allocating the decoded buffer. In particular, callers
    // that treat the result as sensitive never leave a partially decoded
    // prefix behind after malformed input.
    for (const char character : encoded) {
        static_cast<void>(decode_hex_digit(character));
    }

    Bytes decoded;
    decoded.reserve(encoded.size() / 2U);
    for (std::size_t offset = 0U; offset < encoded.size(); offset += 2U) {
        const std::uint8_t high = decode_hex_digit(encoded[offset]);
        const std::uint8_t low = decode_hex_digit(encoded[offset + 1U]);
        decoded.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned int>(high) * 16U +
            static_cast<unsigned int>(low)));
    }
    return decoded;
}

std::string encode_hex(const Bytes& bytes) {
    static constexpr std::array<char, 16U> alphabet{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    if (bytes.size() > (std::numeric_limits<std::size_t>::max() / 2U)) {
        throw CodecError("byte sequence is too large to hex-encode");
    }

    std::string encoded;
    encoded.reserve(bytes.size() * 2U);
    for (const std::uint8_t byte : bytes) {
        encoded.push_back(alphabet[static_cast<std::size_t>(byte >> 4U)]);
        encoded.push_back(alphabet[static_cast<std::size_t>(byte & UINT8_C(0x0f))]);
    }
    return encoded;
}

std::string encode_base64(const Bytes& bytes) {
    static constexpr std::array<char, 64U> alphabet{
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'};

    const std::size_t maximum_input_size =
        (std::numeric_limits<std::size_t>::max() / 4U) * 3U;
    if (bytes.size() > maximum_input_size) {
        throw CodecError("byte sequence is too large to base64-encode");
    }

    std::string encoded;
    encoded.reserve(((bytes.size() + 2U) / 3U) * 4U);

    std::size_t offset = 0U;
    while ((bytes.size() - offset) >= 3U) {
        const std::uint32_t block =
            (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
            (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
            static_cast<std::uint32_t>(bytes[offset + 2U]);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 18U) & 0x3fU)]);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 12U) & 0x3fU)]);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 6U) & 0x3fU)]);
        encoded.push_back(alphabet[static_cast<std::size_t>(block & 0x3fU)]);
        offset += 3U;
    }

    const std::size_t remaining = bytes.size() - offset;
    if (remaining == 1U) {
        const std::uint32_t block =
            static_cast<std::uint32_t>(bytes[offset]) << 16U;
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 18U) & 0x3fU)]);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 12U) & 0x3fU)]);
        encoded.push_back('=');
        encoded.push_back('=');
    } else if (remaining == 2U) {
        const std::uint32_t block =
            (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
            (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 18U) & 0x3fU)]);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 12U) & 0x3fU)]);
        encoded.push_back(alphabet[static_cast<std::size_t>((block >> 6U) & 0x3fU)]);
        encoded.push_back('=');
    }

    return encoded;
}

Bytes decode_base64(const std::string_view encoded,
                    const std::size_t maximum_characters) {
    if (encoded.size() > maximum_characters) {
        std::ostringstream message;
        message << "base64 input is " << encoded.size()
                << " characters; maximum is " << maximum_characters;
        throw CodecError(message.str());
    }
    if (encoded.empty()) {
        return {};
    }
    if ((encoded.size() % 4U) != 0U) {
        throw CodecError(
            "base64 input length must be a multiple of 4 with canonical padding");
    }

    const std::size_t first_padding = encoded.find('=');
    std::size_t padding = 0U;
    if (first_padding != std::string_view::npos) {
        padding = encoded.size() - first_padding;
        if ((padding != 1U && padding != 2U) || first_padding < 2U) {
            throw CodecError("base64 input has non-canonical padding");
        }
    }

    const std::size_t data_characters = encoded.size() - padding;
    for (std::size_t index = 0U; index < data_characters; ++index) {
        static_cast<void>(decode_base64_digit(encoded[index]));
    }
    for (std::size_t index = data_characters; index < encoded.size(); ++index) {
        if (encoded[index] != '=') {
            throw CodecError("base64 input has non-canonical padding");
        }
    }

    if (padding == 2U) {
        const std::uint8_t final_sextet =
            decode_base64_digit(encoded[encoded.size() - 3U]);
        if ((final_sextet & UINT8_C(0x0f)) != 0U) {
            throw CodecError("base64 input has non-canonical non-zero tail bits");
        }
    } else if (padding == 1U) {
        const std::uint8_t final_sextet =
            decode_base64_digit(encoded[encoded.size() - 2U]);
        if ((final_sextet & UINT8_C(0x03)) != 0U) {
            throw CodecError("base64 input has non-canonical non-zero tail bits");
        }
    }

    const std::size_t decoded_size = (encoded.size() / 4U) * 3U - padding;
    Bytes decoded;
    decoded.reserve(decoded_size);
    for (std::size_t offset = 0U; offset < encoded.size(); offset += 4U) {
        const std::uint32_t first = decode_base64_digit(encoded[offset]);
        const std::uint32_t second = decode_base64_digit(encoded[offset + 1U]);
        const std::uint32_t third = encoded[offset + 2U] == '='
                                        ? 0U
                                        : decode_base64_digit(encoded[offset + 2U]);
        const std::uint32_t fourth = encoded[offset + 3U] == '='
                                         ? 0U
                                         : decode_base64_digit(encoded[offset + 3U]);
        const std::uint32_t block =
            (first << 18U) | (second << 12U) | (third << 6U) | fourth;
        decoded.push_back(static_cast<std::uint8_t>(block >> 16U));
        if (decoded.size() < decoded_size) {
            decoded.push_back(
                static_cast<std::uint8_t>((block >> 8U) & UINT32_C(0xff)));
        }
        if (decoded.size() < decoded_size) {
            decoded.push_back(static_cast<std::uint8_t>(block & UINT32_C(0xff)));
        }
    }
    return decoded;
}

bool is_valid_utf8(const std::string_view text) noexcept {
    std::size_t offset = 0U;
    while (offset < text.size()) {
        const std::uint8_t first =
            static_cast<std::uint8_t>(static_cast<unsigned char>(text[offset]));
        if (first <= UINT8_C(0x7f)) {
            ++offset;
            continue;
        }

        if (first >= UINT8_C(0xc2) && first <= UINT8_C(0xdf)) {
            if ((text.size() - offset) < 2U) {
                return false;
            }
            const std::uint8_t second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(text[offset + 1U]));
            if (!is_continuation(second)) {
                return false;
            }
            offset += 2U;
            continue;
        }

        if (first >= UINT8_C(0xe0) && first <= UINT8_C(0xef)) {
            if ((text.size() - offset) < 3U) {
                return false;
            }
            const std::uint8_t second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(text[offset + 1U]));
            const std::uint8_t third = static_cast<std::uint8_t>(
                static_cast<unsigned char>(text[offset + 2U]));
            const bool valid_second =
                (first == UINT8_C(0xe0))
                    ? (second >= UINT8_C(0xa0) && second <= UINT8_C(0xbf))
                    : ((first == UINT8_C(0xed))
                           ? (second >= UINT8_C(0x80) &&
                              second <= UINT8_C(0x9f))
                           : is_continuation(second));
            if (!valid_second || !is_continuation(third)) {
                return false;
            }
            offset += 3U;
            continue;
        }

        if (first >= UINT8_C(0xf0) && first <= UINT8_C(0xf4)) {
            if ((text.size() - offset) < 4U) {
                return false;
            }
            const std::uint8_t second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(text[offset + 1U]));
            const std::uint8_t third = static_cast<std::uint8_t>(
                static_cast<unsigned char>(text[offset + 2U]));
            const std::uint8_t fourth = static_cast<std::uint8_t>(
                static_cast<unsigned char>(text[offset + 3U]));
            const bool valid_second =
                (first == UINT8_C(0xf0))
                    ? (second >= UINT8_C(0x90) && second <= UINT8_C(0xbf))
                    : ((first == UINT8_C(0xf4))
                           ? (second >= UINT8_C(0x80) &&
                              second <= UINT8_C(0x8f))
                           : is_continuation(second));
            if (!valid_second || !is_continuation(third) ||
                !is_continuation(fourth)) {
                return false;
            }
            offset += 4U;
            continue;
        }

        return false;
    }
    return true;
}

void require_valid_utf8(const std::string_view text,
                        const std::string_view field_name) {
    if (!is_valid_utf8(text)) {
        throw CodecError(std::string(field_name) + " is not valid UTF-8");
    }
}

}  // namespace arborkdf
