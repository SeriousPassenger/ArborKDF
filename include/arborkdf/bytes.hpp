#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace arborkdf {

using Bytes = std::vector<std::uint8_t>;

inline void append_u32_be(Bytes& output, const std::uint32_t value) {
    for (std::size_t index = 0U; index < 4U; ++index) {
        const std::size_t shift = (3U - index) * 8U;
        output.push_back(
            static_cast<std::uint8_t>((value >> shift) & UINT32_C(0xff)));
    }
}

inline void append_u64_be(Bytes& output, const std::uint64_t value) {
    for (std::size_t index = 0U; index < 8U; ++index) {
        const std::size_t shift = (7U - index) * 8U;
        output.push_back(
            static_cast<std::uint8_t>((value >> shift) & UINT64_C(0xff)));
    }
}

inline std::uint64_t load_u64_be(const Bytes& input,
                                 const std::size_t offset) {
    if (offset > input.size() || (input.size() - offset) < 8U) {
        throw std::out_of_range("not enough bytes for a big-endian u64");
    }

    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 8U; ++index) {
        value = (value << 8U) |
                static_cast<std::uint64_t>(input[offset + index]);
    }
    return value;
}

}  // namespace arborkdf
