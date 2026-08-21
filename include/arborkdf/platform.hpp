#ifndef ARBORKDF_PLATFORM_HPP
#define ARBORKDF_PLATFORM_HPP

#include "arborkdf/entropy.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace arborkdf {

[[nodiscard]] std::string read_hidden_line(const std::string& prompt,
                                           std::size_t maximum_bytes);
[[nodiscard]] std::string format_mouse_progress_line(
    const EntropyReport& report);
[[nodiscard]] std::vector<MouseEvent> collect_mouse_events();
void secure_clear(std::string& value) noexcept;

}  // namespace arborkdf

#endif
