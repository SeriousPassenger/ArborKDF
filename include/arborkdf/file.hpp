#pragma once

#include <string>
#include <string_view>

namespace arborkdf {

// Creates path as a new binary file and writes contents exactly. The operation
// fails atomically at creation time if any filesystem object already occupies
// path; existing files and symlinks are never opened or truncated.
void write_new_binary_file(const std::string& path,
                           std::string_view contents);

}  // namespace arborkdf
