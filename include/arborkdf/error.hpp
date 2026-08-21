#ifndef ARBORKDF_ERROR_HPP
#define ARBORKDF_ERROR_HPP

#include <stdexcept>
#include <string>

namespace arborkdf {

class Error final : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

}  // namespace arborkdf

#endif
