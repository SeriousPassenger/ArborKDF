#ifndef ARBORKDF_CRYPTO_HPP
#define ARBORKDF_CRYPTO_HPP

#include "arborkdf/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace arborkdf {

enum class SecurityTarget {
    unspecified,
    pq128,
    pq256,
};

struct KdfParameters final {
    std::uint32_t pbkdf2_iterations{};
    std::uint32_t argon2_memory_kib{};
    std::uint32_t argon2_iterations{};
    std::uint32_t argon2_parallelism{};
    std::size_t output_bits{};
    SecurityTarget security_target{SecurityTarget::unspecified};
};

[[nodiscard]] Bytes sha3_256(const Bytes& input);
[[nodiscard]] Bytes sha3_512(const Bytes& input);
[[nodiscard]] Bytes shake256(const Bytes& input, std::size_t output_bytes);
[[nodiscard]] Bytes hmac_sha3_512(const Bytes& key, const Bytes& input);
[[nodiscard]] Bytes kmac256(const Bytes& key,
                            const Bytes& input,
                            std::size_t output_bytes,
                            const std::string& customization);

[[nodiscard]] Bytes derive_root_key(const Bytes& framed_master,
                                    const Bytes& public_salt,
                                    const KdfParameters& parameters);
[[nodiscard]] Bytes derive_subkey(const Bytes& framed_master,
                                  const Bytes& public_salt,
                                  const std::string& path,
                                  const KdfParameters& parameters);

void validate_kdf_parameters(const KdfParameters& parameters);
void secure_clear(Bytes& value) noexcept;

}  // namespace arborkdf

#endif
