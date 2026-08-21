#include "arborkdf/crypto.hpp"

#include "arborkdf/error.hpp"
#include "arborkdf/openssl_context.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <argon2.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

namespace arborkdf {
namespace {

constexpr std::size_t kRootBytes = 64U;
constexpr std::size_t kMaximumOutputBits = 4096U;
constexpr std::size_t kMinimumSaltBytes = 16U;
constexpr std::size_t kMaximumSaltBytes = 1024U;
constexpr std::string_view kAllowedPathCharacters =
    "abcdefghijklmnopqrstuvwxyz0123456789+-/.@#_:";

struct EvpMdDeleter final {
    void operator()(EVP_MD* value) const noexcept { EVP_MD_free(value); }
};

struct EvpMdCtxDeleter final {
    void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); }
};

struct EvpMacDeleter final {
    void operator()(EVP_MAC* value) const noexcept { EVP_MAC_free(value); }
};

struct EvpMacCtxDeleter final {
    void operator()(EVP_MAC_CTX* value) const noexcept { EVP_MAC_CTX_free(value); }
};

struct EvpKdfDeleter final {
    void operator()(EVP_KDF* value) const noexcept { EVP_KDF_free(value); }
};

struct EvpKdfCtxDeleter final {
    void operator()(EVP_KDF_CTX* value) const noexcept { EVP_KDF_CTX_free(value); }
};

using UniqueMd = std::unique_ptr<EVP_MD, EvpMdDeleter>;
using UniqueMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using UniqueMac = std::unique_ptr<EVP_MAC, EvpMacDeleter>;
using UniqueMacCtx = std::unique_ptr<EVP_MAC_CTX, EvpMacCtxDeleter>;
using UniqueKdf = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using UniqueKdfCtx = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

[[nodiscard]] std::string openssl_error(const std::string& operation) {
    const unsigned long code = ERR_get_error();
    if (code == 0UL) {
        return operation + " failed";
    }
    std::array<char, 256U> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return operation + " failed: " + std::string(buffer.data());
}

void append_u32(Bytes& destination, const std::uint32_t value) {
    destination.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    destination.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    destination.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    destination.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void validate_path(const std::string& path) {
    if (path.size() < 8U || path.size() > 64U) {
        throw Error("path must contain between 8 and 64 ASCII characters");
    }
    for (const char value : path) {
        if (kAllowedPathCharacters.find(value) == std::string_view::npos) {
            throw Error(
                "path contains a disallowed character; allowed set is "
                "[a-z0-9+-/.@#_:]");
        }
    }
}

void append_u64(Bytes& destination, const std::uint64_t value) {
    for (unsigned int shift = 56U;; shift -= 8U) {
        destination.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        if (shift == 0U) {
            break;
        }
    }
}

void append_bytes(Bytes& destination, const Bytes& value) {
    append_u64(destination, static_cast<std::uint64_t>(value.size()));
    destination.insert(destination.end(), value.begin(), value.end());
}

void append_string(Bytes& destination, const std::string& value) {
    append_u64(destination, static_cast<std::uint64_t>(value.size()));
    destination.insert(destination.end(), value.begin(), value.end());
}

[[nodiscard]] Bytes domain_frame(const std::string& domain, const Bytes& value) {
    Bytes framed;
    framed.reserve(domain.size() + value.size() + 16U);
    append_string(framed, domain);
    append_bytes(framed, value);
    return framed;
}

[[nodiscard]] Bytes digest(const char* const algorithm,
                           const Bytes& input,
                           const std::size_t expected_size) {
    UniqueMd md(EVP_MD_fetch(
        openssl_context(), algorithm, kOpenSslDefaultProviderQuery));
    if (!md) {
        throw Error(openssl_error(std::string("fetch ") + algorithm));
    }
    UniqueMdCtx context(EVP_MD_CTX_new());
    if (!context) {
        throw Error(openssl_error("allocate digest context"));
    }
    if (EVP_DigestInit_ex2(context.get(), md.get(), nullptr) != 1 ||
        (!input.empty() && EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1)) {
        throw Error(openssl_error(std::string("compute ") + algorithm));
    }
    Bytes output(expected_size);
    unsigned int written = 0U;
    if (EVP_DigestFinal_ex(context.get(), output.data(), &written) != 1 ||
        static_cast<std::size_t>(written) != expected_size) {
        throw Error(openssl_error(std::string("finalize ") + algorithm));
    }
    return output;
}

[[nodiscard]] Bytes pbkdf2_sha3_512(const Bytes& password,
                                    const Bytes& salt,
                                    const std::uint32_t iterations) {
    UniqueKdf kdf(EVP_KDF_fetch(
        openssl_context(), "PBKDF2", kOpenSslDefaultProviderQuery));
    if (!kdf) {
        throw Error(openssl_error("fetch PBKDF2"));
    }
    UniqueKdfCtx context(EVP_KDF_CTX_new(kdf.get()));
    if (!context) {
        throw Error(openssl_error("allocate PBKDF2 context"));
    }

    Bytes output(kRootBytes);
    std::uint64_t iteration_count = iterations;
    int pkcs5_compatibility = 1;
    std::array<char, 9U> digest_name{'S', 'H', 'A', '3', '-', '5', '1', '2', '\0'};
    void* password_pointer = password.empty()
                                 ? nullptr
                                 : const_cast<std::uint8_t*>(password.data());
    void* salt_pointer =
        salt.empty() ? nullptr : const_cast<std::uint8_t*>(salt.data());
    OSSL_PARAM kdf_parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, password_pointer, password.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt_pointer, salt.size()),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iteration_count),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name.data(), 0U),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5_compatibility),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_KDF_derive(context.get(), output.data(), output.size(), kdf_parameters) != 1) {
        secure_clear(output);
        throw Error(openssl_error("PBKDF2-HMAC-SHA3-512"));
    }
    return output;
}

[[nodiscard]] Bytes argon2id(Bytes& password,
                             Bytes& salt,
                             const KdfParameters& parameters) {
    if (password.size() > static_cast<std::size_t>(
                              std::numeric_limits<std::uint32_t>::max()) ||
        salt.size() > static_cast<std::size_t>(
                          std::numeric_limits<std::uint32_t>::max()) ||
        kRootBytes > static_cast<std::size_t>(
                         std::numeric_limits<std::uint32_t>::max())) {
        throw Error("Argon2id input exceeds the v1 32-bit length fields");
    }
    Bytes output(kRootBytes);
    argon2_context context{};
    context.out = output.data();
    context.outlen = static_cast<std::uint32_t>(output.size());
    context.pwd = password.empty() ? nullptr : password.data();
    context.pwdlen = static_cast<std::uint32_t>(password.size());
    context.salt = salt.empty() ? nullptr : salt.data();
    context.saltlen = static_cast<std::uint32_t>(salt.size());
    context.secret = nullptr;
    context.secretlen = 0U;
    context.ad = nullptr;
    context.adlen = 0U;
    context.t_cost = parameters.argon2_iterations;
    context.m_cost = parameters.argon2_memory_kib;
    context.lanes = parameters.argon2_parallelism;
    context.threads = parameters.argon2_parallelism;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = nullptr;
    context.free_cbk = nullptr;
    context.flags = ARGON2_FLAG_CLEAR_PASSWORD;
    const int result = argon2_ctx(&context, Argon2_id);
    if (result != ARGON2_OK) {
        const char* const message = argon2_error_message(result);
        secure_clear(output);
        throw Error(std::string("Argon2id failed: ") +
                    (message == nullptr ? "unknown error" : message));
    }
    return output;
}

[[nodiscard]] Bytes public_context(const Bytes& public_salt, const std::string& path) {
    Bytes context;
    const std::string domain = "ArborKDF/public-context/v1";
    context.reserve(domain.size() + public_salt.size() + path.size() + 24U);
    append_string(context, domain);
    append_bytes(context, public_salt);
    append_string(context, path);
    return context;
}

[[nodiscard]] Bytes sp800_108_hmac_sha3_512(const Bytes& key,
                                            const Bytes& context,
                                            const std::size_t output_bytes) {
    constexpr char kLabel[] = "ArborKDF/subkey/hmac-sha3-512/v1";
    const std::size_t output_bits = output_bytes * 8U;
    if (output_bits > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw Error("SP 800-108 output length exceeds 32-bit L encoding");
    }
    Bytes output;
    output.reserve(output_bytes);
    std::uint32_t counter = 1U;
    try {
        while (output.size() < output_bytes) {
            Bytes input;
            input.reserve(4U + sizeof(kLabel) + context.size() + 5U);
            append_u32(input, counter);
            input.insert(input.end(), kLabel, kLabel + sizeof(kLabel) - 1U);
            input.push_back(0U);
            input.insert(input.end(), context.begin(), context.end());
            append_u32(input, static_cast<std::uint32_t>(output_bits));
            Bytes block = hmac_sha3_512(key, input);
            const std::size_t remaining = output_bytes - output.size();
            const std::size_t take = std::min(remaining, block.size());
            try {
                output.insert(output.end(), block.begin(), block.begin() +
                                                       static_cast<std::ptrdiff_t>(take));
            } catch (...) {
                secure_clear(block);
                throw;
            }
            secure_clear(block);
            if (counter == std::numeric_limits<std::uint32_t>::max()) {
                throw Error("SP 800-108 counter exhausted");
            }
            ++counter;
        }
    } catch (...) {
        secure_clear(output);
        throw;
    }
    return output;
}

}  // namespace

Bytes sha3_256(const Bytes& input) { return digest("SHA3-256", input, 32U); }

Bytes sha3_512(const Bytes& input) { return digest("SHA3-512", input, 64U); }

Bytes shake256(const Bytes& input, const std::size_t output_bytes) {
    UniqueMd md(EVP_MD_fetch(
        openssl_context(), "SHAKE-256", kOpenSslDefaultProviderQuery));
    if (!md) {
        throw Error(openssl_error("fetch SHAKE-256"));
    }
    UniqueMdCtx context(EVP_MD_CTX_new());
    if (!context) {
        throw Error(openssl_error("allocate SHAKE-256 context"));
    }
    if (EVP_DigestInit_ex2(context.get(), md.get(), nullptr) != 1 ||
        (!input.empty() && EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1)) {
        throw Error(openssl_error("compute SHAKE-256"));
    }
    Bytes output(output_bytes);
    if (output_bytes != 0U &&
        EVP_DigestFinalXOF(context.get(), output.data(), output.size()) != 1) {
        secure_clear(output);
        throw Error(openssl_error("finalize SHAKE-256"));
    }
    return output;
}

Bytes hmac_sha3_512(const Bytes& key, const Bytes& input) {
    UniqueMac mac(EVP_MAC_fetch(
        openssl_context(), "HMAC", kOpenSslDefaultProviderQuery));
    if (!mac) {
        throw Error(openssl_error("fetch HMAC"));
    }
    UniqueMacCtx context(EVP_MAC_CTX_new(mac.get()));
    if (!context) {
        throw Error(openssl_error("allocate HMAC context"));
    }
    std::array<char, 9U> digest_name{'S', 'H', 'A', '3', '-', '5', '1', '2', '\0'};
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name.data(), 0U),
        OSSL_PARAM_construct_end(),
    };
    const unsigned char* key_pointer = key.empty() ? nullptr : key.data();
    if (EVP_MAC_init(context.get(), key_pointer, key.size(), parameters) != 1 ||
        (!input.empty() && EVP_MAC_update(context.get(), input.data(), input.size()) != 1)) {
        throw Error(openssl_error("HMAC-SHA3-512"));
    }
    Bytes output(64U);
    std::size_t written = 0U;
    if (EVP_MAC_final(context.get(), output.data(), &written, output.size()) != 1 ||
        written != output.size()) {
        secure_clear(output);
        throw Error(openssl_error("finalize HMAC-SHA3-512"));
    }
    return output;
}

Bytes kmac256(const Bytes& key,
              const Bytes& input,
              const std::size_t output_bytes,
              const std::string& customization) {
    UniqueMac mac(EVP_MAC_fetch(
        openssl_context(), "KMAC-256", kOpenSslDefaultProviderQuery));
    if (!mac) {
        throw Error(openssl_error("fetch KMAC-256"));
    }
    UniqueMacCtx context(EVP_MAC_CTX_new(mac.get()));
    if (!context) {
        throw Error(openssl_error("allocate KMAC-256 context"));
    }
    std::size_t requested_size = output_bytes;
    void* custom_pointer = customization.empty()
                               ? nullptr
                               : const_cast<char*>(customization.data());
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &requested_size),
        OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM, custom_pointer, customization.size()),
        OSSL_PARAM_construct_end(),
    };
    const unsigned char* key_pointer = key.empty() ? nullptr : key.data();
    if (EVP_MAC_init(context.get(), key_pointer, key.size(), parameters) != 1 ||
        (!input.empty() && EVP_MAC_update(context.get(), input.data(), input.size()) != 1)) {
        throw Error(openssl_error("KMAC-256"));
    }
    Bytes output(output_bytes);
    std::size_t written = 0U;
    if ((output_bytes != 0U &&
         EVP_MAC_final(context.get(), output.data(), &written, output.size()) != 1) ||
        written != output.size()) {
        secure_clear(output);
        throw Error(openssl_error("finalize KMAC-256"));
    }
    return output;
}

void validate_kdf_parameters(const KdfParameters& parameters) {
    if (parameters.pbkdf2_iterations == 0U) {
        throw Error("PBKDF2 iterations must be at least 1; no default is used");
    }
    if (parameters.argon2_iterations == 0U) {
        throw Error("Argon2id iterations must be at least 1; no default is used");
    }
    if (parameters.argon2_parallelism == 0U || parameters.argon2_parallelism > 256U) {
        throw Error("Argon2id parallelism must be between 1 and 256; no default is used");
    }
    const std::uint64_t minimum_memory =
        8ULL * static_cast<std::uint64_t>(parameters.argon2_parallelism);
    if (static_cast<std::uint64_t>(parameters.argon2_memory_kib) < minimum_memory) {
        throw Error("Argon2id memory KiB must be at least 8 times the parallelism");
    }
    if (parameters.output_bits == 0U || parameters.output_bits % 8U != 0U ||
        parameters.output_bits > kMaximumOutputBits) {
        throw Error("output bits must be a nonzero multiple of 8 and no greater than 4096");
    }
    std::size_t minimum = 0U;
    switch (parameters.security_target) {
        case SecurityTarget::pq128:
            minimum = 256U;
            break;
        case SecurityTarget::pq256:
            minimum = 512U;
            break;
        case SecurityTarget::unspecified:
            throw Error("post-quantum security target must be explicitly selected");
        default:
            throw Error("post-quantum security target is invalid");
    }
    if (parameters.output_bits < minimum) {
        throw Error("output length is below the selected post-quantum security target");
    }
}

Bytes derive_root_key(const Bytes& framed_master,
                      const Bytes& public_salt,
                      const KdfParameters& parameters) {
    validate_kdf_parameters(parameters);
    if (framed_master.empty()) {
        throw Error("master key input must not be empty");
    }
    if (public_salt.size() < kMinimumSaltBytes || public_salt.size() > kMaximumSaltBytes) {
        throw Error("public salt must contain between 16 and 1024 bytes");
    }

    Bytes pbkdf2_salt = domain_frame("ArborKDF/PBKDF2-HMAC-SHA3-512/v1", public_salt);
    Bytes intermediate =
        pbkdf2_sha3_512(framed_master, pbkdf2_salt, parameters.pbkdf2_iterations);
    secure_clear(pbkdf2_salt);

    Bytes argon_salt;
    Bytes root;
    try {
        argon_salt = domain_frame("ArborKDF/Argon2id-v1.3/v1", public_salt);
        root = argon2id(intermediate, argon_salt, parameters);
    } catch (...) {
        secure_clear(intermediate);
        secure_clear(argon_salt);
        throw;
    }
    secure_clear(intermediate);
    secure_clear(argon_salt);
    return root;
}

Bytes derive_subkey(const Bytes& framed_master,
                    const Bytes& public_salt,
                    const std::string& path,
                    const KdfParameters& parameters) {
    validate_path(path);
    Bytes root = derive_root_key(framed_master, public_salt, parameters);
    Bytes context;
    Bytes output;
    try {
        context = public_context(public_salt, path);
        switch (parameters.security_target) {
            case SecurityTarget::pq128:
                output = kmac256(root,
                                 context,
                                 parameters.output_bits / 8U,
                                 "ArborKDF/subkey/kmac256/v1");
                break;
            case SecurityTarget::pq256:
                output = sp800_108_hmac_sha3_512(
                    root, context, parameters.output_bits / 8U);
                break;
            case SecurityTarget::unspecified:
            default:
                throw Error("post-quantum security target is invalid");
        }
    } catch (...) {
        secure_clear(root);
        secure_clear(context);
        throw;
    }
    secure_clear(root);
    secure_clear(context);
    return output;
}

void secure_clear(Bytes& value) noexcept {
    if (!value.empty()) {
        OPENSSL_cleanse(value.data(), value.size());
    }
    value.clear();
}

}  // namespace arborkdf
