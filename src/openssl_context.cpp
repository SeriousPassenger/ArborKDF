#include "arborkdf/openssl_context.hpp"

#include "arborkdf/error.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <array>
#include <memory>
#include <string>

namespace arborkdf {
namespace {

[[nodiscard]] std::string openssl_context_error(const std::string& operation) {
    const unsigned long code = ERR_get_error();
    if (code == 0UL) {
        return operation + " failed";
    }
    std::array<char, 256U> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return operation + " failed: " + std::string(buffer.data());
}

class PrivateOpenSslContext final {
public:
    PrivateOpenSslContext() : context_(make_context()) {
        if (!context_) {
            throw Error(openssl_context_error("allocate private OpenSSL context"));
        }
        provider_ = OSSL_PROVIDER_load(context_.get(), "default");
        if (provider_ == nullptr) {
            throw Error(openssl_context_error("load OpenSSL default provider"));
        }
    }

    ~PrivateOpenSslContext() {
        if (provider_ != nullptr) {
            static_cast<void>(OSSL_PROVIDER_unload(provider_));
        }
    }

    PrivateOpenSslContext(const PrivateOpenSslContext&) = delete;
    PrivateOpenSslContext& operator=(const PrivateOpenSslContext&) = delete;

    [[nodiscard]] OSSL_LIB_CTX* get() const noexcept { return context_.get(); }

private:
    struct ContextDeleter final {
        void operator()(OSSL_LIB_CTX* value) const noexcept { OSSL_LIB_CTX_free(value); }
    };

    [[nodiscard]] static OSSL_LIB_CTX* make_context() {
        if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1) {
            throw Error(openssl_context_error(
                "initialize OpenSSL without external configuration"));
        }
        return OSSL_LIB_CTX_new();
    }

    std::unique_ptr<OSSL_LIB_CTX, ContextDeleter> context_;
    OSSL_PROVIDER* provider_{};
};

}  // namespace

OSSL_LIB_CTX* openssl_context() {
    static PrivateOpenSslContext context;
    return context.get();
}

}  // namespace arborkdf
