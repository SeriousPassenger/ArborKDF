#ifndef ARBORKDF_OPENSSL_CONTEXT_HPP
#define ARBORKDF_OPENSSL_CONTEXT_HPP

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

namespace arborkdf {

// Returns a private OpenSSL library context with the built-in/default provider
// loaded explicitly. ArborKDF does not load an OpenSSL configuration file.
[[nodiscard]] OSSL_LIB_CTX* openssl_context();

inline constexpr const char* kOpenSslDefaultProviderQuery = "provider=default";

}  // namespace arborkdf

#endif
