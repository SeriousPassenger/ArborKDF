#include "arborkdf/crypto.hpp"
#include "arborkdf/error.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using arborkdf::Bytes;

[[nodiscard]] Bytes from_hex(const std::string& text) {
    if (text.size() % 2U != 0U) {
        throw std::runtime_error("invalid test hex");
    }
    const auto nibble = [](const char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<std::uint8_t>(10 + value - 'a');
        }
        if (value >= 'A' && value <= 'F') {
            return static_cast<std::uint8_t>(10 + value - 'A');
        }
        throw std::runtime_error("invalid test hex");
    };
    Bytes output;
    output.reserve(text.size() / 2U);
    for (std::size_t index = 0U; index < text.size(); index += 2U) {
        const std::uint8_t high = nibble(text[index]);
        const std::uint8_t low = nibble(text[index + 1U]);
        output.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }
    return output;
}

[[nodiscard]] Bytes from_ascii(const std::string_view text) {
    Bytes output;
    output.reserve(text.size());
    for (const char character : text) {
        output.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(character)));
    }
    return output;
}

void require(const bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error("crypto test failed: " + message);
    }
}

template <typename Operation>
void require_error(Operation&& operation,
                   const std::string_view expected_message,
                   const std::string_view description) {
    try {
        operation();
    } catch (const arborkdf::Error& error) {
        require(std::string_view(error.what()).find(expected_message) !=
                    std::string_view::npos,
                std::string(description) + ": unexpected error text: " +
                    error.what());
        return;
    }
    require(false, std::string(description) + ": expected an error");
}

[[nodiscard]] arborkdf::KdfParameters test_parameters(
    const arborkdf::SecurityTarget target,
    const std::size_t output_bits) {
    arborkdf::KdfParameters parameters{};
    parameters.pbkdf2_iterations = 1U;
    parameters.argon2_memory_kib = 8U;
    parameters.argon2_iterations = 1U;
    parameters.argon2_parallelism = 1U;
    parameters.output_bits = output_bits;
    parameters.security_target = target;
    return parameters;
}

[[nodiscard]] Bytes framed_utf8_test_master() {
    return from_hex(
        "00000000000000174172626f724b44462f6d61737465722f757466382f7631"
        "000000000000000474657374");
}

void test_sha3_and_shake() {
    const Bytes sha3_256_expected =
        from_hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    const Bytes sha3_512_expected = from_hex(
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a61"
        "5b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    const Bytes shake256_expected = from_hex(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

    require(arborkdf::sha3_256(Bytes{}) == sha3_256_expected,
            "SHA3-256 empty-message known-answer vector");
    require(arborkdf::sha3_512(Bytes{}) == sha3_512_expected,
            "SHA3-512 empty-message known-answer vector");
    require(arborkdf::shake256(Bytes{}, 64U) == shake256_expected,
            "SHAKE256 empty-message 512-bit known-answer vector");
    require(arborkdf::shake256(Bytes{}, 0U).empty(),
            "SHAKE256 permits an empty requested output");
}

void test_hmac_sha3_512() {
    // Independently cross-checked with Python hmac/hashlib and the OpenSSL CLI.
    const Bytes key(20U, UINT8_C(0x0b));
    const Bytes input = from_ascii("Hi There");
    const Bytes expected = from_hex(
        "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba"
        "47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e");
    require(arborkdf::hmac_sha3_512(key, input) == expected,
            "HMAC-SHA3-512 known-answer vector");
}

void test_kmac256() {
    const Bytes key = from_hex(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    const Bytes data = from_hex("00010203");
    const Bytes expected = from_hex(
        "20c570c31346f703c9ac36c61c03cb64"
        "c3970d0cfc787e9b79599d273a68d2f7"
        "f69d4cc3de9d104a351689f27cf6f595"
        "1f0103f33f4f24871024d9c27773a8dd");
    require(arborkdf::kmac256(key, data, 64U, "My Tagged Application") == expected,
            "NIST SP 800-185 KMAC256 sample");
}

void test_derivation_known_answers() {
    // This is the exact UTF-8 master frame for "test", not an unframed password.
    // The root and final vectors were independently reproduced with Python's
    // hashlib PBKDF2-HMAC-SHA3-512, cryptography's Argon2id v1.3, the OpenSSL
    // KMAC CLI, and Python HMAC-SHA3-512 counter-mode framing.
    const Bytes framed_master = framed_utf8_test_master();
    const Bytes salt = from_hex("000102030405060708090a0b0c0d0e0f");
    const Bytes expected_root = from_hex(
        "f8ac398f57261a95f88ce68384954e54484bcb09841c5a3855de1f595dd391bf"
        "a1163a0316ade9dbdb77cbe2eae809eb41c0a8528ea8cb72bca9c57c130d3236");
    const Bytes expected_pq128 = from_hex(
        "455489cba2bf8306a4ee11ba39260d7e2ba61d14474d7948f02e9e13eca4348c");
    const Bytes expected_pq256 = from_hex(
        "862f1d93ce4c27177362a57578b83efdbdf4fd5c8e649b01ca532e0a7fdcbb79"
        "d75906becbfa33875b725b09e1d97ffaf1f8378bb9a7f4e08b8d32a3fd8ba992");
    const Bytes expected_pq128_512 = from_hex(
        "697d35f74026b64f9f603b8192361fa544ec60df2e2e20643ff7c8302198dd9b"
        "17df3e1d0e314951cef1aaae79921786bc9d918733d4619444756b0f1c16744a");
    const Bytes expected_pq256_1024 = from_hex(
        "e605ee8c6dd455f616b2f2bd49514ac06dd45670b4ad6c10f2a050012084d8a1"
        "dacdf694dca9f3449e7e202fe74cc782e561e0c30c4f8a57cd346bd959ec13de"
        "5044f4e65917eaaa93e987b6c8d1b370e2dbfcd81d906f3e5d227e9e39f04da"
        "1327a2943d1d30a128859c3ddb8cd0dbce81288c2ee38547c836159d5de5f1447");

    arborkdf::KdfParameters parameters =
        test_parameters(arborkdf::SecurityTarget::pq128, 256U);
    require(arborkdf::derive_root_key(framed_master, salt, parameters) ==
                expected_root,
            "PBKDF2-HMAC-SHA3-512 plus Argon2id-v1.3 root vector");
    require(arborkdf::derive_subkey(
                framed_master, salt, "/testing/path", parameters) ==
                expected_pq128,
            "PQ-128 KMAC256 end-to-end vector");

    parameters = test_parameters(arborkdf::SecurityTarget::pq256, 512U);
    require(arborkdf::derive_subkey(
                framed_master, salt, "/testing/path", parameters) ==
                expected_pq256,
            "PQ-256 SP 800-108 HMAC-SHA3-512 end-to-end vector");

    parameters = test_parameters(arborkdf::SecurityTarget::pq128, 512U);
    require(arborkdf::derive_subkey(
                framed_master, salt, "/testing/path", parameters) ==
                expected_pq128_512,
            "KMAC256 binds a 512-bit requested output length");

    parameters = test_parameters(arborkdf::SecurityTarget::pq256, 1024U);
    require(arborkdf::derive_subkey(
                framed_master, salt, "/testing/path", parameters) ==
                expected_pq256_1024,
            "SP 800-108 binds length and expands through counter block two");

    parameters = test_parameters(arborkdf::SecurityTarget::pq128, 256U);
    const Bytes other_path = arborkdf::derive_subkey(
        framed_master, salt, "/testing/other", parameters);
    require(other_path != expected_pq128, "path is bound into the derived key");
}

void test_root_cost_parameter_known_answer() {
    // This second independent vector exercises PBKDF2's U-chain, multiple
    // Argon2 passes, and more than one Argon2 lane.
    const Bytes framed_master = framed_utf8_test_master();
    const Bytes salt = from_hex("000102030405060708090a0b0c0d0e0f");
    const Bytes expected_root = from_hex(
        "9e2f8917dc22fefd5de4fb9f0a60c1f9236341a27c7344ea54a8dbf9dee08f9d"
        "7b098b668453fb3d2b71680c06fcf476a3f5b60f377666129d7dbf5c212a7708");
    arborkdf::KdfParameters parameters =
        test_parameters(arborkdf::SecurityTarget::pq128, 256U);
    parameters.pbkdf2_iterations = 2U;
    parameters.argon2_memory_kib = 32U;
    parameters.argon2_iterations = 2U;
    parameters.argon2_parallelism = 2U;

    require(arborkdf::derive_root_key(framed_master, salt, parameters) ==
                expected_root,
            "multi-iteration, multi-lane root derivation vector");
}

void test_parameter_rejection() {
    arborkdf::KdfParameters parameters =
        test_parameters(arborkdf::SecurityTarget::pq256, 256U);
    require_error(
        [&parameters] { arborkdf::validate_kdf_parameters(parameters); },
        "below the selected",
        "PQ-256 rejects a 256-bit output");

    parameters = test_parameters(arborkdf::SecurityTarget::unspecified, 512U);
    require_error(
        [&parameters] { arborkdf::validate_kdf_parameters(parameters); },
        "explicitly selected",
        "unspecified security target is rejected");

    parameters.security_target = static_cast<arborkdf::SecurityTarget>(999);
    require_error(
        [&parameters] { arborkdf::validate_kdf_parameters(parameters); },
        "target is invalid",
        "out-of-range security target is rejected");
}

void test_path_validation_boundary() {
    const Bytes master = framed_utf8_test_master();
    const Bytes salt(16U, UINT8_C(0x5a));
    const arborkdf::KdfParameters parameters =
        test_parameters(arborkdf::SecurityTarget::pq128, 256U);

    require(arborkdf::derive_subkey(master, salt, "a1234567", parameters).size() ==
                32U,
            "eight-character path is accepted");
    require(arborkdf::derive_subkey(
                master, salt, std::string(64U, 'a'), parameters).size() == 32U,
            "64-character path is accepted");
    require(arborkdf::derive_subkey(
                master, salt, "a0+-/.@#_:", parameters).size() == 32U,
            "documented path punctuation is accepted");

    require_error(
        [&master, &salt, &parameters] {
            static_cast<void>(arborkdf::derive_subkey(
                master, salt, "a123456", parameters));
        },
        "between 8 and 64",
        "seven-character path is rejected");
    require_error(
        [&master, &salt, &parameters] {
            static_cast<void>(arborkdf::derive_subkey(
                master, salt, std::string(65U, 'a'), parameters));
        },
        "between 8 and 64",
        "65-character path is rejected");
    require_error(
        [&master, &salt, &parameters] {
            static_cast<void>(arborkdf::derive_subkey(
                master, salt, "a123456A", parameters));
        },
        "disallowed character",
        "uppercase path character is rejected");
    require_error(
        [&master, &salt, &parameters] {
            const std::string embedded_nul("a123456\0", 8U);
            static_cast<void>(arborkdf::derive_subkey(
                master, salt, embedded_nul, parameters));
        },
        "disallowed character",
        "embedded NUL path character is rejected");
}

}  // namespace

void run_crypto_tests() {
    test_sha3_and_shake();
    test_hmac_sha3_512();
    test_kmac256();
    test_derivation_known_answers();
    test_root_cost_parameter_known_answer();
    test_parameter_rejection();
    test_path_validation_boundary();
}
