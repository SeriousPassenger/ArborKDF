#ifndef ARBORKDF_ENTROPY_HPP
#define ARBORKDF_ENTROPY_HPP

#include "arborkdf/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace arborkdf {

// Mouse input is supplementary data. ArborKDF never assigns it security entropy
// credit; the operating-system CSPRNG remains the primary random source.
struct MouseEvent final {
    std::int32_t dx{};
    std::int32_t dy{};
    std::uint64_t delta_nanoseconds{};
    std::uint32_t flags{};
};

enum class EntropyEstimateRole {
    descriptive,
    minimum_candidate,
    compression_only,
};

struct EntropyEstimateRow final {
    std::string stream;
    std::string method;
    EntropyEstimateRole role{EntropyEstimateRole::descriptive};
    std::size_t sample_count{};
    std::size_t minimum_samples{};
    bool available{};
    std::optional<double> bits_per_symbol;
    std::optional<double> projected_bits;
    std::optional<std::size_t> compressed_bytes;
    std::optional<double> compression_ratio;
    std::string status;
};

struct EntropyReport final {
    std::size_t event_count{};
    std::size_t distinct_symbol_pair_count{};
    std::vector<EntropyEstimateRow> rows;
    std::optional<double> diagnostic_minimum_bits;
    double mouse_security_credit_bits{};
    std::string disclaimer;
};

// OS bit counts describe bytes actually supplied to the conditioner. Mouse and
// combined fields are diagnostic policy weights, not raw transcript lengths,
// certified entropy, or estimates of cryptographic security strength.
struct OsRandomnessDiagnostics final {
    std::string source;
    std::string path;
    std::size_t bytes_read{};
    std::size_t input_bits{};
};

struct CombinedRandomnessDiagnostics final {
    std::optional<double> mouse_diagnostic_bits;
    double os_supplied_input_bits{};
    double mouse_policy_weight_bits{};
    double policy_weighted_total_bits{};
    double os_policy_percent{};
    double mouse_policy_percent{};
    std::string disclaimer;
};

struct ConditioningDiagnostics final {
    OsRandomnessDiagnostics os;
    EntropyReport mouse;
    CombinedRandomnessDiagnostics combined;
};

struct ConditionedRandomResult final {
    Bytes bytes;
    ConditioningDiagnostics diagnostics;
};

inline constexpr std::uint32_t kMouseTranscriptVersion = 1U;
inline constexpr std::uint64_t kTimingSymbolQuantumNanoseconds = 1000U;
inline constexpr std::size_t kMaximumConditionedOutputBytes = 1024U * 1024U;
inline constexpr std::size_t kMinimumOsRandomInputBytes = 64U;
inline constexpr std::size_t kMaximumOsRandomInputBytes = 1024U * 1024U;

// The framing is canonical, versioned, fixed-width, and preserves duplicate
// events and their order. Integers are encoded in network byte order.
[[nodiscard]] Bytes frame_mouse_transcript(const std::vector<MouseEvent>& events);

// These deliberately simple, documented projections are for live diagnostics
// only. They are not entropy-source validation or security-credit functions.
[[nodiscard]] std::uint8_t motion_symbol(const MouseEvent& event) noexcept;
[[nodiscard]] std::uint8_t timing_symbol(const MouseEvent& event) noexcept;

[[nodiscard]] EntropyReport analyze_mouse_events(
    const std::vector<MouseEvent>& events);
[[nodiscard]] std::string format_entropy_report(const EntropyReport& report);

// Returns the byte-aligned Linux OS-random input length. At least 64 bytes
// (512 input bits) are always used. A larger mouse diagnostic is matched by an
// equal, rounded-up quantity of OS input for the requested display policy.
[[nodiscard]] std::size_t required_os_random_bytes(
    const std::optional<double>& mouse_diagnostic_bits);

[[nodiscard]] std::string format_os_randomness_diagnostics(
    const OsRandomnessDiagnostics& diagnostics);
[[nodiscard]] std::string format_combined_randomness_diagnostics(
    const CombinedRandomnessDiagnostics& diagnostics);
[[nodiscard]] std::string format_conditioning_diagnostics(
    const ConditioningDiagnostics& diagnostics);

// After a blocking getrandom(2) readiness check, obtains at least 64 counted
// bytes directly from Linux /dev/urandom, increasing that input to match a
// larger mouse diagnostic. Purpose, OS bytes, transcript, and output length are
// framed into the v2 SHAKE256 conditioner. A source failure is fatal. Fresh
// diagnostics are returned beside (and never cached as) output.
[[nodiscard]] ConditionedRandomResult condition_random(
    const std::vector<MouseEvent>& events,
    const std::string& purpose,
    std::size_t output_bytes);

// Streaming equivalent. It retains compact motion/timing diagnostic symbols,
// but not the full event list. Fresh OS input is obtained only by finish().
class StreamingRandomConditioner final {
public:
    explicit StreamingRandomConditioner(const std::string& purpose);
    ~StreamingRandomConditioner();

    StreamingRandomConditioner(StreamingRandomConditioner&& other) noexcept;
    StreamingRandomConditioner& operator=(StreamingRandomConditioner&& other) noexcept;

    StreamingRandomConditioner(const StreamingRandomConditioner&) = delete;
    StreamingRandomConditioner& operator=(const StreamingRandomConditioner&) = delete;

    void add_event(const MouseEvent& event);
    [[nodiscard]] ConditionedRandomResult finish(std::size_t output_bytes);
    [[nodiscard]] std::size_t event_count() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

}  // namespace arborkdf

#endif
