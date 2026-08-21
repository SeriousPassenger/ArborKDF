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
    std::vector<EntropyEstimateRow> rows;
    std::optional<double> diagnostic_minimum_bits;
    double mouse_security_credit_bits{};
    std::string disclaimer;
};

inline constexpr std::uint32_t kMouseTranscriptVersion = 1U;
inline constexpr std::uint64_t kTimingSymbolQuantumNanoseconds = 1000U;
inline constexpr std::size_t kMaximumConditionedOutputBytes = 1024U * 1024U;

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

// Obtains the full requested byte count with RAND_priv_bytes, derives an equally
// long domain-separated SHAKE256 stream from the mouse transcript, and XORs the
// streams. A failure of the operating-system/OpenSSL random source is a hard
// error; deterministic expansion is never reported as additional entropy.
[[nodiscard]] Bytes condition_random(const std::vector<MouseEvent>& events,
                                     const std::string& purpose,
                                     std::size_t output_bytes);

// Streaming equivalent for collectors that should not retain an unbounded
// event list. Each instance obtains fresh OS randomness on construction.
class StreamingRandomConditioner final {
public:
    explicit StreamingRandomConditioner(const std::string& purpose);
    ~StreamingRandomConditioner();

    StreamingRandomConditioner(StreamingRandomConditioner&& other) noexcept;
    StreamingRandomConditioner& operator=(StreamingRandomConditioner&& other) noexcept;

    StreamingRandomConditioner(const StreamingRandomConditioner&) = delete;
    StreamingRandomConditioner& operator=(const StreamingRandomConditioner&) = delete;

    void add_event(const MouseEvent& event);
    [[nodiscard]] Bytes finish(std::size_t output_bytes);
    [[nodiscard]] std::size_t event_count() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

}  // namespace arborkdf

#endif
