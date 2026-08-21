#include "arborkdf/entropy.hpp"
#include "arborkdf/error.hpp"
#include "arborkdf/platform.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(const bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error("entropy test failed: " + message);
    }
}

[[nodiscard]] const arborkdf::EntropyEstimateRow& find_row(
    const arborkdf::EntropyReport& report,
    const char* const stream,
    const char* const method) {
    for (const arborkdf::EntropyEstimateRow& row : report.rows) {
        if (row.stream == stream && row.method == method) {
            return row;
        }
    }
    throw std::runtime_error("entropy test failed: missing requested row");
}

[[nodiscard]] std::vector<arborkdf::MouseEvent> constant_events(
    const std::size_t count) {
    return std::vector<arborkdf::MouseEvent>(
        count, arborkdf::MouseEvent{1, -1, 8000000U, 0U});
}

[[nodiscard]] std::vector<arborkdf::MouseEvent> random_like_events(
    const std::size_t count) {
    std::vector<arborkdf::MouseEvent> events;
    events.reserve(count);
    std::uint32_t state = 0x9e3779b9U;
    for (std::size_t index = 0U; index < count; ++index) {
        state ^= state << 13U;
        state ^= state >> 17U;
        state ^= state << 5U;
        const std::int32_t dx = static_cast<std::int32_t>(state & 0x0fU) - 8;
        const std::int32_t dy =
            static_cast<std::int32_t>((state >> 4U) & 0x0fU) - 8;
        const std::uint64_t microseconds = 7000U + ((state >> 8U) & 0xffU);
        events.push_back(arborkdf::MouseEvent{dx,
                                              dy,
                                              microseconds * 1000U,
                                              0U});
    }
    return events;
}

[[nodiscard]] std::vector<arborkdf::MouseEvent> binary_random_like_events(
    const std::size_t count) {
    std::vector<arborkdf::MouseEvent> events;
    events.reserve(count);
    std::uint32_t state = 0x243f6a88U;
    for (std::size_t index = 0U; index < count; ++index) {
        state ^= state << 13U;
        state ^= state >> 17U;
        state ^= state << 5U;
        const bool motion_bit = (state & 1U) != 0U;
        const bool timing_bit = (state & 2U) != 0U;
        events.push_back(
            arborkdf::MouseEvent{motion_bit ? 1 : -1,
                                 motion_bit ? -1 : 1,
                                 timing_bit ? 8000000U : 8001000U,
                                 0U});
    }
    return events;
}

[[nodiscard]] std::size_t maximum_line_width(const std::string& text) {
    std::istringstream input(text);
    std::string line;
    std::size_t maximum = 0U;
    while (std::getline(input, line)) {
        maximum = std::max(maximum, line.size());
    }
    return maximum;
}

void test_symbolization_and_repeat_preservation() {
    const arborkdf::MouseEvent minimum{-100, -8, 1234567U, 0U};
    const arborkdf::MouseEvent maximum{100, 7, 1234567U, 0U};
    require(arborkdf::motion_symbol(minimum) == 0x88U,
            "negative motion saturation");
    require(arborkdf::motion_symbol(maximum) == 0x77U,
            "positive motion saturation");
    require(arborkdf::timing_symbol(minimum) ==
                static_cast<std::uint8_t>(1234U & 0xffU),
            "timing quantization");

    const arborkdf::MouseEvent event{2, -3, 9000001U, 7U};
    const std::vector<arborkdf::MouseEvent> once{event};
    const std::vector<arborkdf::MouseEvent> twice{event, event};
    const arborkdf::Bytes one_frame = arborkdf::frame_mouse_transcript(once);
    const arborkdf::Bytes two_frames = arborkdf::frame_mouse_transcript(twice);
    require(two_frames.size() == one_frame.size() + 21U,
            "duplicate event remains in transcript");
    require(arborkdf::frame_mouse_transcript(twice) == two_frames,
            "transcript framing is deterministic");
    const std::string transcript_domain = "ArborKDF/mouse-transcript/v1";
    const std::size_t version_offset = 4U + transcript_domain.size();
    require(two_frames.size() > version_offset + 4U &&
                two_frames[version_offset] == 0U &&
                two_frames[version_offset + 1U] == 0U &&
                two_frames[version_offset + 2U] == 0U &&
                two_frames[version_offset + 3U] == 1U,
            "transcript version is explicitly framed");
    require(arborkdf::load_u64_be(two_frames, two_frames.size() - 8U) == 2U,
            "transcript trailer preserves event count");

    std::vector<arborkdf::MouseEvent> changed = twice;
    changed[1].flags ^= 1U;
    require(arborkdf::frame_mouse_transcript(changed) != two_frames,
            "event change affects transcript");
}

void test_constant_and_alternating_diagnostics() {
    const arborkdf::EntropyReport constant =
        arborkdf::analyze_mouse_events(constant_events(256U));
    const auto& constant_mcv =
        find_row(constant, "motion-v1", "MCV min-entropy (Wilson upper)");
    const auto& constant_markov = find_row(
        constant, "motion-v1", "First-order transition min-entropy");
    const auto& constant_deflate =
        find_row(constant, "motion-v1", "Raw DEFLATE compressed size/ratio");
    require(constant_mcv.available && constant_mcv.bits_per_symbol.has_value(),
            "constant MCV availability");
    require(std::fabs(*constant_mcv.bits_per_symbol) < 1.0e-12,
            "constant MCV is zero");
    require(constant_markov.available && constant_markov.bits_per_symbol.has_value(),
            "constant Markov availability");
    require(std::fabs(*constant_markov.bits_per_symbol) < 1.0e-12,
            "constant Markov is zero");
    require(constant_deflate.available && constant_deflate.compression_ratio.has_value(),
            "constant compression availability");
    require(*constant_deflate.compression_ratio < 1.0,
            "constant stream is compressible");
    require(constant.diagnostic_minimum_bits.has_value() &&
                std::fabs(*constant.diagnostic_minimum_bits) < 1.0e-12,
            "constant diagnostic minimum is zero");
    require(constant.distinct_symbol_pair_count == 1U,
            "repeated events remain one distinct diagnostic symbol pair");

    std::vector<arborkdf::MouseEvent> short_alternating;
    short_alternating.reserve(64U);
    for (std::size_t index = 0U; index < 64U; ++index) {
        const bool even = index % 2U == 0U;
        short_alternating.push_back(
            arborkdf::MouseEvent{even ? 1 : -1,
                                 even ? -1 : 1,
                                 even ? 8000000U : 8001000U,
                                 0U});
    }
    const arborkdf::EntropyReport short_alternating_report =
        arborkdf::analyze_mouse_events(short_alternating);
    require(short_alternating_report.diagnostic_minimum_bits.has_value() &&
                std::fabs(*short_alternating_report.diagnostic_minimum_bits) <
                    1.0e-12,
            "short deterministic alternation is gated to zero before Markov");
    require(short_alternating_report.distinct_symbol_pair_count == 2U,
            "alternation reports two distinct diagnostic symbol pairs");

    const arborkdf::EntropyReport short_nonperiodic_report =
        arborkdf::analyze_mouse_events(random_like_events(64U));
    const auto& short_nonperiodic_mcv = find_row(
        short_nonperiodic_report,
        "motion-v1",
        "MCV min-entropy (Wilson upper)");
    const auto& short_nonperiodic_gate = find_row(
        short_nonperiodic_report,
        "motion-v1",
        "Exact repeated-prefix gate");
    require(short_nonperiodic_mcv.projected_bits.has_value() &&
                *short_nonperiodic_mcv.projected_bits > 0.0,
            "pre-128 nonperiodic MCV is individually positive");
    require(!short_nonperiodic_gate.projected_bits.has_value(),
            "pre-128 nonperiodic repeat gate remains inactive");
    require(!short_nonperiodic_report.diagnostic_minimum_bits.has_value(),
            "pre-128 nonperiodic input cannot use MCV alone");

    std::vector<arborkdf::MouseEvent> alternating;
    constexpr std::size_t kAlternatingRegressionEvents = 32768U;
    alternating.reserve(kAlternatingRegressionEvents);
    for (std::size_t index = 0U; index < kAlternatingRegressionEvents; ++index) {
        const bool even = index % 2U == 0U;
        alternating.push_back(
            arborkdf::MouseEvent{even ? 1 : -1,
                                 even ? -1 : 1,
                                 even ? 8000000U : 8001000U,
                                 0U});
    }
    const arborkdf::EntropyReport alternating_report =
        arborkdf::analyze_mouse_events(alternating);
    const auto& alternating_mcv = find_row(
        alternating_report, "motion-v1", "MCV min-entropy (Wilson upper)");
    const auto& alternating_markov = find_row(
        alternating_report, "motion-v1", "First-order transition min-entropy");
    require(alternating_mcv.bits_per_symbol.has_value() &&
                alternating_markov.bits_per_symbol.has_value(),
            "alternating estimates available");
    require(*alternating_markov.bits_per_symbol < *alternating_mcv.bits_per_symbol,
            "Markov diagnostic detects alternating predictability");
    require(alternating_markov.projected_bits.has_value() &&
                std::fabs(*alternating_markov.projected_bits) < 1.0e-12,
            "long deterministic alternation does not accumulate entropy");
    require(alternating_report.diagnostic_minimum_bits.has_value() &&
                std::fabs(*alternating_report.diagnostic_minimum_bits) < 1.0e-12,
            "long deterministic alternation leaves overall diagnostic at zero");

    std::vector<arborkdf::MouseEvent> higher_order_periodic;
    constexpr std::size_t kHigherOrderRegressionEvents = 32768U;
    higher_order_periodic.reserve(kHigherOrderRegressionEvents);
    const std::vector<arborkdf::MouseEvent> pattern{
        arborkdf::MouseEvent{1, -1, 8000000U, 0U},
        arborkdf::MouseEvent{2, -2, 8001000U, 0U},
        arborkdf::MouseEvent{1, -1, 8000000U, 0U},
        arborkdf::MouseEvent{3, -3, 8002000U, 0U}};
    for (std::size_t index = 0U; index < kHigherOrderRegressionEvents; ++index) {
        higher_order_periodic.push_back(pattern[index % pattern.size()]);
    }
    const arborkdf::EntropyReport higher_order_report =
        arborkdf::analyze_mouse_events(higher_order_periodic);
    const auto& repeat_gate = find_row(
        higher_order_report, "motion-v1", "Exact repeated-prefix gate");
    require(repeat_gate.projected_bits.has_value() &&
                std::fabs(*repeat_gate.projected_bits) < 1.0e-12,
            "higher-order exact repetition triggers the zero gate");
    require(higher_order_report.diagnostic_minimum_bits.has_value() &&
                std::fabs(*higher_order_report.diagnostic_minimum_bits) <
                    1.0e-12,
            "higher-order exact repetition cannot accumulate mouse bits");

    std::vector<arborkdf::MouseEvent> prefixed_periodic;
    prefixed_periodic.reserve(8193U);
    prefixed_periodic.push_back(
        arborkdf::MouseEvent{0, 0, 7123456U, 0U});
    for (std::size_t index = 0U; index < 8192U; ++index) {
        prefixed_periodic.push_back(pattern[index % pattern.size()]);
    }
    const arborkdf::EntropyReport prefixed_report =
        arborkdf::analyze_mouse_events(prefixed_periodic);
    const auto& prefixed_gate = find_row(
        prefixed_report, "motion-v1", "Exact repeated-prefix gate");
    require(!prefixed_gate.projected_bits.has_value(),
            "synthetic first event disrupts the exact-prefix gate fixture");
    require(prefixed_report.diagnostic_minimum_bits.has_value() &&
                std::fabs(*prefixed_report.diagnostic_minimum_bits) < 1.0e-12,
            "compression gate catches a periodic tail after the first event");

    std::vector<arborkdf::MouseEvent> periodic_with_deviation =
        higher_order_periodic;
    periodic_with_deviation.push_back(
        arborkdf::MouseEvent{7, 7, 8123456U, 0U});
    const arborkdf::EntropyReport deviation_report =
        arborkdf::analyze_mouse_events(periodic_with_deviation);
    const auto& deviation_gate = find_row(
        deviation_report, "motion-v1", "Exact repeated-prefix gate");
    require(!deviation_gate.projected_bits.has_value(),
            "final deviation disrupts the exact-prefix gate fixture");
    require(deviation_report.diagnostic_minimum_bits.has_value() &&
                std::fabs(*deviation_report.diagnostic_minimum_bits) < 1.0e-12,
            "one deviation cannot erase the compression anomaly gate");
}

void test_random_like_and_statuses() {
    const std::vector<arborkdf::MouseEvent> events = random_like_events(512U);
    const arborkdf::EntropyReport report = arborkdf::analyze_mouse_events(events);
    const auto& shannon = find_row(report, "motion-v1", "Shannon entropy");
    const auto& mcv =
        find_row(report, "motion-v1", "MCV min-entropy (Wilson upper)");
    const auto& renyi =
        find_row(report, "motion-v1", "Renyi-2 collision entropy");
    const auto& compression =
        find_row(report, "motion-v1", "Raw DEFLATE compressed size/ratio");
    require(shannon.available && shannon.bits_per_symbol.has_value() &&
                *shannon.bits_per_symbol > 4.0,
            "random-like Shannon diagnostic");
    require(mcv.available && mcv.role == arborkdf::EntropyEstimateRole::minimum_candidate,
            "MCV is eligible for minimum");
    require(renyi.available &&
                renyi.role == arborkdf::EntropyEstimateRole::descriptive,
            "Renyi-2 is excluded from minimum");
    require(compression.available &&
                compression.role == arborkdf::EntropyEstimateRole::compression_only &&
                compression.status.find("not an entropy estimate") != std::string::npos,
            "compression is never called entropy");

    const arborkdf::EntropyReport short_report =
        arborkdf::analyze_mouse_events(constant_events(8U));
    const auto& short_mcv =
        find_row(short_report, "motion-v1", "MCV min-entropy (Wilson upper)");
    const auto& short_markov =
        find_row(short_report,
                 "motion-v1",
                 "First-order transition min-entropy");
    require(!short_mcv.available &&
                short_mcv.status.find("need at least 32") != std::string::npos,
            "MCV reports minimum sample requirement");
    require(!short_markov.available &&
                short_markov.status.find("need at least 128") != std::string::npos,
            "Markov reports minimum sample requirement");
    require(!short_report.diagnostic_minimum_bits.has_value(),
            "descriptive rows do not create a diagnostic minimum");

    const arborkdf::EntropyReport binary_report =
        arborkdf::analyze_mouse_events(binary_random_like_events(8192U));
    require(binary_report.diagnostic_minimum_bits.has_value() &&
                *binary_report.diagnostic_minimum_bits > 512.0,
            "unpredictable-looking binary marginals are not zeroed merely "
            "because their alphabet compresses");
}

void test_report_policy() {
    const arborkdf::EntropyReport report =
        arborkdf::analyze_mouse_events(constant_events(256U));
    require(report.mouse_security_credit_bits == 0.0,
            "mouse security credit is always zero");
    const std::string text = arborkdf::format_entropy_report(report);
    require(text.find("Mouse estimator diagnostics") != std::string::npos,
            "mouse report heading");
    require(text.find("Not source validation") != std::string::npos,
            "report validation disclaimer");
    require(text.find("no average is used") != std::string::npos,
            "report explicitly avoids averaging");
    require(text.find("DEFLATE") != std::string::npos,
            "compression diagnostic is visible");
    require(text.find("Distinct motion/timing pairs") != std::string::npos &&
                text.find("Repeated symbolic observations") != std::string::npos,
            "observed and repeated-symbol counts are shown separately");
    require(maximum_line_width(text) <= 79U,
            "mouse table and notes fit narrow terminals");

    arborkdf::EntropyReport maximum_progress{};
    maximum_progress.event_count = 1000000U;
    maximum_progress.distinct_symbol_pair_count = 65536U;
    maximum_progress.diagnostic_minimum_bits = 8000000.0;
    const std::string long_progress =
        arborkdf::format_mouse_progress_line(maximum_progress);
    require(long_progress.size() == 79U && long_progress.front() == '\r',
            "worst-case live progress is padded to 78 visible columns");
    maximum_progress.diagnostic_minimum_bits = 0.0;
    const std::string short_progress =
        arborkdf::format_mouse_progress_line(maximum_progress);
    require(short_progress.size() == long_progress.size(),
            "shorter progress updates overwrite stale trailing characters");

    bool malformed_report_rejected = false;
    try {
        arborkdf::EntropyReport malformed{};
        malformed.event_count = 1U;
        malformed.distinct_symbol_pair_count = 2U;
        static_cast<void>(arborkdf::format_entropy_report(malformed));
    } catch (const arborkdf::Error&) {
        malformed_report_rejected = true;
    }
    require(malformed_report_rejected,
            "malformed distinct-pair count is rejected before subtraction");
}

void test_os_sizing_policy() {
    require(arborkdf::required_os_random_bytes(std::nullopt) == 64U,
            "unavailable mouse diagnostic uses 512 OS input bits");
    require(arborkdf::required_os_random_bytes(0.0) == 64U,
            "zero mouse diagnostic uses 512 OS input bits");
    require(arborkdf::required_os_random_bytes(512.0) == 64U,
            "512 mouse diagnostic bits use 64 OS bytes");
    require(arborkdf::required_os_random_bytes(512.001) == 65U,
            "mouse diagnostic is rounded up to a whole OS byte");
    require(arborkdf::required_os_random_bytes(520.0) == 65U,
            "byte-aligned mouse diagnostic is exactly matched");
    require(arborkdf::required_os_random_bytes(521.0) == 66U,
            "next partial byte rounds upward");

    for (const double invalid : {-1.0,
                                 std::numeric_limits<double>::infinity(),
                                 std::numeric_limits<double>::quiet_NaN()}) {
        bool rejected = false;
        try {
            static_cast<void>(arborkdf::required_os_random_bytes(invalid));
        } catch (const arborkdf::Error&) {
            rejected = true;
        }
        require(rejected, "invalid mouse diagnostic bit count rejected");
    }
    bool excessive_rejected = false;
    try {
        const double excessive =
            static_cast<double>(arborkdf::kMaximumOsRandomInputBytes) * 8.0 +
            1.0;
        static_cast<void>(arborkdf::required_os_random_bytes(excessive));
    } catch (const arborkdf::Error&) {
        excessive_rejected = true;
    }
    require(excessive_rejected, "excessive OS random input request rejected");
}

void test_conditioner_and_tables() {
    const std::vector<arborkdf::MouseEvent> events = constant_events(4U);
    const arborkdf::ConditionedRandomResult first =
        arborkdf::condition_random(events, "ArborKDF/test/masterkey", 32U);
    const arborkdf::ConditionedRandomResult second =
        arborkdf::condition_random(events, "ArborKDF/test/masterkey", 32U);
    require(first.bytes.size() == 32U && second.bytes.size() == 32U,
            "conditioner output size");
    require(first.bytes != second.bytes,
            "fresh /dev/urandom input changes conditioned output");
    require(first.diagnostics.os.path == "/dev/urandom" &&
                first.diagnostics.os.bytes_read == 64U &&
                first.diagnostics.os.input_bits == 512U,
            "conditioner reports exact minimum OS input");
    require(first.diagnostics.combined.os_policy_percent == 100.0 &&
                first.diagnostics.combined.mouse_policy_percent == 0.0,
            "unavailable mouse estimate has OS-only policy weighting");

    const std::string formatted =
        arborkdf::format_conditioning_diagnostics(first.diagnostics);
    require(formatted.find("OS randomness diagnostics") != std::string::npos,
            "OS diagnostics table heading");
    require(formatted.find("Mouse estimator diagnostics") != std::string::npos,
            "mouse diagnostics table heading");
    require(formatted.find("Combined conditioner diagnostics") !=
                std::string::npos,
            "combined diagnostics table heading");
    require(formatted.find("/dev/urandom") != std::string::npos,
            "OS source path is visible");
    require(maximum_line_width(formatted) <= 79U,
            "all diagnostic tables and notes fit narrow terminals");

    const arborkdf::ConditionedRandomResult below_threshold =
        arborkdf::condition_random(random_like_events(128U),
                                   "ArborKDF/test/below-threshold",
                                   32U);
    require(below_threshold.diagnostics.mouse.diagnostic_minimum_bits.has_value() &&
                *below_threshold.diagnostics.mouse.diagnostic_minimum_bits > 0.0 &&
                *below_threshold.diagnostics.mouse.diagnostic_minimum_bits < 512.0,
            "random-like 128-event fixture has a positive sub-512 diagnostic");
    require(below_threshold.diagnostics.os.bytes_read == 64U,
            "sub-512 diagnostic retains the 64-byte OS minimum");
    require(std::fabs(
                below_threshold.diagnostics.combined.mouse_policy_weight_bits -
                *below_threshold.diagnostics.mouse.diagnostic_minimum_bits) <
                1.0e-12,
            "sub-512 policy uses the unrounded mouse diagnostic");
    require(below_threshold.diagnostics.combined.os_policy_percent > 50.0 &&
                below_threshold.diagnostics.combined.os_policy_percent < 100.0,
            "sub-512 policy share is OS-majority rather than forced 50/50");

    const arborkdf::ConditionedRandomResult high_mouse =
        arborkdf::condition_random(random_like_events(8192U),
                                   "ArborKDF/test/high-mouse",
                                   32U);
    require(high_mouse.diagnostics.mouse.diagnostic_minimum_bits.has_value() &&
                *high_mouse.diagnostics.mouse.diagnostic_minimum_bits > 512.0,
            "high-mouse test fixture exceeds the OS minimum");
    require(high_mouse.diagnostics.os.bytes_read ==
                arborkdf::required_os_random_bytes(
                    high_mouse.diagnostics.mouse.diagnostic_minimum_bits),
            "actual OS read exactly matches the byte-rounded sizing policy");
    require(std::fabs(high_mouse.diagnostics.combined.os_policy_percent - 50.0) <
                    1.0e-12 &&
                std::fabs(
                    high_mouse.diagnostics.combined.mouse_policy_percent - 50.0) <
                    1.0e-12,
            "high mouse diagnostic uses exact 50/50 policy weighting");

    arborkdf::StreamingRandomConditioner streaming("ArborKDF/test/salt");
    for (const arborkdf::MouseEvent& event : events) {
        streaming.add_event(event);
    }
    require(streaming.event_count() == events.size(), "streaming event count");
    require(streaming.finish(48U).bytes.size() == 48U,
            "streaming output size");

    bool second_finish_rejected = false;
    try {
        static_cast<void>(streaming.finish(48U));
    } catch (const arborkdf::Error&) {
        second_finish_rejected = true;
    }
    require(second_finish_rejected, "second finalization rejected");

    bool empty_purpose_rejected = false;
    try {
        static_cast<void>(arborkdf::condition_random(events, "", 32U));
    } catch (const arborkdf::Error&) {
        empty_purpose_rejected = true;
    }
    require(empty_purpose_rejected, "empty purpose rejected");

    bool zero_output_rejected = false;
    try {
        static_cast<void>(
            arborkdf::condition_random(events, "ArborKDF/test/invalid", 0U));
    } catch (const arborkdf::Error&) {
        zero_output_rejected = true;
    }
    require(zero_output_rejected, "zero output rejected");

    bool excessive_output_rejected = false;
    try {
        static_cast<void>(arborkdf::condition_random(
            events,
            "ArborKDF/test/invalid",
            arborkdf::kMaximumConditionedOutputBytes + 1U));
    } catch (const arborkdf::Error&) {
        excessive_output_rejected = true;
    }
    require(excessive_output_rejected, "excessive output rejected");
}

}  // namespace

void run_entropy_tests() {
    test_symbolization_and_repeat_preservation();
    test_constant_and_alternating_diagnostics();
    test_random_like_and_statuses();
    test_report_policy();
    test_os_sizing_policy();
    test_conditioner_and_tables();
}
