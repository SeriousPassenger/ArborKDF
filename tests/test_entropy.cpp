#include "arborkdf/entropy.hpp"
#include "arborkdf/error.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
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
    const auto& constant_markov =
        find_row(constant, "motion-v1", "First-order Markov fitted path");
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

    std::vector<arborkdf::MouseEvent> alternating;
    alternating.reserve(256U);
    for (std::size_t index = 0U; index < 256U; ++index) {
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
        alternating_report, "motion-v1", "First-order Markov fitted path");
    require(alternating_mcv.bits_per_symbol.has_value() &&
                alternating_markov.bits_per_symbol.has_value(),
            "alternating estimates available");
    require(*alternating_markov.bits_per_symbol < *alternating_mcv.bits_per_symbol,
            "Markov diagnostic detects alternating predictability");
}

void test_random_like_and_statuses() {
    std::vector<arborkdf::MouseEvent> events;
    events.reserve(512U);
    std::uint32_t state = 0x9e3779b9U;
    for (std::size_t index = 0U; index < 512U; ++index) {
        state ^= state << 13U;
        state ^= state >> 17U;
        state ^= state << 5U;
        const std::int32_t dx = static_cast<std::int32_t>(state & 0x0fU) - 8;
        const std::int32_t dy =
            static_cast<std::int32_t>((state >> 4U) & 0x0fU) - 8;
        const std::uint64_t microseconds = 7000U + ((state >> 8U) & 0xffU);
        events.push_back(arborkdf::MouseEvent{dx, dy, microseconds * 1000U, 0U});
    }
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
        find_row(short_report, "motion-v1", "First-order Markov fitted path");
    require(!short_mcv.available &&
                short_mcv.status.find("need at least 32") != std::string::npos,
            "MCV reports minimum sample requirement");
    require(!short_markov.available &&
                short_markov.status.find("need at least 128") != std::string::npos,
            "Markov reports minimum sample requirement");
    require(!short_report.diagnostic_minimum_bits.has_value(),
            "descriptive rows do not create a diagnostic minimum");
}

void test_report_policy() {
    const arborkdf::EntropyReport report =
        arborkdf::analyze_mouse_events(constant_events(256U));
    require(report.mouse_security_credit_bits == 0.0,
            "mouse security credit is always zero");
    const std::string text = arborkdf::format_entropy_report(report);
    require(text.find("not a validation") != std::string::npos,
            "report validation disclaimer");
    require(text.find("No average was calculated.") != std::string::npos,
            "report explicitly avoids averaging");
    require(text.find("Mouse security credit: 0.000 bits") != std::string::npos,
            "formatted zero security credit");
    require(text.find("not an entropy estimate") != std::string::npos,
            "formatted compression warning");
    require(text.find("minimum=128") != std::string::npos,
            "formatted minimum sample requirement");
}

void test_conditioner() {
    const std::vector<arborkdf::MouseEvent> events = constant_events(4U);
    const arborkdf::Bytes first =
        arborkdf::condition_random(events, "ArborKDF/test/masterkey", 32U);
    const arborkdf::Bytes second =
        arborkdf::condition_random(events, "ArborKDF/test/masterkey", 32U);
    require(first.size() == 32U && second.size() == 32U,
            "conditioner output size");
    require(first != second, "fresh OS randomness changes conditioned output");

    arborkdf::StreamingRandomConditioner streaming("ArborKDF/test/salt");
    for (const arborkdf::MouseEvent& event : events) {
        streaming.add_event(event);
    }
    require(streaming.event_count() == events.size(), "streaming event count");
    require(streaming.finish(48U).size() == 48U, "streaming output size");

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
}

}  // namespace

void run_entropy_tests() {
    test_symbolization_and_repeat_preservation();
    test_constant_and_alternating_diagnostics();
    test_random_like_and_statuses();
    test_report_policy();
    test_conditioner();
}
