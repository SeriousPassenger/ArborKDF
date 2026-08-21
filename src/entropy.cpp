#include "arborkdf/entropy.hpp"

#include "arborkdf/error.hpp"
#include "arborkdf/openssl_context.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace arborkdf {
namespace {

constexpr std::size_t kMouseEventPayloadBytes = 20U;
constexpr std::size_t kMouseEventFrameBytes = 1U + kMouseEventPayloadBytes;
constexpr std::uint8_t kMouseEventTag = 0x01U;
constexpr std::uint8_t kMouseTranscriptEndTag = 0xffU;
constexpr std::size_t kShannonMinimumSamples = 2U;
constexpr std::size_t kMcvMinimumSamples = 32U;
constexpr std::size_t kRenyiMinimumSamples = 2U;
constexpr std::size_t kMarkovMinimumSamples = 128U;
constexpr std::size_t kDeflateMinimumSamples = 32U;
constexpr std::size_t kMarkovHorizon = 128U;
constexpr double kWilsonZ = 2.576;
constexpr double kMaximumSymbolBits = 8.0;
constexpr std::size_t kMaximumPurposeBytes = 4096U;

struct EvpMdDeleter final {
    void operator()(EVP_MD* value) const noexcept { EVP_MD_free(value); }
};

struct EvpMdCtxDeleter final {
    void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); }
};

class CleanseBytes final {
public:
    explicit CleanseBytes(Bytes& value) noexcept : value_(value) {}
    ~CleanseBytes() {
        if (!value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size());
        }
    }

    CleanseBytes(const CleanseBytes&) = delete;
    CleanseBytes& operator=(const CleanseBytes&) = delete;

private:
    Bytes& value_;
};

using UniqueMd = std::unique_ptr<EVP_MD, EvpMdDeleter>;
using UniqueMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

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

void append_u64(Bytes& destination, const std::uint64_t value) {
    for (unsigned int shift = 56U;; shift -= 8U) {
        destination.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        if (shift == 0U) {
            break;
        }
    }
}

void append_string(Bytes& destination, const std::string& value) {
    if (value.size() > static_cast<std::size_t>(
                           std::numeric_limits<std::uint32_t>::max())) {
        throw Error("framed string is too long");
    }
    append_u32(destination, static_cast<std::uint32_t>(value.size()));
    destination.insert(destination.end(), value.begin(), value.end());
}

[[nodiscard]] Bytes transcript_header() {
    Bytes header;
    append_string(header, "ArborKDF/mouse-transcript/v1");
    append_u32(header, kMouseTranscriptVersion);
    append_u32(header, static_cast<std::uint32_t>(kMouseEventPayloadBytes));
    return header;
}

[[nodiscard]] Bytes frame_mouse_event(const MouseEvent& event) {
    Bytes frame;
    frame.reserve(kMouseEventFrameBytes);
    frame.push_back(kMouseEventTag);
    append_u32(frame, static_cast<std::uint32_t>(event.dx));
    append_u32(frame, static_cast<std::uint32_t>(event.dy));
    append_u64(frame, event.delta_nanoseconds);
    append_u32(frame, event.flags);
    return frame;
}

[[nodiscard]] Bytes transcript_trailer(const std::uint64_t event_count) {
    Bytes trailer;
    trailer.reserve(9U);
    trailer.push_back(kMouseTranscriptEndTag);
    append_u64(trailer, event_count);
    return trailer;
}

[[nodiscard]] std::uint8_t signed_nibble(const std::int32_t value) noexcept {
    const std::int32_t clipped = std::clamp(value, -8, 7);
    return static_cast<std::uint8_t>(static_cast<std::uint32_t>(clipped) & 0x0fU);
}

[[nodiscard]] std::array<std::size_t, 256U> frequencies(const Bytes& symbols) {
    std::array<std::size_t, 256U> counts{};
    for (const std::uint8_t symbol : symbols) {
        ++counts[symbol];
    }
    return counts;
}

[[nodiscard]] double clamp_symbol_bits(const double value) noexcept {
    if (!(value > 0.0)) {
        return 0.0;
    }
    return std::min(value, kMaximumSymbolBits);
}

[[nodiscard]] double shannon_entropy(const Bytes& symbols) {
    const auto counts = frequencies(symbols);
    const double count = static_cast<double>(symbols.size());
    double result = 0.0;
    for (const std::size_t frequency : counts) {
        if (frequency == 0U) {
            continue;
        }
        const double probability = static_cast<double>(frequency) / count;
        result -= probability * std::log2(probability);
    }
    return clamp_symbol_bits(result);
}

[[nodiscard]] double wilson_upper_probability(const std::size_t successes,
                                              const std::size_t trials) {
    const double n = static_cast<double>(trials);
    const double proportion = static_cast<double>(successes) / n;
    const double z_squared = kWilsonZ * kWilsonZ;
    const double denominator = 1.0 + (z_squared / n);
    const double center = (proportion + (z_squared / (2.0 * n))) / denominator;
    const double radicand = (proportion * (1.0 - proportion) / n) +
                            (z_squared / (4.0 * n * n));
    const double margin = (kWilsonZ / denominator) * std::sqrt(radicand);
    return std::clamp(center + margin, 0.0, 1.0);
}

[[nodiscard]] double mcv_min_entropy(const Bytes& symbols) {
    const auto counts = frequencies(symbols);
    const std::size_t most_common =
        *std::max_element(counts.begin(), counts.end());
    const double probability = wilson_upper_probability(most_common, symbols.size());
    if (probability >= 1.0) {
        return 0.0;
    }
    return clamp_symbol_bits(-std::log2(probability));
}

[[nodiscard]] double renyi2_entropy(const Bytes& symbols) {
    const auto counts = frequencies(symbols);
    const double count = static_cast<double>(symbols.size());
    double collision_probability = 0.0;
    for (const std::size_t frequency : counts) {
        const double probability = static_cast<double>(frequency) / count;
        collision_probability += probability * probability;
    }
    return clamp_symbol_bits(-std::log2(collision_probability));
}

[[nodiscard]] double fitted_markov_path_entropy(const Bytes& symbols) {
    constexpr std::size_t kAlphabetSize = 256U;
    const auto counts = frequencies(symbols);
    std::vector<std::size_t> transitions(kAlphabetSize * kAlphabetSize, 0U);
    std::array<std::size_t, kAlphabetSize> row_counts{};
    for (std::size_t index = 1U; index < symbols.size(); ++index) {
        const std::size_t from = symbols[index - 1U];
        const std::size_t to = symbols[index];
        ++transitions[(from * kAlphabetSize) + to];
        ++row_counts[from];
    }

    const double negative_infinity = -std::numeric_limits<double>::infinity();
    std::array<double, kAlphabetSize> path{};
    std::array<double, kAlphabetSize> next{};
    path.fill(negative_infinity);
    next.fill(negative_infinity);
    const double sample_count = static_cast<double>(symbols.size());
    for (std::size_t state = 0U; state < kAlphabetSize; ++state) {
        if (counts[state] != 0U) {
            path[state] = std::log(static_cast<double>(counts[state]) / sample_count);
        }
    }

    const std::size_t horizon = std::min(kMarkovHorizon, symbols.size());
    for (std::size_t step = 1U; step < horizon; ++step) {
        next.fill(negative_infinity);
        for (std::size_t from = 0U; from < kAlphabetSize; ++from) {
            if (!std::isfinite(path[from]) || row_counts[from] == 0U) {
                continue;
            }
            const double row_count = static_cast<double>(row_counts[from]);
            for (std::size_t to = 0U; to < kAlphabetSize; ++to) {
                const std::size_t transition =
                    transitions[(from * kAlphabetSize) + to];
                if (transition == 0U) {
                    continue;
                }
                const double candidate =
                    path[from] + std::log(static_cast<double>(transition) / row_count);
                next[to] = std::max(next[to], candidate);
            }
        }
        path = next;
    }

    const double maximum_log_probability =
        *std::max_element(path.begin(), path.end());
    if (!std::isfinite(maximum_log_probability)) {
        return 0.0;
    }
    const double bits = -maximum_log_probability / std::log(2.0);
    return clamp_symbol_bits(bits / static_cast<double>(horizon));
}

struct DeflateResult final {
    std::size_t bytes{};
    double ratio{};
};

[[nodiscard]] DeflateResult raw_deflate_size(const Bytes& symbols) {
    z_stream stream{};
    const int initialization = deflateInit2(&stream,
                                            Z_BEST_COMPRESSION,
                                            Z_DEFLATED,
                                            -MAX_WBITS,
                                            8,
                                            Z_DEFAULT_STRATEGY);
    if (initialization != Z_OK) {
        throw Error("raw DEFLATE initialization failed");
    }

    struct EndDeflate final {
        z_stream* stream;
        ~EndDeflate() { static_cast<void>(deflateEnd(stream)); }
    } cleanup{&stream};

    constexpr std::size_t kOutputChunkBytes = 16384U;
    std::array<unsigned char, kOutputChunkBytes> output{};
    std::size_t input_offset = 0U;
    std::size_t compressed_bytes = 0U;
    int result = Z_OK;
    while (result != Z_STREAM_END) {
        if (stream.avail_in == 0U && input_offset < symbols.size()) {
            const std::size_t remaining = symbols.size() - input_offset;
            const std::size_t chunk = std::min(
                remaining,
                static_cast<std::size_t>(std::numeric_limits<uInt>::max()));
            stream.next_in = const_cast<Bytef*>(
                reinterpret_cast<const Bytef*>(symbols.data() + input_offset));
            stream.avail_in = static_cast<uInt>(chunk);
            input_offset += chunk;
        }

        const int flush = input_offset == symbols.size() ? Z_FINISH : Z_NO_FLUSH;
        stream.next_out = output.data();
        stream.avail_out = static_cast<uInt>(output.size());
        result = deflate(&stream, flush);
        if (result != Z_OK && result != Z_STREAM_END) {
            throw Error("raw DEFLATE compression failed");
        }
        const std::size_t produced = output.size() - stream.avail_out;
        if (compressed_bytes > std::numeric_limits<std::size_t>::max() - produced) {
            throw Error("raw DEFLATE size overflow");
        }
        compressed_bytes += produced;
    }

    return DeflateResult{compressed_bytes,
                         static_cast<double>(compressed_bytes) /
                             static_cast<double>(symbols.size())};
}

[[nodiscard]] std::string unavailable_status(const std::size_t minimum,
                                             const std::size_t actual) {
    return "N/A: need at least " + std::to_string(minimum) +
           " samples; got " + std::to_string(actual);
}

void add_numeric_row(std::vector<EntropyEstimateRow>& rows,
                     const std::string& stream,
                     const std::string& method,
                     const EntropyEstimateRole role,
                     const Bytes& symbols,
                     const std::size_t minimum_samples,
                     const std::string& ready_status,
                     double (*estimate)(const Bytes&)) {
    EntropyEstimateRow row{};
    row.stream = stream;
    row.method = method;
    row.role = role;
    row.sample_count = symbols.size();
    row.minimum_samples = minimum_samples;
    if (symbols.size() < minimum_samples) {
        row.status = unavailable_status(minimum_samples, symbols.size());
        rows.push_back(std::move(row));
        return;
    }
    const double bits_per_symbol = estimate(symbols);
    row.available = true;
    row.bits_per_symbol = bits_per_symbol;
    row.projected_bits = bits_per_symbol * static_cast<double>(symbols.size());
    row.status = ready_status;
    rows.push_back(std::move(row));
}

void add_deflate_row(std::vector<EntropyEstimateRow>& rows,
                     const std::string& stream,
                     const Bytes& symbols) {
    EntropyEstimateRow row{};
    row.stream = stream;
    row.method = "Raw DEFLATE compressed size/ratio";
    row.role = EntropyEstimateRole::compression_only;
    row.sample_count = symbols.size();
    row.minimum_samples = kDeflateMinimumSamples;
    if (symbols.size() < kDeflateMinimumSamples) {
        row.status = unavailable_status(kDeflateMinimumSamples, symbols.size()) +
                     "; not an entropy estimate";
        rows.push_back(std::move(row));
        return;
    }
    const DeflateResult result = raw_deflate_size(symbols);
    row.available = true;
    row.compressed_bytes = result.bytes;
    row.compression_ratio = result.ratio;
    row.status = "ready; compressibility diagnostic only; not an entropy estimate";
    rows.push_back(std::move(row));
}

void add_stream_rows(std::vector<EntropyEstimateRow>& rows,
                     const std::string& stream,
                     const Bytes& symbols) {
    add_numeric_row(rows,
                    stream,
                    "Shannon entropy",
                    EntropyEstimateRole::descriptive,
                    symbols,
                    kShannonMinimumSamples,
                    "ready; descriptive only; excluded from diagnostic minimum",
                    shannon_entropy);
    add_numeric_row(rows,
                    stream,
                    "MCV min-entropy (Wilson upper)",
                    EntropyEstimateRole::minimum_candidate,
                    symbols,
                    kMcvMinimumSamples,
                    "ready; 99% Wilson upper probability bound; diagnostic only",
                    mcv_min_entropy);
    add_numeric_row(rows,
                    stream,
                    "Renyi-2 collision entropy",
                    EntropyEstimateRole::descriptive,
                    symbols,
                    kRenyiMinimumSamples,
                    "ready; collision entropy is not a min-entropy lower bound; excluded",
                    renyi2_entropy);
    add_numeric_row(rows,
                    stream,
                    "First-order Markov fitted path",
                    EntropyEstimateRole::minimum_candidate,
                    symbols,
                    kMarkovMinimumSamples,
                    "ready; fitted 128-symbol path model; diagnostic only",
                    fitted_markov_path_entropy);
    add_deflate_row(rows, stream, symbols);
}

[[nodiscard]] std::string role_text(const EntropyEstimateRole role) {
    switch (role) {
        case EntropyEstimateRole::descriptive:
            return "descriptive";
        case EntropyEstimateRole::minimum_candidate:
            return "minimum candidate";
        case EntropyEstimateRole::compression_only:
            return "compression only";
    }
    return "unknown";
}

void digest_update(EVP_MD_CTX* const context, const Bytes& bytes) {
    if (!bytes.empty() && EVP_DigestUpdate(context, bytes.data(), bytes.size()) != 1) {
        throw Error(openssl_error("update SHAKE-256 conditioner"));
    }
}

}  // namespace

Bytes frame_mouse_transcript(const std::vector<MouseEvent>& events) {
    Bytes framed = transcript_header();
    const std::size_t trailer_size = 9U;
    if (events.size() >
        (std::numeric_limits<std::size_t>::max() - framed.size() - trailer_size) /
            kMouseEventFrameBytes) {
        throw Error("mouse transcript is too large");
    }
    framed.reserve(framed.size() + (events.size() * kMouseEventFrameBytes) +
                   trailer_size);
    for (const MouseEvent& event : events) {
        const Bytes event_frame = frame_mouse_event(event);
        framed.insert(framed.end(), event_frame.begin(), event_frame.end());
    }
    const Bytes trailer = transcript_trailer(static_cast<std::uint64_t>(events.size()));
    framed.insert(framed.end(), trailer.begin(), trailer.end());
    return framed;
}

std::uint8_t motion_symbol(const MouseEvent& event) noexcept {
    return static_cast<std::uint8_t>((signed_nibble(event.dx) << 4U) |
                                     signed_nibble(event.dy));
}

std::uint8_t timing_symbol(const MouseEvent& event) noexcept {
    const std::uint64_t quanta =
        event.delta_nanoseconds / kTimingSymbolQuantumNanoseconds;
    return static_cast<std::uint8_t>(quanta & 0xffU);
}

EntropyReport analyze_mouse_events(const std::vector<MouseEvent>& events) {
    Bytes motion;
    Bytes timing;
    motion.reserve(events.size());
    timing.reserve(events.size());
    for (const MouseEvent& event : events) {
        motion.push_back(motion_symbol(event));
        timing.push_back(timing_symbol(event));
    }

    EntropyReport report{};
    report.event_count = events.size();
    report.mouse_security_credit_bits = 0.0;
    report.disclaimer =
        "Live diagnostics only: not entropy-source validation, not a security "
        "entropy claim, and no average is calculated.";
    report.rows.reserve(10U);
    add_stream_rows(report.rows, "motion-v1", motion);
    add_stream_rows(report.rows, "timing-v1", timing);

    for (const EntropyEstimateRow& row : report.rows) {
        if (!row.available || row.role != EntropyEstimateRole::minimum_candidate ||
            !row.projected_bits.has_value()) {
            continue;
        }
        if (!report.diagnostic_minimum_bits.has_value() ||
            *row.projected_bits < *report.diagnostic_minimum_bits) {
            report.diagnostic_minimum_bits = row.projected_bits;
        }
    }
    return report;
}

std::string format_entropy_report(const EntropyReport& report) {
    std::ostringstream output;
    output << "Mouse entropy diagnostics (not a validation)\n";
    output << "Events: " << report.event_count << '\n';
    output << report.disclaimer << '\n';
    output << std::fixed << std::setprecision(3);
    for (const EntropyEstimateRow& row : report.rows) {
        output << row.stream << " | " << row.method << " | " << role_text(row.role)
               << " | samples=" << row.sample_count
               << " | minimum=" << row.minimum_samples << " | ";
        if (row.bits_per_symbol.has_value()) {
            output << "bits/symbol=" << *row.bits_per_symbol << " | ";
        } else {
            output << "bits/symbol=N/A | ";
        }
        if (row.projected_bits.has_value()) {
            output << "projected=" << *row.projected_bits << " bits | ";
        } else {
            output << "projected=N/A | ";
        }
        if (row.compressed_bytes.has_value() && row.compression_ratio.has_value()) {
            output << "compressed=" << *row.compressed_bytes
                   << " bytes, ratio=" << *row.compression_ratio << " | ";
        }
        output << row.status << '\n';
    }
    if (report.diagnostic_minimum_bits.has_value()) {
        output << "Diagnostic minimum (never averaged): "
               << *report.diagnostic_minimum_bits << " bits\n";
    } else {
        output << "Diagnostic minimum: N/A; insufficient samples\n";
    }
    output << "No average was calculated.\n";
    output << "Mouse security credit: " << report.mouse_security_credit_bits
           << " bits\n";
    return output.str();
}

class StreamingRandomConditioner::Impl final {
public:
    explicit Impl(const std::string& purpose)
        : md_(EVP_MD_fetch(openssl_context(),
                           "SHAKE-256",
                           kOpenSslDefaultProviderQuery)),
          context_(EVP_MD_CTX_new()) {
        if (purpose.empty()) {
            throw Error("conditioner purpose must not be empty");
        }
        if (purpose.size() > kMaximumPurposeBytes) {
            throw Error("conditioner purpose is too long");
        }
        if (!md_) {
            throw Error(openssl_error("fetch SHAKE-256"));
        }
        if (!context_) {
            throw Error(openssl_error("allocate SHAKE-256 context"));
        }
        if (EVP_DigestInit_ex2(context_.get(), md_.get(), nullptr) != 1) {
            throw Error(openssl_error("initialize SHAKE-256 conditioner"));
        }

        Bytes conditioner_header;
        append_string(conditioner_header, "ArborKDF/random-conditioner/v1");
        append_u32(conditioner_header, 1U);
        append_string(conditioner_header, purpose);
        digest_update(context_.get(), conditioner_header);

        const Bytes header = transcript_header();
        digest_update(context_.get(), header);
    }

    void add_event(const MouseEvent& event) {
        ensure_active();
        if (event_count_ == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("mouse event counter exhausted");
        }
        const Bytes frame = frame_mouse_event(event);
        digest_update(context_.get(), frame);
        ++event_count_;
    }

    [[nodiscard]] Bytes finish(const std::size_t output_bytes) {
        ensure_active();
        if (output_bytes == 0U || output_bytes > kMaximumConditionedOutputBytes) {
            throw Error("conditioned output length must be between 1 and " +
                        std::to_string(kMaximumConditionedOutputBytes) + " bytes");
        }
        finished_ = true;
        const Bytes trailer = transcript_trailer(event_count_);
        digest_update(context_.get(), trailer);
        Bytes mouse_stream(output_bytes);
        const CleanseBytes cleanse_mouse_stream(mouse_stream);
        if (EVP_DigestFinalXOF(
                context_.get(), mouse_stream.data(), mouse_stream.size()) != 1) {
            throw Error(openssl_error("finalize SHAKE-256 conditioner"));
        }

        Bytes output(output_bytes);
        if (RAND_priv_bytes_ex(openssl_context(),
                               output.data(),
                               output.size(),
                               256U) != 1) {
            OPENSSL_cleanse(output.data(), output.size());
            throw Error(openssl_error("obtain operating-system private randomness"));
        }
        for (std::size_t index = 0U; index < output.size(); ++index) {
            output[index] = static_cast<std::uint8_t>(
                output[index] ^ mouse_stream[index]);
        }
        return output;
    }

    [[nodiscard]] std::size_t event_count() const noexcept {
        if (event_count_ > static_cast<std::uint64_t>(
                               std::numeric_limits<std::size_t>::max())) {
            return std::numeric_limits<std::size_t>::max();
        }
        return static_cast<std::size_t>(event_count_);
    }

private:
    void ensure_active() const {
        if (finished_) {
            throw Error("random conditioner has already been finalized");
        }
    }

    UniqueMd md_;
    UniqueMdCtx context_;
    std::uint64_t event_count_{};
    bool finished_{};
};

StreamingRandomConditioner::StreamingRandomConditioner(const std::string& purpose)
    : implementation_(std::make_unique<Impl>(purpose)) {}

StreamingRandomConditioner::~StreamingRandomConditioner() = default;

StreamingRandomConditioner::StreamingRandomConditioner(
    StreamingRandomConditioner&& other) noexcept = default;

StreamingRandomConditioner& StreamingRandomConditioner::operator=(
    StreamingRandomConditioner&& other) noexcept = default;

void StreamingRandomConditioner::add_event(const MouseEvent& event) {
    if (!implementation_) {
        throw Error("random conditioner is in a moved-from state");
    }
    implementation_->add_event(event);
}

Bytes StreamingRandomConditioner::finish(const std::size_t output_bytes) {
    if (!implementation_) {
        throw Error("random conditioner is in a moved-from state");
    }
    return implementation_->finish(output_bytes);
}

std::size_t StreamingRandomConditioner::event_count() const noexcept {
    return implementation_ ? implementation_->event_count() : 0U;
}

Bytes condition_random(const std::vector<MouseEvent>& events,
                       const std::string& purpose,
                       const std::size_t output_bytes) {
    StreamingRandomConditioner conditioner(purpose);
    for (const MouseEvent& event : events) {
        conditioner.add_event(event);
    }
    return conditioner.finish(output_bytes);
}

}  // namespace arborkdf
