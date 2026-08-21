#include "arborkdf/entropy.hpp"

#include "arborkdf/error.hpp"
#include "arborkdf/openssl_context.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef __linux__
#error "ArborKDF randomness is not implemented yet in this version on non-Linux systems"
#endif

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

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
constexpr std::size_t kRepetitionGateMinimumSamples = 32U;
constexpr std::size_t kDeflateMinimumSamples = 32U;
constexpr double kStructuralCompressionGateFraction = 0.25;
constexpr double kWilsonZ = 2.576;
constexpr double kMaximumSymbolBits = 8.0;
constexpr std::size_t kMaximumPurposeBytes = 4096U;
constexpr std::uint32_t kRandomConditionerVersion = 2U;
constexpr const char* kLinuxRandomSource = "Linux kernel CSPRNG";
constexpr const char* kLinuxRandomPath = "/dev/urandom";

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
        if (active_ && !value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size());
        }
    }

    CleanseBytes(const CleanseBytes&) = delete;
    CleanseBytes& operator=(const CleanseBytes&) = delete;

    void dismiss() noexcept { active_ = false; }

private:
    Bytes& value_;
    bool active_{true};
};

class CleanseSizes final {
public:
    explicit CleanseSizes(std::vector<std::size_t>& value) noexcept
        : value_(value) {}
    ~CleanseSizes() {
        if (!value_.empty()) {
            OPENSSL_cleanse(value_.data(), value_.size() * sizeof(value_[0]));
        }
    }

    CleanseSizes(const CleanseSizes&) = delete;
    CleanseSizes& operator=(const CleanseSizes&) = delete;

private:
    std::vector<std::size_t>& value_;
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

// Empirical average conditional min-entropy for a first-order transition
// model. For each prior symbol, the Wilson upper bound of its most likely next
// symbol is used as a conservative guessing probability. A deterministic
// cycle therefore has probability one and a zero entropy rate, regardless of
// transcript length.
[[nodiscard]] double first_order_transition_min_entropy(const Bytes& symbols) {
    constexpr std::size_t kAlphabetSize = 256U;
    std::vector<std::size_t> transitions(kAlphabetSize * kAlphabetSize, 0U);
    const CleanseSizes cleanse_transitions(transitions);
    std::array<std::size_t, kAlphabetSize> row_counts{};
    for (std::size_t index = 1U; index < symbols.size(); ++index) {
        const std::size_t from = symbols[index - 1U];
        const std::size_t to = symbols[index];
        ++transitions[(from * kAlphabetSize) + to];
        ++row_counts[from];
    }

    const std::size_t transition_count = symbols.size() - 1U;
    if (transition_count == 0U) {
        return 0.0;
    }
    double upper_guess_probability = 0.0;
    for (std::size_t from = 0U; from < kAlphabetSize; ++from) {
        if (row_counts[from] == 0U) {
            continue;
        }
        const auto row_begin = transitions.begin() +
                               static_cast<std::ptrdiff_t>(from * kAlphabetSize);
        const std::size_t most_common_next = *std::max_element(
            row_begin,
            row_begin + static_cast<std::ptrdiff_t>(kAlphabetSize));
        const double row_weight = static_cast<double>(row_counts[from]) /
                                  static_cast<double>(transition_count);
        upper_guess_probability +=
            row_weight * wilson_upper_probability(most_common_next,
                                                   row_counts[from]);
    }
    upper_guess_probability = std::clamp(upper_guess_probability, 0.0, 1.0);
    if (upper_guess_probability >= 1.0) {
        return 0.0;
    }
    return clamp_symbol_bits(-std::log2(upper_guess_probability));
}

// Finds an exact prefix period that appears at least twice. This is an anomaly
// gate, not an entropy estimator: detecting repetition can safely force the
// diagnostic minimum to zero, while failing to detect it provides no positive
// entropy evidence. The prefix-function implementation is linear time.
[[nodiscard]] std::optional<std::size_t> exact_repeated_prefix_period(
    const Bytes& symbols) {
    if (symbols.size() < 2U) {
        return std::nullopt;
    }
    std::vector<std::size_t> prefix(symbols.size(), 0U);
    const CleanseSizes cleanse_prefix(prefix);
    for (std::size_t index = 1U; index < symbols.size(); ++index) {
        std::size_t matched = prefix[index - 1U];
        while (matched != 0U && symbols[index] != symbols[matched]) {
            matched = prefix[matched - 1U];
        }
        if (symbols[index] == symbols[matched]) {
            ++matched;
        }
        prefix[index] = matched;
    }
    const std::size_t period = symbols.size() - prefix.back();
    if (period > symbols.size() / 2U) {
        return std::nullopt;
    }
    return period;
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

void add_markov_row(std::vector<EntropyEstimateRow>& rows,
                    const std::string& stream,
                    const Bytes& symbols) {
    EntropyEstimateRow row{};
    row.stream = stream;
    row.method = "First-order transition min-entropy";
    row.role = EntropyEstimateRole::minimum_candidate;
    row.sample_count = symbols.size();
    row.minimum_samples = kMarkovMinimumSamples;
    if (symbols.size() < kMarkovMinimumSamples) {
        row.status = unavailable_status(kMarkovMinimumSamples, symbols.size());
        rows.push_back(std::move(row));
        return;
    }
    const double bits_per_transition =
        first_order_transition_min_entropy(symbols);
    row.available = true;
    row.bits_per_symbol = bits_per_transition;
    row.projected_bits = bits_per_transition *
                         static_cast<double>(symbols.size() - 1U);
    row.status =
        "ready; Wilson-bounded first-order guessing model; diagnostic only";
    rows.push_back(std::move(row));
}

void add_repetition_gate_row(std::vector<EntropyEstimateRow>& rows,
                             const std::string& stream,
                             const Bytes& symbols) {
    EntropyEstimateRow row{};
    row.stream = stream;
    row.method = "Exact repeated-prefix gate";
    row.role = EntropyEstimateRole::minimum_candidate;
    row.sample_count = symbols.size();
    row.minimum_samples = kRepetitionGateMinimumSamples;
    if (symbols.size() < kRepetitionGateMinimumSamples) {
        row.status = unavailable_status(kRepetitionGateMinimumSamples,
                                        symbols.size());
        rows.push_back(std::move(row));
        return;
    }
    row.available = true;
    const std::optional<std::size_t> period =
        exact_repeated_prefix_period(symbols);
    if (period.has_value()) {
        row.bits_per_symbol = 0.0;
        row.projected_bits = 0.0;
        row.status = "exact repeated prefix detected; period " +
                     std::to_string(*period) +
                     "; diagnostic minimum forced to zero";
    } else {
        row.status =
            "no exact repeated prefix detected; gate adds no entropy estimate";
    }
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
    row.status =
        "ready; not an entropy estimate; a rate <= 25% of the marginal "
        "Shannon rate only triggers a zero structural-anomaly gate";
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
    add_markov_row(rows, stream, symbols);
    add_repetition_gate_row(rows, stream, symbols);
    add_deflate_row(rows, stream, symbols);
}

void digest_update(EVP_MD_CTX* const context, const Bytes& bytes) {
    if (!bytes.empty() && EVP_DigestUpdate(context, bytes.data(), bytes.size()) != 1) {
        throw Error(openssl_error("update SHAKE-256 conditioner"));
    }
}

class FileDescriptor final {
public:
    explicit FileDescriptor(const int value) noexcept : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) {
            static_cast<void>(::close(value_));
        }
    }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    [[nodiscard]] int get() const noexcept { return value_; }

private:
    int value_;
};

[[nodiscard]] std::string system_error(const std::string& operation,
                                       const int error_number) {
    return operation + ": " + std::string(std::strerror(error_number));
}

void wait_for_linux_csprng_initialization() {
    std::uint8_t readiness_byte = 0U;
    for (;;) {
        const ssize_t result = ::getrandom(&readiness_byte, 1U, 0U);
        if (result == 1) {
            OPENSSL_cleanse(&readiness_byte, sizeof(readiness_byte));
            return;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            const int error_number = errno;
            OPENSSL_cleanse(&readiness_byte, sizeof(readiness_byte));
            throw Error(system_error(
                "wait for Linux kernel CSPRNG initialization", error_number));
        }
        OPENSSL_cleanse(&readiness_byte, sizeof(readiness_byte));
        throw Error(
            "wait for Linux kernel CSPRNG initialization: unexpected short read");
    }
}

[[nodiscard]] Bytes read_linux_urandom(const std::size_t byte_count) {
    // A blocking getrandom(2) read does not complete before the kernel CSPRNG
    // is initialized. The byte is discarded; all counted conditioner input is
    // still read directly from /dev/urandom as required by this version.
    wait_for_linux_csprng_initialization();
    Bytes random(byte_count);
    CleanseBytes cleanse_random(random);

    const int descriptor = ::open(kLinuxRandomPath,
                                  O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
    if (descriptor < 0) {
        const int error_number = errno;
        throw Error(system_error("open /dev/urandom", error_number));
    }
    const FileDescriptor close_descriptor(descriptor);

    struct stat status {};
    if (::fstat(close_descriptor.get(), &status) != 0) {
        const int error_number = errno;
        throw Error(system_error("inspect /dev/urandom", error_number));
    }
    if (!S_ISCHR(status.st_mode)) {
        throw Error("/dev/urandom is not a character device");
    }

    std::size_t offset = 0U;
    while (offset < random.size()) {
        const std::size_t remaining = random.size() - offset;
        const std::size_t request = std::min(
            remaining,
            static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const ssize_t result = ::read(close_descriptor.get(),
                                      random.data() + offset,
                                      request);
        if (result < 0) {
            const int error_number = errno;
            if (error_number == EINTR) {
                continue;
            }
            throw Error(system_error("read /dev/urandom", error_number));
        }
        if (result == 0) {
            throw Error("unexpected end of /dev/urandom");
        }
        offset += static_cast<std::size_t>(result);
    }

    cleanse_random.dismiss();
    return random;
}

[[nodiscard]] EntropyReport analyze_symbol_streams(const Bytes& motion,
                                                   const Bytes& timing) {
    if (motion.size() != timing.size()) {
        throw Error("mouse diagnostic symbol streams have inconsistent lengths");
    }
    EntropyReport report{};
    report.event_count = motion.size();
    Bytes seen_symbol_pairs(65536U, UINT8_C(0));
    const CleanseBytes cleanse_seen_symbol_pairs(seen_symbol_pairs);
    for (std::size_t index = 0U; index < motion.size(); ++index) {
        const std::size_t pair =
            (static_cast<std::size_t>(motion[index]) << 8U) |
            static_cast<std::size_t>(timing[index]);
        if (seen_symbol_pairs[pair] == UINT8_C(0)) {
            seen_symbol_pairs[pair] = UINT8_C(1);
            ++report.distinct_symbol_pair_count;
        }
    }
    report.mouse_security_credit_bits = 0.0;
    report.disclaimer =
        "Not source validation, certified entropy, or a security-strength claim.";
    report.rows.reserve(12U);
    add_stream_rows(report.rows, "motion-v1", motion);
    add_stream_rows(report.rows, "timing-v1", timing);

    for (const char* const stream : {"motion-v1", "timing-v1"}) {
        std::optional<double> shannon_rate;
        const EntropyEstimateRow* compression = nullptr;
        for (const EntropyEstimateRow& row : report.rows) {
            if (row.stream != stream) {
                continue;
            }
            if (row.method == "Shannon entropy" &&
                row.bits_per_symbol.has_value()) {
                shannon_rate = row.bits_per_symbol;
            } else if (row.role == EntropyEstimateRole::compression_only) {
                compression = &row;
            }
        }
        if (shannon_rate.has_value() && *shannon_rate > 0.0 &&
            compression != nullptr && compression->available &&
            compression->compressed_bytes.has_value() &&
            compression->sample_count != 0U) {
            const double compressed_rate =
                (static_cast<double>(*compression->compressed_bytes) * 8.0) /
                static_cast<double>(compression->sample_count);
            if (compressed_rate <=
                *shannon_rate * kStructuralCompressionGateFraction) {
                // Compression is never converted into entropy. It is used only
                // as a conservative zero-valued structural anomaly gate when
                // it is dramatically below the zero-order coding bound.
                report.diagnostic_minimum_bits = 0.0;
                break;
            }
        }
    }

    for (const EntropyEstimateRow& row : report.rows) {
        if (!row.available || row.role != EntropyEstimateRole::minimum_candidate ||
            !row.projected_bits.has_value()) {
            continue;
        }
        // Until the transition model reaches its minimum sample count, only a
        // zero-valued anomaly gate may establish the aggregate diagnostic. MCV
        // alone cannot distinguish a balanced deterministic cycle.
        if (motion.size() < kMarkovMinimumSamples &&
            *row.projected_bits != 0.0) {
            continue;
        }
        if (!report.diagnostic_minimum_bits.has_value() ||
            *row.projected_bits < *report.diagnostic_minimum_bits) {
            report.diagnostic_minimum_bits = row.projected_bits;
        }
    }
    return report;
}

[[nodiscard]] std::string fixed_number(const double value,
                                       const int precision = 3) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(precision) << value;
    return output.str();
}

[[nodiscard]] std::string fit_cell(const std::string& value,
                                   const std::size_t width) {
    if (value.size() <= width) {
        return value + std::string(width - value.size(), ' ');
    }
    if (width == 0U) {
        return {};
    }
    return value.substr(0U, width - 1U) + "~";
}

void add_two_column_row(std::ostringstream& output,
                        const std::string& field,
                        const std::string& value) {
    constexpr std::size_t kFieldWidth = 25U;
    constexpr std::size_t kValueWidth = 38U;
    output << "| " << fit_cell(field, kFieldWidth) << " | "
           << fit_cell(value, kValueWidth) << " |\n";
}

[[nodiscard]] std::string two_column_border() {
    return "+" + std::string(27U, '-') + "+" + std::string(40U, '-') + "+\n";
}

[[nodiscard]] std::string compact_method(const EntropyEstimateRow& row) {
    if (row.method == "Shannon entropy") {
        return "Shannon";
    }
    if (row.method == "MCV min-entropy (Wilson upper)") {
        return "MCV/Wilson";
    }
    if (row.method == "Renyi-2 collision entropy") {
        return "Renyi-2";
    }
    if (row.method == "First-order transition min-entropy") {
        return "Markov-1/Wilson";
    }
    if (row.method == "Exact repeated-prefix gate") {
        return "Repeat gate";
    }
    if (row.method == "Raw DEFLATE compressed size/ratio") {
        return "DEFLATE";
    }
    return row.method;
}

void add_mouse_row(std::ostringstream& output,
                   const EntropyEstimateRow& row) {
    constexpr std::size_t kViewWidth = 9U;
    constexpr std::size_t kMethodWidth = 18U;
    constexpr std::size_t kSamplesWidth = 8U;
    constexpr std::size_t kRateWidth = 10U;
    constexpr std::size_t kProjectionWidth = 14U;
    std::string rate = "-";
    std::string projection;
    if (row.bits_per_symbol.has_value()) {
        rate = fixed_number(*row.bits_per_symbol);
    }
    if (row.projected_bits.has_value()) {
        projection = fixed_number(*row.projected_bits);
    } else if (row.compressed_bytes.has_value() &&
               row.compression_ratio.has_value()) {
        projection = "r=" + fixed_number(*row.compression_ratio) + " " +
                     std::to_string(*row.compressed_bytes) + "B";
    } else if (row.available) {
        projection = "not detected";
    } else {
        projection = "N/A (<" + std::to_string(row.minimum_samples) + ")";
    }
    output << "| " << fit_cell(row.stream, kViewWidth) << " | "
           << fit_cell(compact_method(row), kMethodWidth) << " | "
           << fit_cell(std::to_string(row.sample_count), kSamplesWidth) << " | "
           << fit_cell(rate, kRateWidth) << " | "
           << fit_cell(projection, kProjectionWidth) << " |\n";
}

[[nodiscard]] CombinedRandomnessDiagnostics combine_diagnostics(
    const OsRandomnessDiagnostics& os,
    const EntropyReport& mouse) {
    CombinedRandomnessDiagnostics combined{};
    combined.mouse_diagnostic_bits = mouse.diagnostic_minimum_bits;
    combined.os_supplied_input_bits = static_cast<double>(os.input_bits);
    const double raw_mouse_bits = mouse.diagnostic_minimum_bits.value_or(0.0);
    if (raw_mouse_bits >
        static_cast<double>(kMinimumOsRandomInputBytes * 8U)) {
        // Match the byte-rounded OS allocation so the high-mouse display policy
        // is exactly 50/50. The measured diagnostic remains separately visible
        // and the rounded mouse value is explicitly only a policy weight.
        combined.mouse_policy_weight_bits = combined.os_supplied_input_bits;
    } else {
        combined.mouse_policy_weight_bits = raw_mouse_bits;
    }
    combined.policy_weighted_total_bits = combined.os_supplied_input_bits +
                                          combined.mouse_policy_weight_bits;
    if (combined.policy_weighted_total_bits > 0.0) {
        combined.os_policy_percent =
            (combined.os_supplied_input_bits /
             combined.policy_weighted_total_bits) *
            100.0;
        combined.mouse_policy_percent =
            (combined.mouse_policy_weight_bits /
             combined.policy_weighted_total_bits) *
            100.0;
    }
    combined.disclaimer =
        "Policy weighting only; not certified entropy or security strength.";
    return combined;
}

}  // namespace

Bytes frame_mouse_transcript(const std::vector<MouseEvent>& events) {
    Bytes framed = transcript_header();
    CleanseBytes cleanse_framed(framed);
    const std::size_t trailer_size = 9U;
    if (events.size() >
        (std::numeric_limits<std::size_t>::max() - framed.size() - trailer_size) /
            kMouseEventFrameBytes) {
        throw Error("mouse transcript is too large");
    }
    framed.reserve(framed.size() + (events.size() * kMouseEventFrameBytes) +
                   trailer_size);
    for (const MouseEvent& event : events) {
        Bytes event_frame = frame_mouse_event(event);
        const CleanseBytes cleanse_event_frame(event_frame);
        framed.insert(framed.end(), event_frame.begin(), event_frame.end());
    }
    Bytes trailer = transcript_trailer(static_cast<std::uint64_t>(events.size()));
    const CleanseBytes cleanse_trailer(trailer);
    framed.insert(framed.end(), trailer.begin(), trailer.end());
    cleanse_framed.dismiss();
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
    CleanseBytes cleanse_motion(motion);
    Bytes timing;
    CleanseBytes cleanse_timing(timing);
    motion.reserve(events.size());
    timing.reserve(events.size());
    for (const MouseEvent& event : events) {
        motion.push_back(motion_symbol(event));
        timing.push_back(timing_symbol(event));
    }
    return analyze_symbol_streams(motion, timing);
}

std::string format_entropy_report(const EntropyReport& report) {
    if (report.distinct_symbol_pair_count > report.event_count) {
        throw Error(
            "mouse report has more distinct symbol pairs than observed events");
    }
    std::ostringstream output;
    constexpr std::size_t kMouseBorderWidth = 75U;
    const std::string border = "+" + std::string(kMouseBorderWidth - 2U, '-') +
                               "+\n";
    output << "Mouse estimator diagnostics\n" << border;
    output << "| " << fit_cell("View", 9U) << " | "
           << fit_cell("Diagnostic", 18U) << " | "
           << fit_cell("Samples", 8U) << " | "
           << fit_cell("Rate", 10U) << " | "
           << fit_cell("Projected bits", 14U) << " |\n";
    output << border;
    for (const EntropyEstimateRow& row : report.rows) {
        add_mouse_row(output, row);
    }
    output << border;
    output << "Observed events: " << report.event_count << '\n';
    output << "Distinct motion/timing pairs: "
           << report.distinct_symbol_pair_count << '\n';
    output << "Repeated symbolic observations: "
           << report.event_count - report.distinct_symbol_pair_count << '\n';
    if (report.diagnostic_minimum_bits.has_value()) {
        output << "Diagnostic minimum: "
               << fixed_number(*report.diagnostic_minimum_bits)
               << " input bits\n";
    } else {
        output << "Diagnostic minimum: N/A (insufficient samples)\n";
    }
    output << "Mouse security credit: "
           << fixed_number(report.mouse_security_credit_bits) << " bits\n";
    output << "Note: MCV/Markov/repetition/compression gates; no average is used.\n";
    output << "Note: " << report.disclaimer << '\n';
    return output.str();
}

std::size_t required_os_random_bytes(
    const std::optional<double>& mouse_diagnostic_bits) {
    if (!mouse_diagnostic_bits.has_value() || *mouse_diagnostic_bits <= 512.0) {
        if (mouse_diagnostic_bits.has_value() &&
            (!std::isfinite(*mouse_diagnostic_bits) ||
             *mouse_diagnostic_bits < 0.0)) {
            throw Error("mouse diagnostic bit count must be finite and non-negative");
        }
        return kMinimumOsRandomInputBytes;
    }
    if (!std::isfinite(*mouse_diagnostic_bits) ||
        *mouse_diagnostic_bits < 0.0) {
        throw Error("mouse diagnostic bit count must be finite and non-negative");
    }
    const double required = std::ceil(*mouse_diagnostic_bits / 8.0);
    if (required > static_cast<double>(kMaximumOsRandomInputBytes)) {
        throw Error("mouse diagnostic requires more than " +
                    std::to_string(kMaximumOsRandomInputBytes) +
                    " bytes of OS random input");
    }
    return static_cast<std::size_t>(required);
}

std::string format_os_randomness_diagnostics(
    const OsRandomnessDiagnostics& diagnostics) {
    std::ostringstream output;
    const std::string border = two_column_border();
    output << "OS randomness diagnostics\n" << border;
    add_two_column_row(output, "Field", "Value");
    output << border;
    add_two_column_row(output, "Source", diagnostics.source);
    add_two_column_row(output, "Path", diagnostics.path);
    add_two_column_row(output, "Bytes read", std::to_string(diagnostics.bytes_read));
    add_two_column_row(output, "Input length",
                       std::to_string(diagnostics.input_bits) + " bits");
    output << border;
    output << "Note: Blocking getrandom(2) first confirmed kernel CSPRNG readiness.\n";
    output << "Note: Counted bytes were then read directly from /dev/urandom.\n";
    return output.str();
}

std::string format_combined_randomness_diagnostics(
    const CombinedRandomnessDiagnostics& diagnostics) {
    std::ostringstream output;
    const std::string border = two_column_border();
    output << "Combined conditioner diagnostics\n" << border;
    add_two_column_row(output, "Field", "Value");
    output << border;
    add_two_column_row(output,
                       "OS supplied input",
                       fixed_number(diagnostics.os_supplied_input_bits) + " bits");
    add_two_column_row(
        output,
        "Mouse diagnostic",
        diagnostics.mouse_diagnostic_bits.has_value()
            ? fixed_number(*diagnostics.mouse_diagnostic_bits) + " bits"
            : "N/A");
    add_two_column_row(output,
                       "Mouse policy weight",
                       fixed_number(diagnostics.mouse_policy_weight_bits) +
                           " bits");
    add_two_column_row(output,
                       "Policy-weighted total",
                       fixed_number(diagnostics.policy_weighted_total_bits) +
                           " bits");
    add_two_column_row(output,
                       "OS policy share",
                       fixed_number(diagnostics.os_policy_percent, 2) + "%");
    add_two_column_row(output,
                       "Mouse policy share",
                       fixed_number(diagnostics.mouse_policy_percent, 2) + "%");
    output << border;
    output << "Note: " << diagnostics.disclaimer << '\n';
    return output.str();
}

std::string format_conditioning_diagnostics(
    const ConditioningDiagnostics& diagnostics) {
    return format_os_randomness_diagnostics(diagnostics.os) + "\n" +
           format_entropy_report(diagnostics.mouse) + "\n" +
           format_combined_randomness_diagnostics(diagnostics.combined);
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
        append_string(conditioner_header, "ArborKDF/random-conditioner/v2");
        append_u32(conditioner_header, kRandomConditionerVersion);
        append_string(conditioner_header, purpose);
        append_string(conditioner_header, "mouse-transcript");
        digest_update(context_.get(), conditioner_header);

        const Bytes header = transcript_header();
        digest_update(context_.get(), header);
    }

    ~Impl() {
        if (!motion_symbols_.empty()) {
            OPENSSL_cleanse(motion_symbols_.data(), motion_symbols_.size());
        }
        if (!timing_symbols_.empty()) {
            OPENSSL_cleanse(timing_symbols_.data(), timing_symbols_.size());
        }
    }

    void add_event(const MouseEvent& event) {
        ensure_active();
        if (event_count_ == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("mouse event counter exhausted");
        }
        if (motion_symbols_.size() ==
            std::numeric_limits<std::size_t>::max()) {
            throw Error("mouse diagnostic symbol storage exhausted");
        }
        const std::size_t needed = motion_symbols_.size() + 1U;
        if (needed > motion_symbols_.capacity() ||
            needed > timing_symbols_.capacity()) {
            const std::size_t current_capacity =
                std::max(motion_symbols_.capacity(), timing_symbols_.capacity());
            const std::size_t grown =
                current_capacity >
                        std::numeric_limits<std::size_t>::max() / 2U
                    ? needed
                    : std::max(needed, current_capacity * 2U);
            motion_symbols_.reserve(grown);
            timing_symbols_.reserve(grown);
        }
        motion_symbols_.push_back(motion_symbol(event));
        timing_symbols_.push_back(timing_symbol(event));
        Bytes frame = frame_mouse_event(event);
        const CleanseBytes cleanse_frame(frame);
        digest_update(context_.get(), frame);
        ++event_count_;
    }

    [[nodiscard]] ConditionedRandomResult finish(
        const std::size_t output_bytes) {
        ensure_active();
        if (output_bytes == 0U || output_bytes > kMaximumConditionedOutputBytes) {
            throw Error("conditioned output length must be between 1 and " +
                        std::to_string(kMaximumConditionedOutputBytes) + " bytes");
        }
        finished_ = true;
        EntropyReport mouse_report =
            analyze_symbol_streams(motion_symbols_, timing_symbols_);
        const std::size_t os_byte_count =
            required_os_random_bytes(mouse_report.diagnostic_minimum_bits);
        Bytes os_random = read_linux_urandom(os_byte_count);
        const CleanseBytes cleanse_os_random(os_random);

        const Bytes trailer = transcript_trailer(event_count_);
        digest_update(context_.get(), trailer);

        Bytes os_header;
        append_string(os_header, "linux-os-random-input");
        append_string(os_header, kLinuxRandomPath);
        append_u64(os_header, static_cast<std::uint64_t>(os_random.size()));
        digest_update(context_.get(), os_header);
        digest_update(context_.get(), os_random);

        Bytes output_header;
        append_string(output_header, "requested-output-length");
        append_u64(output_header, static_cast<std::uint64_t>(output_bytes));
        digest_update(context_.get(), output_header);

        ConditioningDiagnostics diagnostics{};
        diagnostics.os.source = kLinuxRandomSource;
        diagnostics.os.path = kLinuxRandomPath;
        diagnostics.os.bytes_read = os_random.size();
        diagnostics.os.input_bits = os_random.size() * 8U;
        diagnostics.mouse = std::move(mouse_report);
        diagnostics.combined = combine_diagnostics(diagnostics.os,
                                                   diagnostics.mouse);

        ConditionedRandomResult result{};
        result.diagnostics = std::move(diagnostics);
        result.bytes.resize(output_bytes);
        CleanseBytes cleanse_output(result.bytes);
        if (EVP_DigestFinalXOF(context_.get(),
                              result.bytes.data(),
                              result.bytes.size()) != 1) {
            throw Error(openssl_error("finalize SHAKE-256 conditioner"));
        }
        if (EVP_MD_CTX_reset(context_.get()) != 1) {
            throw Error(openssl_error("reset SHAKE-256 conditioner"));
        }
        cleanse_output.dismiss();
        return result;
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
    Bytes motion_symbols_;
    Bytes timing_symbols_;
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

ConditionedRandomResult StreamingRandomConditioner::finish(
    const std::size_t output_bytes) {
    if (!implementation_) {
        throw Error("random conditioner is in a moved-from state");
    }
    return implementation_->finish(output_bytes);
}

std::size_t StreamingRandomConditioner::event_count() const noexcept {
    return implementation_ ? implementation_->event_count() : 0U;
}

ConditionedRandomResult condition_random(const std::vector<MouseEvent>& events,
                                         const std::string& purpose,
                                         const std::size_t output_bytes) {
    StreamingRandomConditioner conditioner(purpose);
    for (const MouseEvent& event : events) {
        conditioner.add_event(event);
    }
    return conditioner.finish(output_bytes);
}

}  // namespace arborkdf
