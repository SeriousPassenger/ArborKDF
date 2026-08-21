#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "arborkdf/platform.hpp"

#include "arborkdf/error.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <new>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace arborkdf {
namespace {

constexpr std::size_t kProgressWidth = 40U;
constexpr double kProgressTargetBits = 256.0;
constexpr std::size_t kMaximumMouseEvents = 1000000U;
constexpr auto kProgressRefreshInterval = std::chrono::milliseconds(500);

void wipe_mouse_events(std::vector<MouseEvent>& events) noexcept {
    if (!events.empty()) {
        OPENSSL_cleanse(events.data(), events.size() * sizeof(MouseEvent));
    }
    events.clear();
}

void wipe_string(std::string& value) noexcept {
    if (!value.empty()) {
        OPENSSL_cleanse(value.data(), value.size());
    }
    value.clear();
}

class MouseEventErrorWiper final {
public:
    explicit MouseEventErrorWiper(std::vector<MouseEvent>& events) noexcept
        : events_(events) {}

    ~MouseEventErrorWiper() {
        if (armed_) {
            wipe_mouse_events(events_);
        }
    }

    MouseEventErrorWiper(const MouseEventErrorWiper&) = delete;
    MouseEventErrorWiper& operator=(const MouseEventErrorWiper&) = delete;

    void release() noexcept { armed_ = false; }

private:
    std::vector<MouseEvent>& events_;
    bool armed_{true};
};

class StringWiper final {
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}
    ~StringWiper() {
        if (armed_) {
            wipe_string(value_);
        }
    }

    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;

    void release() noexcept { armed_ = false; }

private:
    std::string& value_;
    bool armed_{true};
};

void reserve_mouse_transcript(std::vector<MouseEvent>& events) {
    try {
        // Reserving the bounded maximum prevents allocator growth from leaving
        // stale copies of already-collected event records in freed buffers.
        events.reserve(kMaximumMouseEvents);
    } catch (const std::bad_alloc&) {
        throw Error("unable to allocate the bounded mouse transcript buffer");
    } catch (const std::length_error&) {
        throw Error("mouse transcript limit exceeds this platform's vector capacity");
    }
}

void enforce_mouse_event_limit(const std::vector<MouseEvent>& events) {
    if (events.size() >= kMaximumMouseEvents) {
        throw Error("mouse transcript reached the hard limit of 1000000 events "
                    "before Enter was pressed");
    }
}

[[nodiscard]] bool progress_refresh_due(
    const std::chrono::steady_clock::time_point last_refresh) noexcept {
    return std::chrono::steady_clock::now() - last_refresh >=
           kProgressRefreshInterval;
}

[[nodiscard]] std::string progress_line(const std::vector<MouseEvent>& events) {
    const EntropyReport report = analyze_mouse_events(events);
    std::ostringstream output;
    output << '\r' << "Mouse diagnostic projection [";
    std::size_t filled = 0U;
    if (report.diagnostic_minimum_bits.has_value()) {
        const double ratio = std::max(0.0, *report.diagnostic_minimum_bits) /
                             kProgressTargetBits;
        const double scaled = std::floor(std::min(1.0, ratio) *
                                         static_cast<double>(kProgressWidth));
        filled = static_cast<std::size_t>(scaled);
    }
    output << std::string(filled, '#') << std::string(kProgressWidth - filled, '.');
    output << "] ";
    if (report.diagnostic_minimum_bits.has_value()) {
        output.setf(std::ios::fixed);
        output.precision(1);
        output << *report.diagnostic_minimum_bits << "/256 bits";
    } else {
        output << "warming up; " << events.size() << " events";
    }
    output << " - Enter stops";
    return output.str();
}

#ifndef _WIN32

void reserve_hidden_input(std::string& value, const std::size_t maximum_bytes) {
    if (maximum_bytes > value.max_size()) {
        throw Error("hidden input limit exceeds this platform's string capacity");
    }
    try {
        value.reserve(maximum_bytes);
    } catch (const std::bad_alloc&) {
        throw Error("unable to allocate the bounded hidden-input buffer");
    } catch (const std::length_error&) {
        throw Error("hidden input limit exceeds this platform's string capacity");
    }
}

[[nodiscard]] bool is_utf8_continuation_byte(const unsigned char value) noexcept {
    return (value & 0xc0U) == 0x80U;
}

[[nodiscard]] std::size_t utf8_sequence_size(const unsigned char lead) noexcept {
    if (lead <= 0x7fU) {
        return 1U;
    }
    if (lead >= 0xc2U && lead <= 0xdfU) {
        return 2U;
    }
    if (lead >= 0xe0U && lead <= 0xefU) {
        return 3U;
    }
    if (lead >= 0xf0U && lead <= 0xf4U) {
        return 4U;
    }
    return 0U;
}

void erase_last_utf8_sequence(std::string& value) noexcept {
    if (value.empty()) {
        return;
    }

    const std::size_t last = value.size() - 1U;
    std::size_t candidate = last;
    while (candidate > 0U &&
           is_utf8_continuation_byte(
               static_cast<unsigned char>(value[candidate]))) {
        --candidate;
    }
    const std::size_t expected = utf8_sequence_size(
        static_cast<unsigned char>(value[candidate]));
    const std::size_t start = expected != 0U && expected <= value.size() &&
                                      candidate == value.size() - expected
                                  ? candidate
                                  : last;
    OPENSSL_cleanse(value.data() + static_cast<std::ptrdiff_t>(start),
                    value.size() - start);
    value.resize(start);
}

#endif

#ifdef _WIN32

class WindowsConsoleMode final {
public:
    explicit WindowsConsoleMode(const DWORD requested_mode)
        : input_(GetStdHandle(STD_INPUT_HANDLE)) {
        if (input_ == INVALID_HANDLE_VALUE || input_ == nullptr ||
            GetConsoleMode(input_, &original_) == 0) {
            throw Error("an interactive Windows console is required");
        }
        if (SetConsoleMode(input_, requested_mode) == 0) {
            throw Error("failed to configure the Windows console");
        }
        configured_ = true;
    }

    ~WindowsConsoleMode() {
        if (configured_) {
            static_cast<void>(SetConsoleMode(input_, original_));
        }
    }

    WindowsConsoleMode(const WindowsConsoleMode&) = delete;
    WindowsConsoleMode& operator=(const WindowsConsoleMode&) = delete;

    [[nodiscard]] HANDLE input() const noexcept { return input_; }
    [[nodiscard]] DWORD original() const noexcept { return original_; }

private:
    HANDLE input_{INVALID_HANDLE_VALUE};
    DWORD original_{};
    bool configured_{};
};

void wipe_wide_string(std::wstring& value) noexcept {
    if (!value.empty()) {
        OPENSSL_cleanse(value.data(), value.size() * sizeof(wchar_t));
    }
    value.clear();
}

class WideStringWiper final {
public:
    explicit WideStringWiper(std::wstring& value) noexcept : value_(value) {}
    ~WideStringWiper() { wipe_wide_string(value_); }

    WideStringWiper(const WideStringWiper&) = delete;
    WideStringWiper& operator=(const WideStringWiper&) = delete;

private:
    std::wstring& value_;
};

void reserve_hidden_wide_input(std::wstring& value,
                               const std::size_t maximum_bytes) {
    if (maximum_bytes > value.max_size()) {
        throw Error("hidden input limit exceeds this platform's wide-string capacity");
    }
    try {
        value.reserve(maximum_bytes);
    } catch (const std::bad_alloc&) {
        throw Error("unable to allocate the bounded Windows hidden-input buffer");
    } catch (const std::length_error&) {
        throw Error("hidden input limit exceeds this platform's wide-string capacity");
    }
}

[[nodiscard]] bool is_high_surrogate(const wchar_t value) noexcept {
    const std::uint32_t code_unit = static_cast<std::uint32_t>(value);
    return code_unit >= UINT32_C(0xd800) && code_unit <= UINT32_C(0xdbff);
}

[[nodiscard]] bool is_low_surrogate(const wchar_t value) noexcept {
    const std::uint32_t code_unit = static_cast<std::uint32_t>(value);
    return code_unit >= UINT32_C(0xdc00) && code_unit <= UINT32_C(0xdfff);
}

[[nodiscard]] std::size_t utf8_bytes_for_bmp_code_unit(
    const wchar_t value) noexcept {
    const std::uint32_t code_unit = static_cast<std::uint32_t>(value);
    if (code_unit <= UINT32_C(0x7f)) {
        return 1U;
    }
    if (code_unit <= UINT32_C(0x7ff)) {
        return 2U;
    }
    return 3U;
}

void enforce_hidden_input_growth(const std::size_t current_bytes,
                                 const std::size_t additional_bytes,
                                 const std::size_t maximum_bytes) {
    if (additional_bytes > maximum_bytes ||
        current_bytes > maximum_bytes - additional_bytes) {
        throw Error("hidden input exceeds the configured UTF-8 byte limit");
    }
}

void append_windows_console_character(std::wstring& value,
                                      std::size_t& utf8_bytes,
                                      const wchar_t character,
                                      const std::size_t maximum_bytes) {
    const bool pending_high = !value.empty() && is_high_surrogate(value.back());
    if (is_high_surrogate(character)) {
        if (pending_high) {
            throw Error("Windows console input contains an unpaired UTF-16 surrogate");
        }
        // Reserve the complete scalar's UTF-8 budget before retaining its first
        // UTF-16 code unit, so even a pending surrogate respects the hard bound.
        enforce_hidden_input_growth(utf8_bytes, 4U, maximum_bytes);
        value.push_back(character);
        return;
    }
    if (is_low_surrogate(character)) {
        if (!pending_high) {
            throw Error("Windows console input contains an unpaired UTF-16 surrogate");
        }
        enforce_hidden_input_growth(utf8_bytes, 4U, maximum_bytes);
        value.push_back(character);
        utf8_bytes += 4U;
        return;
    }
    if (pending_high) {
        throw Error("Windows console input contains an unpaired UTF-16 surrogate");
    }
    const std::size_t additional = utf8_bytes_for_bmp_code_unit(character);
    enforce_hidden_input_growth(utf8_bytes, additional, maximum_bytes);
    value.push_back(character);
    utf8_bytes += additional;
}

void erase_last_windows_console_character(std::wstring& value,
                                          std::size_t& utf8_bytes) noexcept {
    if (value.empty()) {
        return;
    }
    std::size_t start = value.size() - 1U;
    std::size_t removed_utf8_bytes = 0U;
    if (is_high_surrogate(value[start])) {
        removed_utf8_bytes = 0U;
    } else if (is_low_surrogate(value[start]) && start > 0U &&
               is_high_surrogate(value[start - 1U])) {
        --start;
        removed_utf8_bytes = 4U;
    } else {
        removed_utf8_bytes = utf8_bytes_for_bmp_code_unit(value[start]);
    }
    OPENSSL_cleanse(value.data() + static_cast<std::ptrdiff_t>(start),
                    (value.size() - start) * sizeof(wchar_t));
    value.resize(start);
    utf8_bytes = removed_utf8_bytes <= utf8_bytes
                     ? utf8_bytes - removed_utf8_bytes
                     : 0U;
}

[[nodiscard]] std::string windows_wide_to_utf8(const std::wstring& value,
                                               const std::size_t maximum_bytes) {
    if (value.empty()) {
        return {};
    }
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw Error("Windows console input exceeds the UTF-8 conversion API limit");
    }
    const int source_size = static_cast<int>(value.size());
    const int required = WideCharToMultiByte(CP_UTF8,
                                             WC_ERR_INVALID_CHARS,
                                             value.data(),
                                             source_size,
                                             nullptr,
                                             0,
                                             nullptr,
                                             nullptr);
    if (required <= 0) {
        throw Error("failed to convert Windows console input to strict UTF-8");
    }
    if (static_cast<std::size_t>(required) > maximum_bytes) {
        throw Error("hidden input exceeds the configured UTF-8 byte limit");
    }
    std::string output(static_cast<std::size_t>(required), '\0');
    const int converted = WideCharToMultiByte(CP_UTF8,
                                              WC_ERR_INVALID_CHARS,
                                              value.data(),
                                              source_size,
                                              output.data(),
                                              required,
                                              nullptr,
                                              nullptr);
    if (converted != required) {
        wipe_string(output);
        throw Error("failed to convert Windows console input to strict UTF-8");
    }
    return output;
}

#else

constexpr std::array<int, 4U> kTerminalSignals{SIGINT, SIGTERM, SIGHUP, SIGQUIT};
volatile std::sig_atomic_t gTerminalSignal = 0;
volatile std::sig_atomic_t gTerminalSignalPipe = -1;

extern "C" void terminal_signal_handler(const int signal_number) noexcept {
    const int saved_errno = errno;
    gTerminalSignal = signal_number;
    const int descriptor = static_cast<int>(gTerminalSignalPipe);
    if (descriptor >= 0) {
        const unsigned char marker = 1U;
        const ssize_t ignored = ::write(descriptor, &marker, 1U);
        static_cast<void>(ignored);
    }
    errno = saved_errno;
}

void close_descriptor(int& descriptor) noexcept {
    if (descriptor >= 0) {
        static_cast<void>(::close(descriptor));
        descriptor = -1;
    }
}

void configure_private_descriptor(const int descriptor) {
    const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
    if (descriptor_flags < 0 ||
        ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
        throw Error("failed to set close-on-exec on a terminal helper descriptor");
    }
    const int status_flags = ::fcntl(descriptor, F_GETFL);
    if (status_flags < 0 ||
        ::fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) < 0) {
        throw Error("failed to make a terminal helper descriptor nonblocking");
    }
}

class PosixSignalBridge final {
public:
    PosixSignalBridge() {
        if (gTerminalSignalPipe >= 0) {
            throw Error("nested interactive terminal sessions are not supported");
        }

        int descriptors[2]{-1, -1};
        if (::pipe(descriptors) != 0) {
            throw Error("failed to create the terminal signal pipe");
        }
        read_descriptor_ = descriptors[0];
        write_descriptor_ = descriptors[1];
        try {
            configure_private_descriptor(read_descriptor_);
            configure_private_descriptor(write_descriptor_);
        } catch (...) {
            close_descriptor(read_descriptor_);
            close_descriptor(write_descriptor_);
            throw;
        }

        gTerminalSignal = 0;
        gTerminalSignalPipe = static_cast<std::sig_atomic_t>(write_descriptor_);
        struct sigaction action {};
        action.sa_handler = terminal_signal_handler;
        static_cast<void>(sigemptyset(&action.sa_mask));
        action.sa_flags = 0;
        for (std::size_t index = 0U; index < kTerminalSignals.size(); ++index) {
            if (::sigaction(kTerminalSignals[index], &action,
                            &original_actions_[index]) != 0) {
                restore_installed_handlers();
                gTerminalSignalPipe = -1;
                close_descriptor(read_descriptor_);
                close_descriptor(write_descriptor_);
                throw Error("failed to install an interactive terminal signal handler");
            }
            ++installed_handlers_;
        }
    }

    ~PosixSignalBridge() {
        restore_installed_handlers();
        gTerminalSignalPipe = -1;
        gTerminalSignal = 0;
        close_descriptor(read_descriptor_);
        close_descriptor(write_descriptor_);
    }

    PosixSignalBridge(const PosixSignalBridge&) = delete;
    PosixSignalBridge& operator=(const PosixSignalBridge&) = delete;

    void wait_for(const int descriptor, const short requested_events) {
        for (;;) {
            throw_if_interrupted();
            std::array<struct pollfd, 2U> descriptors{};
            descriptors[0].fd = descriptor;
            descriptors[0].events = requested_events;
            descriptors[1].fd = read_descriptor_;
            descriptors[1].events = POLLIN;
            const int result = ::poll(descriptors.data(),
                                      static_cast<nfds_t>(descriptors.size()),
                                      -1);
            if (result < 0) {
                if (errno == EINTR) {
                    throw_if_interrupted();
                    continue;
                }
                throw Error("failed while waiting on the controlling terminal");
            }
            if ((descriptors[1].revents &
                 static_cast<short>(POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0) {
                drain_signal_pipe();
                throw_if_interrupted();
                throw Error("terminal signal pipe closed unexpectedly");
            }
            if ((descriptors[0].revents & POLLNVAL) != 0) {
                throw Error("controlling terminal descriptor became invalid");
            }
            if ((descriptors[0].revents & POLLERR) != 0) {
                throw Error("controlling terminal reported an I/O error");
            }
            if ((descriptors[0].revents & requested_events) != 0) {
                return;
            }
            if ((descriptors[0].revents & POLLHUP) != 0) {
                throw Error("controlling terminal was closed");
            }
        }
    }

    void throw_if_interrupted() const {
        const int signal_number = static_cast<int>(gTerminalSignal);
        if (signal_number != 0) {
            throw Error("interactive terminal operation interrupted by signal " +
                        std::to_string(signal_number));
        }
    }

private:
    void restore_installed_handlers() noexcept {
        while (installed_handlers_ > 0U) {
            --installed_handlers_;
            static_cast<void>(::sigaction(kTerminalSignals[installed_handlers_],
                                          &original_actions_[installed_handlers_],
                                          nullptr));
        }
    }

    void drain_signal_pipe() noexcept {
        std::array<unsigned char, 64U> buffer{};
        for (;;) {
            const ssize_t result =
                ::read(read_descriptor_, buffer.data(), buffer.size());
            if (result > 0) {
                continue;
            }
            if (result < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
    }

    int read_descriptor_{-1};
    int write_descriptor_{-1};
    std::array<struct sigaction, kTerminalSignals.size()> original_actions_{};
    std::size_t installed_handlers_{};
};

void best_effort_write(const int descriptor, const std::string_view value) noexcept {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const ssize_t result =
            ::write(descriptor, value.data() + static_cast<std::ptrdiff_t>(offset),
                    value.size() - offset);
        if (result > 0) {
            offset += static_cast<std::size_t>(result);
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
}

class PosixTerminal final {
public:
    explicit PosixTerminal(const bool mouse_mode) : mouse_mode_(mouse_mode) {
        descriptor_ = ::open("/dev/tty", O_RDWR | O_NOCTTY);
        if (descriptor_ < 0) {
            throw Error("an interactive controlling terminal is required");
        }
        try {
            configure_private_descriptor(descriptor_);
        } catch (...) {
            close_descriptor(descriptor_);
            throw;
        }
        if (::tcgetattr(descriptor_, &original_) != 0) {
            close_descriptor(descriptor_);
            throw Error("failed to configure the controlling terminal");
        }
        try {
            signal_bridge_.emplace();
            struct termios configured = original_;
            configured.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
            configured.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL));
            configured.c_cc[VMIN] = 1;
            configured.c_cc[VTIME] = 0;
            if (::tcsetattr(descriptor_, TCSAFLUSH, &configured) != 0) {
                throw Error("failed to configure the controlling terminal");
            }
            configured_ = true;
            if (mouse_mode_) {
                write_text("\x1b[?1003h\x1b[?1006h");
            }
        } catch (...) {
            cleanup_terminal();
            signal_bridge_.reset();
            throw;
        }
    }

    ~PosixTerminal() { cleanup_terminal(); }

    PosixTerminal(const PosixTerminal&) = delete;
    PosixTerminal& operator=(const PosixTerminal&) = delete;

    [[nodiscard]] char read_character() {
        for (;;) {
            signal_bridge_->wait_for(descriptor_, POLLIN);
            char character = '\0';
            const ssize_t result = ::read(descriptor_, &character, 1U);
            if (result == 1) {
                return character;
            }
            if (result == 0) {
                throw Error("controlling terminal reached end-of-file");
            }
            if (errno == EINTR) {
                signal_bridge_->throw_if_interrupted();
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            throw Error("failed to read from the controlling terminal");
        }
    }

    void write_text(const std::string_view value) {
        std::size_t offset = 0U;
        while (offset < value.size()) {
            signal_bridge_->wait_for(descriptor_, POLLOUT);
            const ssize_t result = ::write(
                descriptor_,
                value.data() + static_cast<std::ptrdiff_t>(offset),
                value.size() - offset);
            if (result > 0) {
                offset += static_cast<std::size_t>(result);
                continue;
            }
            if (result == 0) {
                throw Error("controlling terminal accepted zero output bytes");
            }
            if (errno == EINTR) {
                signal_bridge_->throw_if_interrupted();
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            throw Error("failed to write to the controlling terminal");
        }
    }

private:
    void cleanup_terminal() noexcept {
        if (descriptor_ < 0) {
            return;
        }
        if (mouse_mode_) {
            best_effort_write(descriptor_, "\x1b[?1003l\x1b[?1006l");
        }
        if (configured_) {
            static_cast<void>(::tcsetattr(descriptor_, TCSAFLUSH, &original_));
            configured_ = false;
        }
        close_descriptor(descriptor_);
    }

    int descriptor_{-1};
    struct termios original_ {};
    bool configured_{};
    bool mouse_mode_{};
    std::optional<PosixSignalBridge> signal_bridge_;
};

struct SgrMouseRecord final {
    int code{};
    int x{};
    int y{};
    bool release{};
};

[[nodiscard]] std::optional<int> parse_int(const std::string_view text) {
    int output = 0;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto result = std::from_chars(begin, end, output, 10);
    if (text.empty() || result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }
    return output;
}

[[nodiscard]] std::optional<SgrMouseRecord> parse_sgr_mouse(const std::string& sequence) {
    if (sequence.size() < 7U || sequence.compare(0U, 3U, "\x1b[<") != 0) {
        return std::nullopt;
    }
    const char terminator = sequence.back();
    if (terminator != 'M' && terminator != 'm') {
        return std::nullopt;
    }
    const std::string_view body(sequence.data() + 3U, sequence.size() - 4U);
    const std::size_t first_separator = body.find(';');
    if (first_separator == std::string::npos) {
        return std::nullopt;
    }
    const std::size_t second_separator = body.find(';', first_separator + 1U);
    if (second_separator == std::string::npos ||
        body.find(';', second_separator + 1U) != std::string::npos) {
        return std::nullopt;
    }
    const std::optional<int> code = parse_int(body.substr(0U, first_separator));
    const std::optional<int> x = parse_int(
        body.substr(first_separator + 1U, second_separator - first_separator - 1U));
    const std::optional<int> y = parse_int(body.substr(second_separator + 1U));
    if (!code.has_value() || !x.has_value() || !y.has_value() || *code < 0 || *x < 0 ||
        *y < 0) {
        return std::nullopt;
    }
    return SgrMouseRecord{*code, *x, *y, terminator == 'm'};
}

#endif

}  // namespace

std::string read_hidden_line(const std::string& prompt,
                             const std::size_t maximum_bytes) {
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original = 0U;
    if (input == INVALID_HANDLE_VALUE || input == nullptr ||
        GetConsoleMode(input, &original) == 0) {
        throw Error("an interactive Windows console is required for hidden input");
    }
    const DWORD requested =
        original & static_cast<DWORD>(~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
    WindowsConsoleMode guard(requested);
    std::cerr << prompt << std::flush;

    std::wstring wide_value;
    reserve_hidden_wide_input(wide_value, maximum_bytes);
    const WideStringWiper wide_wiper(wide_value);
    std::size_t utf8_bytes = 0U;
    bool finished = false;
    while (!finished) {
        INPUT_RECORD record{};
        DWORD count = 0U;
        if (ReadConsoleInputW(guard.input(), &record, 1U, &count) == 0 ||
            count != 1U) {
            throw Error("failed to read hidden input from the Windows console");
        }
        if (record.EventType != KEY_EVENT ||
            record.Event.KeyEvent.bKeyDown == FALSE) {
            continue;
        }

        const KEY_EVENT_RECORD& key = record.Event.KeyEvent;
        const unsigned int repeats =
            std::max(1U, static_cast<unsigned int>(key.wRepeatCount));
        if (key.wVirtualKeyCode == VK_RETURN) {
            if (!wide_value.empty() && is_high_surrogate(wide_value.back())) {
                throw Error("Windows console input ends with an unpaired UTF-16 surrogate");
            }
            finished = true;
            continue;
        }
        if (key.wVirtualKeyCode == VK_BACK) {
            for (unsigned int repeat = 0U; repeat < repeats; ++repeat) {
                erase_last_windows_console_character(wide_value, utf8_bytes);
            }
            continue;
        }
        const wchar_t character = key.uChar.UnicodeChar;
        if (character == L'\0') {
            continue;
        }
        for (unsigned int repeat = 0U; repeat < repeats; ++repeat) {
            append_windows_console_character(
                wide_value, utf8_bytes, character, maximum_bytes);
        }
    }
    std::cerr << '\n';

    std::string value = windows_wide_to_utf8(wide_value, maximum_bytes);
    StringWiper value_wiper(value);
    value_wiper.release();
    return value;
#else
    PosixTerminal terminal(false);
    terminal.write_text(prompt);
    std::string value;
    reserve_hidden_input(value, maximum_bytes);
    StringWiper value_wiper(value);
    for (;;) {
        const char character = terminal.read_character();
        if (character == '\n' || character == '\r') {
            break;
        }
        if (character == 0x7f || character == '\b') {
            erase_last_utf8_sequence(value);
            continue;
        }
        if (value.size() >= maximum_bytes) {
            throw Error("hidden input exceeds the configured UTF-8 byte limit");
        }
        value.push_back(character);
    }
    terminal.write_text("\n");
    value_wiper.release();
    return value;
#endif
}

std::vector<MouseEvent> collect_mouse_events() {
    std::vector<MouseEvent> events;
    reserve_mouse_transcript(events);
    MouseEventErrorWiper error_wiper(events);
    std::cerr << "Move the mouse to add supplemental randomness; press Enter to finish.\n"
              << "Live figures are diagnostics, not validated entropy or security credit.\n";
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original = 0U;
    if (input == INVALID_HANDLE_VALUE || input == nullptr ||
        GetConsoleMode(input, &original) == 0) {
        throw Error("an interactive Windows console is required for mouse collection");
    }
    DWORD requested = original;
    requested |= ENABLE_EXTENDED_FLAGS | ENABLE_MOUSE_INPUT;
    requested &= static_cast<DWORD>(~(ENABLE_QUICK_EDIT_MODE | ENABLE_LINE_INPUT |
                                      ENABLE_ECHO_INPUT));
    WindowsConsoleMode guard(requested);
    std::cerr << progress_line(events) << std::flush;
    auto last_progress_refresh = std::chrono::steady_clock::now();
    COORD previous{};
    bool have_previous = false;
    auto previous_time = std::chrono::steady_clock::now();
    bool finished = false;
    while (!finished) {
        INPUT_RECORD record{};
        DWORD count = 0U;
        if (ReadConsoleInputW(guard.input(), &record, 1U, &count) == 0 || count != 1U) {
            throw Error("failed to read Windows console mouse events");
        }
        if (record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown != FALSE &&
            record.Event.KeyEvent.wVirtualKeyCode == VK_RETURN) {
            finished = true;
            continue;
        }
        if (record.EventType != MOUSE_EVENT) {
            continue;
        }
        const auto now = std::chrono::steady_clock::now();
        const COORD current = record.Event.MouseEvent.dwMousePosition;
        const std::int32_t dx = have_previous
                                    ? static_cast<std::int32_t>(current.X - previous.X)
                                    : 0;
        const std::int32_t dy = have_previous
                                    ? static_cast<std::int32_t>(current.Y - previous.Y)
                                    : 0;
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now - previous_time);
        const auto nonnegative = std::max<std::int64_t>(0, elapsed.count());
        if (events.size() >= kMaximumMouseEvents) {
            std::cerr << progress_line(events) << '\n' << std::flush;
            enforce_mouse_event_limit(events);
        }
        events.push_back(MouseEvent{
            dx,
            dy,
            static_cast<std::uint64_t>(nonnegative),
            static_cast<std::uint32_t>(record.Event.MouseEvent.dwEventFlags)});
        previous = current;
        previous_time = now;
        have_previous = true;
        if (progress_refresh_due(last_progress_refresh)) {
            std::cerr << progress_line(events) << std::flush;
            last_progress_refresh = std::chrono::steady_clock::now();
        }
    }
    std::cerr << progress_line(events) << '\n' << std::flush;
#else
    PosixTerminal terminal(true);
    terminal.write_text(progress_line(events));
    auto last_progress_refresh = std::chrono::steady_clock::now();
    std::string sequence;
    const StringWiper sequence_wiper(sequence);
    int previous_x = 0;
    int previous_y = 0;
    bool have_previous = false;
    auto previous_time = std::chrono::steady_clock::now();
    bool finished = false;
    while (!finished) {
        const char character = terminal.read_character();
        if (sequence.empty() && (character == '\n' || character == '\r')) {
            finished = true;
            continue;
        }
        if (character == '\x1b') {
            wipe_string(sequence);
            sequence.assign(1U, character);
            continue;
        }
        if (sequence.empty()) {
            continue;
        }
        sequence.push_back(character);
        if (sequence.size() > 128U) {
            wipe_string(sequence);
            continue;
        }
        if (character != 'M' && character != 'm') {
            continue;
        }
        const std::optional<SgrMouseRecord> record = parse_sgr_mouse(sequence);
        wipe_string(sequence);
        if (!record.has_value()) {
            continue;
        }
        const auto now = std::chrono::steady_clock::now();
        const int raw_dx = have_previous ? record->x - previous_x : 0;
        const int raw_dy = have_previous ? record->y - previous_y : 0;
        const std::int32_t dx = static_cast<std::int32_t>(std::clamp(
            raw_dx,
            static_cast<int>(std::numeric_limits<std::int32_t>::min()),
            static_cast<int>(std::numeric_limits<std::int32_t>::max())));
        const std::int32_t dy = static_cast<std::int32_t>(std::clamp(
            raw_dy,
            static_cast<int>(std::numeric_limits<std::int32_t>::min()),
            static_cast<int>(std::numeric_limits<std::int32_t>::max())));
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now - previous_time);
        const auto nonnegative = std::max<std::int64_t>(0, elapsed.count());
        std::uint32_t flags = static_cast<std::uint32_t>(record->code);
        if (record->release) {
            flags |= UINT32_C(0x80000000);
        }
        if (events.size() >= kMaximumMouseEvents) {
            terminal.write_text(progress_line(events) + "\n");
            enforce_mouse_event_limit(events);
        }
        events.push_back(MouseEvent{
            dx, dy, static_cast<std::uint64_t>(nonnegative), flags});
        previous_x = record->x;
        previous_y = record->y;
        previous_time = now;
        have_previous = true;
        if (progress_refresh_due(last_progress_refresh)) {
            terminal.write_text(progress_line(events));
            last_progress_refresh = std::chrono::steady_clock::now();
        }
    }
    terminal.write_text(progress_line(events) + "\n");
#endif
    std::cerr << '\n';
    error_wiper.release();
    return events;
}

void secure_clear(std::string& value) noexcept {
    wipe_string(value);
}

}  // namespace arborkdf
