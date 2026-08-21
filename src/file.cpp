#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "arborkdf/file.hpp"

#include "arborkdf/error.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace arborkdf {
namespace {

#ifdef _WIN32

class WindowsFile final {
  public:
    explicit WindowsFile(const HANDLE handle) noexcept : handle_(handle) {}

    ~WindowsFile() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            static_cast<void>(CloseHandle(handle_));
        }
    }

    WindowsFile(const WindowsFile&) = delete;
    WindowsFile& operator=(const WindowsFile&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

    void close_checked() {
        if (handle_ == INVALID_HANDLE_VALUE) {
            return;
        }
        const HANDLE handle = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        if (CloseHandle(handle) == 0) {
            throw Error("failed to close exported wordlist file; an incomplete "
                        "new file may remain");
        }
    }

  private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

[[noreturn]] void throw_windows_create_error(const DWORD error) {
    if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
        throw Error("output file already exists; refusing to overwrite it");
    }
    throw Error("cannot create output file (Windows error " +
                std::to_string(static_cast<unsigned long>(error)) + ")");
}

#else

class PosixFile final {
  public:
    explicit PosixFile(const int descriptor) noexcept
        : descriptor_(descriptor) {}

    ~PosixFile() {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
    }

    PosixFile(const PosixFile&) = delete;
    PosixFile& operator=(const PosixFile&) = delete;

    [[nodiscard]] int get() const noexcept { return descriptor_; }

    void close_checked() {
        if (descriptor_ < 0) {
            return;
        }
        const int descriptor = descriptor_;
        descriptor_ = -1;
        if (::close(descriptor) != 0) {
            throw Error("failed to close exported wordlist file; an incomplete "
                        "new file may remain");
        }
    }

  private:
    int descriptor_{-1};
};

#endif

}  // namespace

void write_new_binary_file(const std::string& path,
                           const std::string_view contents) {
    if (path.empty()) {
        throw Error("output file path must not be empty");
    }
    if (contents.size() > static_cast<std::size_t>(
                              std::numeric_limits<std::ptrdiff_t>::max())) {
        throw Error("output is too large for this platform's address space");
    }

    const std::filesystem::path native_path = std::filesystem::u8path(path);

#ifdef _WIN32
    const HANDLE raw_handle = CreateFileW(native_path.c_str(),
                                          GENERIC_WRITE,
                                          0U,
                                          nullptr,
                                          CREATE_NEW,
                                          FILE_ATTRIBUTE_NORMAL |
                                              FILE_FLAG_OPEN_REPARSE_POINT,
                                          nullptr);
    if (raw_handle == INVALID_HANDLE_VALUE) {
        throw_windows_create_error(GetLastError());
    }
    WindowsFile file(raw_handle);

    std::size_t offset = 0U;
    while (offset < contents.size()) {
        constexpr std::size_t kMaximumChunk =
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max());
        const std::size_t chunk =
            std::min(contents.size() - offset, kMaximumChunk);
        DWORD written = 0U;
        if (WriteFile(file.get(),
                      contents.data() + static_cast<std::ptrdiff_t>(offset),
                      static_cast<DWORD>(chunk),
                      &written,
                      nullptr) == 0 ||
            written == 0U) {
            throw Error("failed to write exported wordlist file; an incomplete "
                        "new file may remain");
        }
        offset += static_cast<std::size_t>(written);
    }
    if (FlushFileBuffers(file.get()) == 0) {
        throw Error("failed to flush exported wordlist file; an incomplete "
                    "new file may remain");
    }
    file.close_checked();
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    const int descriptor = ::open(native_path.c_str(), flags, 0666);
    if (descriptor < 0) {
        if (errno == EEXIST) {
            throw Error("output file already exists; refusing to overwrite it");
        }
        throw Error("cannot create output file");
    }
    PosixFile file(descriptor);

    std::size_t offset = 0U;
    while (offset < contents.size()) {
        const std::size_t maximum = static_cast<std::size_t>(
            std::numeric_limits<ssize_t>::max());
        const std::size_t chunk = std::min(contents.size() - offset, maximum);
        const ssize_t written =
            ::write(file.get(),
                    contents.data() + static_cast<std::ptrdiff_t>(offset),
                    chunk);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            throw Error("failed to write exported wordlist file; an incomplete "
                        "new file may remain");
        }
        offset += static_cast<std::size_t>(written);
    }
    if (::fsync(file.get()) != 0) {
        throw Error("failed to flush exported wordlist file; an incomplete "
                    "new file may remain");
    }
    file.close_checked();
#endif
}

}  // namespace arborkdf
