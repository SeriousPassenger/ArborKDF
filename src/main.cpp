#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "arborkdf/cli.hpp"

#ifdef _WIN32

#include <windows.h>

#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class WindowsModule final {
public:
    explicit WindowsModule(const wchar_t* const name) : value_(LoadLibraryW(name)) {
        if (value_ == nullptr) {
            throw std::runtime_error("failed to load a required Windows system library");
        }
    }

    ~WindowsModule() { static_cast<void>(FreeLibrary(value_)); }

    WindowsModule(const WindowsModule&) = delete;
    WindowsModule& operator=(const WindowsModule&) = delete;

    [[nodiscard]] HMODULE get() const noexcept { return value_; }

private:
    HMODULE value_{};
};

class WindowsLocalMemory final {
public:
    explicit WindowsLocalMemory(void* const value) noexcept : value_(value) {}
    ~WindowsLocalMemory() {
        if (value_ != nullptr) {
            static_cast<void>(LocalFree(static_cast<HLOCAL>(value_)));
        }
    }

    WindowsLocalMemory(const WindowsLocalMemory&) = delete;
    WindowsLocalMemory& operator=(const WindowsLocalMemory&) = delete;

private:
    void* value_{};
};

class WindowsConsoleCodePages final {
public:
    WindowsConsoleCodePages()
        : original_input_(GetConsoleCP()),
          original_output_(GetConsoleOutputCP()) {
        if (original_input_ != 0U && original_input_ != CP_UTF8) {
            if (SetConsoleCP(CP_UTF8) == 0) {
                throw std::runtime_error("failed to configure UTF-8 Windows console input");
            }
            changed_input_ = true;
        }
        if (original_output_ != 0U && original_output_ != CP_UTF8) {
            if (SetConsoleOutputCP(CP_UTF8) == 0) {
                restore_input();
                throw std::runtime_error("failed to configure UTF-8 Windows console output");
            }
            changed_output_ = true;
        }
    }

    ~WindowsConsoleCodePages() {
        if (changed_output_) {
            static_cast<void>(SetConsoleOutputCP(original_output_));
        }
        restore_input();
    }

    WindowsConsoleCodePages(const WindowsConsoleCodePages&) = delete;
    WindowsConsoleCodePages& operator=(const WindowsConsoleCodePages&) = delete;

private:
    void restore_input() noexcept {
        if (changed_input_) {
            static_cast<void>(SetConsoleCP(original_input_));
            changed_input_ = false;
        }
    }

    UINT original_input_{};
    UINT original_output_{};
    bool changed_input_{};
    bool changed_output_{};
};

using CommandLineToArgvWFunction = LPWSTR*(WINAPI*)(LPCWSTR, int*);

[[nodiscard]] CommandLineToArgvWFunction load_command_line_parser(
    const WindowsModule& shell_module) {
    const FARPROC address =
        GetProcAddress(shell_module.get(), "CommandLineToArgvW");
    if (address == nullptr) {
        throw std::runtime_error("failed to load the Windows command-line parser");
    }
    static_assert(sizeof(CommandLineToArgvWFunction) == sizeof(FARPROC),
                  "Windows function pointers must have a uniform representation");
    CommandLineToArgvWFunction parser = nullptr;
    std::memcpy(&parser, &address, sizeof(parser));
    return parser;
}

[[nodiscard]] std::string wide_argument_to_utf8(const wchar_t* const value) {
    if (value == nullptr) {
        throw std::runtime_error("Windows returned a null command-line argument");
    }
    const std::size_t length = std::char_traits<wchar_t>::length(value);
    if (length == 0U) {
        return {};
    }
    if (length > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("a command-line argument exceeds the Windows API limit");
    }
    const int source_size = static_cast<int>(length);
    const int required = WideCharToMultiByte(CP_UTF8,
                                             WC_ERR_INVALID_CHARS,
                                             value,
                                             source_size,
                                             nullptr,
                                             0,
                                             nullptr,
                                             nullptr);
    if (required <= 0) {
        throw std::runtime_error("a command-line argument is not valid UTF-16");
    }
    std::string output(static_cast<std::size_t>(required), '\0');
    const int converted = WideCharToMultiByte(CP_UTF8,
                                              WC_ERR_INVALID_CHARS,
                                              value,
                                              source_size,
                                              output.data(),
                                              required,
                                              nullptr,
                                              nullptr);
    if (converted != required) {
        throw std::runtime_error("failed to convert a command-line argument to UTF-8");
    }
    return output;
}

[[nodiscard]] int run_windows_cli() {
    const WindowsConsoleCodePages console_code_pages;
    const WindowsModule shell_module(L"shell32.dll");
    const CommandLineToArgvWFunction parse_command_line =
        load_command_line_parser(shell_module);
    int argument_count = 0;
    LPWSTR* const wide_arguments =
        parse_command_line(GetCommandLineW(), &argument_count);
    if (wide_arguments == nullptr || argument_count <= 0) {
        throw std::runtime_error("failed to parse the Windows command line");
    }
    const WindowsLocalMemory arguments_guard(wide_arguments);

    std::vector<std::string> arguments;
    arguments.reserve(static_cast<std::size_t>(argument_count));
    for (int index = 0; index < argument_count; ++index) {
        arguments.push_back(wide_argument_to_utf8(wide_arguments[index]));
    }

    std::vector<char*> argument_pointers;
    argument_pointers.reserve(arguments.size() + 1U);
    for (std::string& argument : arguments) {
        argument_pointers.push_back(argument.data());
    }
    argument_pointers.push_back(nullptr);
    return arborkdf::run_cli(argument_count, argument_pointers.data());
}

}  // namespace

int main() {
    try {
        return run_windows_cli();
    } catch (const std::exception& exception) {
        std::cerr << "error: " << exception.what() << '\n';
        return 2;
    }
}

#else

int main(int argc, char* argv[]) { return arborkdf::run_cli(argc, argv); }

#endif
