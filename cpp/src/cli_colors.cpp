#include "basefwx/cli_colors.hpp"

#include <iostream>

#if defined(_WIN32) || defined(_WIN64)
    #include <io.h>
    #include <windows.h>
    #define isatty _isatty
    #define fileno _fileno
    
    #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
        #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
    #endif
#else
    #include <unistd.h>
#endif

namespace basefwx::cli {

namespace {
    bool g_colors_enabled = true;
    bool g_colors_checked = false;
    
#if defined(_WIN32) || defined(_WIN64)
    // Enable Windows 10+ ANSI color support
    bool EnableWindowsAnsiColors() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        DWORD mode = 0;
        if (!GetConsoleMode(hOut, &mode)) {
            return false;
        }
        
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        return SetConsoleMode(hOut, mode) != 0;
    }
#endif
}

bool ColorsEnabled(std::ostream& os) {
    if (!g_colors_checked) {
        // Auto-detect: check if output is a TTY
        bool is_tty = false;
        if (&os == &std::cout) {
            is_tty = isatty(fileno(stdout)) != 0;
        } else if (&os == &std::cerr) {
            is_tty = isatty(fileno(stderr)) != 0;
        }
        
        g_colors_enabled = is_tty;
        
#if defined(_WIN32) || defined(_WIN64)
        // On Windows, also enable ANSI processing
        if (is_tty) {
            g_colors_enabled = EnableWindowsAnsiColors();
        }
#endif
        
        g_colors_checked = true;
    }
    return g_colors_enabled;
}

void SetColorsEnabled(bool enabled) {
    g_colors_enabled = enabled;
    g_colors_checked = true;
}

std::string Colorize(const std::string& text, const char* color) {
    if (!ColorsEnabled()) {
        return text;
    }
    return std::string(color) + text + color::RESET;
}

}  // namespace basefwx::cli
