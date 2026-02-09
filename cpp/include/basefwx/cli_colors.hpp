#pragma once

#include <iostream>
#include <ostream>
#include <string>

namespace basefwx::cli {

// ANSI color codes
namespace color {
    // Reset
    constexpr const char* RESET = "\033[0m";
    
    // Regular colors
    constexpr const char* BLACK = "\033[0;30m";
    constexpr const char* RED = "\033[0;31m";
    constexpr const char* GREEN = "\033[0;32m";
    constexpr const char* YELLOW = "\033[0;33m";
    constexpr const char* BLUE = "\033[0;34m";
    constexpr const char* MAGENTA = "\033[0;35m";
    constexpr const char* CYAN = "\033[0;36m";
    constexpr const char* WHITE = "\033[0;37m";
    
    // Bold colors
    constexpr const char* BOLD_BLACK = "\033[1;30m";
    constexpr const char* BOLD_RED = "\033[1;31m";
    constexpr const char* BOLD_GREEN = "\033[1;32m";
    constexpr const char* BOLD_YELLOW = "\033[1;33m";
    constexpr const char* BOLD_BLUE = "\033[1;34m";
    constexpr const char* BOLD_MAGENTA = "\033[1;35m";
    constexpr const char* BOLD_CYAN = "\033[1;36m";
    constexpr const char* BOLD_WHITE = "\033[1;37m";
    
    // Bright colors
    constexpr const char* BRIGHT_BLACK = "\033[0;90m";
    constexpr const char* BRIGHT_RED = "\033[0;91m";
    constexpr const char* BRIGHT_GREEN = "\033[0;92m";
    constexpr const char* BRIGHT_YELLOW = "\033[0;93m";
    constexpr const char* BRIGHT_BLUE = "\033[0;94m";
    constexpr const char* BRIGHT_MAGENTA = "\033[0;95m";
    constexpr const char* BRIGHT_CYAN = "\033[0;96m";
    constexpr const char* BRIGHT_WHITE = "\033[0;97m";
}

// Check if colors should be enabled for the given stream
bool ColorsEnabled(std::ostream& os = std::cout);

// Set whether colors are enabled (can be disabled via --no-color)
void SetColorsEnabled(bool enabled);

// Colorize text
std::string Colorize(const std::string& text, const char* color);

// Helper functions
inline std::string Red(const std::string& text) { return Colorize(text, color::RED); }
inline std::string Green(const std::string& text) { return Colorize(text, color::GREEN); }
inline std::string Yellow(const std::string& text) { return Colorize(text, color::YELLOW); }
inline std::string Blue(const std::string& text) { return Colorize(text, color::BLUE); }
inline std::string Magenta(const std::string& text) { return Colorize(text, color::MAGENTA); }
inline std::string Cyan(const std::string& text) { return Colorize(text, color::CYAN); }

inline std::string BoldRed(const std::string& text) { return Colorize(text, color::BOLD_RED); }
inline std::string BoldGreen(const std::string& text) { return Colorize(text, color::BOLD_GREEN); }
inline std::string BoldYellow(const std::string& text) { return Colorize(text, color::BOLD_YELLOW); }
inline std::string BoldBlue(const std::string& text) { return Colorize(text, color::BOLD_BLUE); }

}  // namespace basefwx::cli
