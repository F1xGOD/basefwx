#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace basefwx {

struct An7Options {
    bool force_any = false;
    bool keep_input = false;
    std::optional<std::filesystem::path> out;
};

struct Dean7Options {
    bool keep_input = false;
    std::optional<std::filesystem::path> out;
};

struct Dean7Result {
    std::filesystem::path output_path;
    std::string restored_name;
    std::uint64_t bytes_written = 0;
};

void an7_file(const std::filesystem::path& input,
              const std::string& password,
              const An7Options& opts = {});

Dean7Result dean7_file(const std::filesystem::path& input,
                       const std::string& password,
                       const Dean7Options& opts = {});

}  // namespace basefwx
