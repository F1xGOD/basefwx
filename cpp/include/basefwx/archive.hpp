#pragma once

#include <filesystem>
#include <string>

namespace basefwx::archive {

enum class PackMode {
    None,
    Tgz,
    Txz
};

struct PackResult {
    std::filesystem::path source;
    PackMode mode = PackMode::None;
    bool used = false;
    std::filesystem::path temp_dir;
};

PackMode DecidePackMode(const std::filesystem::path& input, bool compress);
PackMode PackModeFromFlag(const std::string& flag);
PackMode PackModeFromExtension(const std::filesystem::path& path);
std::string PackFlag(PackMode mode);

PackResult PackInput(const std::filesystem::path& input, bool compress);
void CleanupPack(const PackResult& result);

std::filesystem::path UnpackArchive(const std::filesystem::path& archive,
                                    PackMode mode,
                                    const std::filesystem::path& dest_dir = {});

}  // namespace basefwx::archive
