#include "basefwx/archive.hpp"

#include "basefwx/constants.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <set>
#include <stdexcept>
#include <system_error>
#include <string_view>
#include <vector>

#include <zlib.h>

#if BASEFWX_HAS_LZMA
#include <lzma.h>
#endif

namespace basefwx::archive {

namespace {

constexpr std::size_t kTarBlockSize = 512;

struct TarHeader {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
};

static_assert(sizeof(TarHeader) == kTarBlockSize, "Tar header must be 512 bytes");

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::filesystem::path CreateTempDir(const std::string& prefix) {
    auto base = std::filesystem::temp_directory_path();
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 64; ++i) {
        auto token = std::to_string(gen());
        auto candidate = base / (prefix + "-" + token);
        std::error_code ec;
        if (std::filesystem::create_directory(candidate, ec)) {
            return candidate;
        }
    }
    throw std::runtime_error("Failed to create temporary directory");
}

void WriteOctal(char* dest, std::size_t size, std::uint64_t value) {
    std::snprintf(dest, size, "%0*llo", static_cast<int>(size - 1),
                  static_cast<unsigned long long>(value));
}

std::uint64_t ParseOctal(const char* data, std::size_t size) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        char ch = data[i];
        if (ch == '\0' || ch == ' ') {
            continue;
        }
        if (ch < '0' || ch > '7') {
            break;
        }
        value = (value << 3) + static_cast<std::uint64_t>(ch - '0');
    }
    return value;
}

bool SplitTarName(const std::string& full, std::string& name, std::string& prefix) {
    if (full.size() <= sizeof(TarHeader::name)) {
        name = full;
        prefix.clear();
        return true;
    }
    if (full.size() > sizeof(TarHeader::name) + sizeof(TarHeader::prefix)) {
        return false;
    }
    auto pos = full.rfind('/');
    while (pos != std::string::npos) {
        std::string candidate_prefix = full.substr(0, pos);
        std::string candidate_name = full.substr(pos + 1);
        if (candidate_name.size() <= sizeof(TarHeader::name)
            && candidate_prefix.size() <= sizeof(TarHeader::prefix)) {
            name = candidate_name;
            prefix = candidate_prefix;
            return true;
        }
        if (pos == 0) {
            break;
        }
        pos = full.rfind('/', pos - 1);
    }
    return false;
}

void WriteHeader(std::ofstream& out, const std::string& entry_name, std::uint64_t size, bool is_dir) {
    TarHeader header{};
    std::string name_field;
    std::string prefix_field;
    if (!SplitTarName(entry_name, name_field, prefix_field)) {
        throw std::runtime_error("Tar entry name too long: " + entry_name);
    }
    std::memcpy(header.name, name_field.c_str(), name_field.size());
    std::memcpy(header.prefix, prefix_field.c_str(), prefix_field.size());
    WriteOctal(header.mode, sizeof(header.mode), is_dir ? 0755 : 0644);
    WriteOctal(header.uid, sizeof(header.uid), 0);
    WriteOctal(header.gid, sizeof(header.gid), 0);
    WriteOctal(header.size, sizeof(header.size), is_dir ? 0 : size);
    WriteOctal(header.mtime, sizeof(header.mtime),
               static_cast<std::uint64_t>(std::time(nullptr)));
    header.typeflag = is_dir ? '5' : '0';
    std::memcpy(header.magic, "ustar", 5);
    std::memcpy(header.version, "00", 2);

    std::memset(header.chksum, ' ', sizeof(header.chksum));
    unsigned int sum = 0;
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&header);
    for (std::size_t i = 0; i < sizeof(TarHeader); ++i) {
        sum += bytes[i];
    }
    std::snprintf(header.chksum, sizeof(header.chksum), "%06o", sum);
    header.chksum[6] = '\0';
    header.chksum[7] = ' ';

    out.write(reinterpret_cast<const char*>(&header), sizeof(TarHeader));
}

void WriteFileData(std::ofstream& out, const std::filesystem::path& path, std::uint64_t size) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::array<char, 1 << 16> buffer{};
    std::uint64_t remaining = size;
    while (remaining > 0) {
        std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
        input.read(buffer.data(), static_cast<std::streamsize>(chunk));
        if (input.gcount() != static_cast<std::streamsize>(chunk)) {
            throw std::runtime_error("Failed to read file: " + path.string());
        }
        out.write(buffer.data(), static_cast<std::streamsize>(chunk));
        remaining -= chunk;
    }
    std::size_t pad = static_cast<std::size_t>((kTarBlockSize - (size % kTarBlockSize)) % kTarBlockSize);
    if (pad) {
        std::array<char, kTarBlockSize> zeros{};
        out.write(zeros.data(), static_cast<std::streamsize>(pad));
    }
}

void WriteTarArchive(const std::filesystem::path& input, const std::filesystem::path& tar_path) {
    std::ofstream out(tar_path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open tar output: " + tar_path.string());
    }

    std::string root_name = input.filename().string();
    std::error_code ec;
    if (std::filesystem::is_directory(input, ec)) {
        std::string root_entry = root_name;
        if (!root_entry.empty() && root_entry.back() != '/') {
            root_entry.push_back('/');
        }
        WriteHeader(out, root_entry, 0, true);
        for (const auto& entry : std::filesystem::recursive_directory_iterator(input)) {
            if (entry.is_symlink()) {
                continue;
            }
            auto rel = std::filesystem::relative(entry.path(), input);
            std::string name = (std::filesystem::path(root_name) / rel).generic_string();
            if (entry.is_directory()) {
                if (!name.empty() && name.back() != '/') {
                    name.push_back('/');
                }
                WriteHeader(out, name, 0, true);
            } else if (entry.is_regular_file()) {
                std::uint64_t size = static_cast<std::uint64_t>(entry.file_size());
                WriteHeader(out, name, size, false);
                WriteFileData(out, entry.path(), size);
            }
        }
    } else {
        std::uint64_t size = static_cast<std::uint64_t>(std::filesystem::file_size(input));
        WriteHeader(out, root_name, size, false);
        WriteFileData(out, input, size);
    }

    std::array<char, kTarBlockSize> zeros{};
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
}

bool IsAllZero(const TarHeader& header) {
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&header);
    for (std::size_t i = 0; i < sizeof(TarHeader); ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

std::string ExtractName(const TarHeader& header) {
    std::string name(header.name, header.name + sizeof(header.name));
    name = name.c_str();
    std::string prefix(header.prefix, header.prefix + sizeof(header.prefix));
    prefix = prefix.c_str();
    if (!prefix.empty()) {
        return prefix + "/" + name;
    }
    return name;
}

bool IsSafePath(const std::filesystem::path& dest_dir, const std::string& name) {
    std::filesystem::path rel(name);
    if (rel.is_absolute()) {
        return false;
    }
    for (const auto& part : rel) {
        if (part == "..") {
            return false;
        }
    }
    auto base = dest_dir.lexically_normal();
    auto full = (dest_dir / rel).lexically_normal();
    auto mismatch = std::mismatch(base.begin(), base.end(), full.begin());
    return mismatch.first == base.end();
}

std::filesystem::path ExtractTar(const std::filesystem::path& tar_path,
                                 const std::filesystem::path& dest_dir) {
    std::ifstream input(tar_path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open tar archive: " + tar_path.string());
    }
    std::set<std::string> roots;
    while (true) {
        TarHeader header{};
        input.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (input.gcount() == 0) {
            break;
        }
        if (input.gcount() != static_cast<std::streamsize>(sizeof(header))) {
            throw std::runtime_error("Truncated tar archive");
        }
        if (IsAllZero(header)) {
            break;
        }
        std::string name = ExtractName(header);
        if (name.empty()) {
            continue;
        }
        if (!IsSafePath(dest_dir, name)) {
            throw std::runtime_error("Unsafe tar entry detected");
        }
        std::filesystem::path out_path = dest_dir / std::filesystem::path(name);
        if (!name.empty()) {
            std::filesystem::path rel(name);
            if (!rel.empty()) {
                roots.insert((*rel.begin()).string());
            }
        }

        std::uint64_t size = ParseOctal(header.size, sizeof(header.size));
        char type = header.typeflag;
        if (type == '5') {
            std::error_code ec;
            std::filesystem::create_directories(out_path, ec);
        } else if (type == '0' || type == '\0') {
            std::error_code ec;
            std::filesystem::create_directories(out_path.parent_path(), ec);
            std::ofstream output(out_path, std::ios::binary);
            if (!output) {
                throw std::runtime_error("Failed to write output: " + out_path.string());
            }
            std::array<char, 1 << 16> buffer{};
            std::uint64_t remaining = size;
            while (remaining > 0) {
                std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
                input.read(buffer.data(), static_cast<std::streamsize>(chunk));
                if (input.gcount() != static_cast<std::streamsize>(chunk)) {
                    throw std::runtime_error("Truncated tar archive");
                }
                output.write(buffer.data(), static_cast<std::streamsize>(chunk));
                remaining -= chunk;
            }
        } else {
            std::array<char, 1 << 16> buffer{};
            std::uint64_t remaining = size;
            while (remaining > 0) {
                std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
                input.read(buffer.data(), static_cast<std::streamsize>(chunk));
                if (input.gcount() != static_cast<std::streamsize>(chunk)) {
                    throw std::runtime_error("Truncated tar archive");
                }
                remaining -= chunk;
            }
        }
        std::size_t pad = static_cast<std::size_t>((kTarBlockSize - (size % kTarBlockSize)) % kTarBlockSize);
        if (pad) {
            input.seekg(static_cast<std::streamoff>(pad), std::ios::cur);
        }
    }

    if (roots.size() == 1) {
        return dest_dir / *roots.begin();
    }
    return dest_dir;
}

void CompressGzip(const std::filesystem::path& input,
                  const std::filesystem::path& output,
                  int level) {
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input for gzip: " + input.string());
    }
    std::string mode = "wb" + std::to_string(level);
    gzFile gz = gzopen(output.string().c_str(), mode.c_str());
    if (!gz) {
        throw std::runtime_error("Failed to open gzip output: " + output.string());
    }
    std::array<char, 1 << 16> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = in.gcount();
        if (got > 0) {
            int written = gzwrite(gz, buffer.data(), static_cast<unsigned int>(got));
            if (written == 0) {
                gzclose(gz);
                throw std::runtime_error("Failed to write gzip output");
            }
        }
    }
    gzclose(gz);
}

void DecompressGzip(const std::filesystem::path& input,
                    const std::filesystem::path& output) {
    gzFile gz = gzopen(input.string().c_str(), "rb");
    if (!gz) {
        throw std::runtime_error("Failed to open gzip input: " + input.string());
    }
    std::ofstream out(output, std::ios::binary);
    if (!out) {
        gzclose(gz);
        throw std::runtime_error("Failed to open gzip output: " + output.string());
    }
    std::array<char, 1 << 16> buffer{};
    int read_bytes = 0;
    while ((read_bytes = gzread(gz, buffer.data(), static_cast<unsigned int>(buffer.size()))) > 0) {
        out.write(buffer.data(), read_bytes);
    }
    if (read_bytes < 0) {
        gzclose(gz);
        throw std::runtime_error("Failed to read gzip input");
    }
    gzclose(gz);
}

#if BASEFWX_HAS_LZMA
void CompressXz(const std::filesystem::path& input, const std::filesystem::path& output) {
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input for xz: " + input.string());
    }
    std::ofstream out(output, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open xz output: " + output.string());
    }
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_easy_encoder(&strm,
                                     9 | LZMA_PRESET_EXTREME,
                                     LZMA_CHECK_CRC64);
    if (ret != LZMA_OK) {
        throw std::runtime_error("Failed to initialize xz encoder");
    }
    std::array<std::uint8_t, 1 << 16> in_buf{};
    std::array<std::uint8_t, 1 << 16> out_buf{};
    while (true) {
        in.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(in_buf.size()));
        std::streamsize got = in.gcount();
        strm.next_in = in_buf.data();
        strm.avail_in = static_cast<std::size_t>(got);
        lzma_action action = in.eof() ? LZMA_FINISH : LZMA_RUN;
        do {
            strm.next_out = out_buf.data();
            strm.avail_out = out_buf.size();
            ret = lzma_code(&strm, action);
            if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
                lzma_end(&strm);
                throw std::runtime_error("XZ compression failed");
            }
            std::size_t write_size = out_buf.size() - strm.avail_out;
            if (write_size > 0) {
                out.write(reinterpret_cast<char*>(out_buf.data()),
                          static_cast<std::streamsize>(write_size));
            }
        } while (strm.avail_out == 0);
        if (ret == LZMA_STREAM_END) {
            break;
        }
    }
    lzma_end(&strm);
}

void DecompressXz(const std::filesystem::path& input, const std::filesystem::path& output) {
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open xz input: " + input.string());
    }
    std::ofstream out(output, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open xz output: " + output.string());
    }
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK) {
        throw std::runtime_error("Failed to initialize xz decoder");
    }
    std::array<std::uint8_t, 1 << 16> in_buf{};
    std::array<std::uint8_t, 1 << 16> out_buf{};
    bool eof = false;
    while (true) {
        if (strm.avail_in == 0 && !eof) {
            in.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(in_buf.size()));
            std::streamsize got = in.gcount();
            if (got == 0) {
                eof = true;
            } else {
                strm.next_in = in_buf.data();
                strm.avail_in = static_cast<std::size_t>(got);
            }
        }
        strm.next_out = out_buf.data();
        strm.avail_out = out_buf.size();
        ret = lzma_code(&strm, LZMA_RUN);
        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
            lzma_end(&strm);
            throw std::runtime_error("XZ decompression failed");
        }
        std::size_t write_size = out_buf.size() - strm.avail_out;
        if (write_size > 0) {
            out.write(reinterpret_cast<char*>(out_buf.data()),
                      static_cast<std::streamsize>(write_size));
        }
        if (ret == LZMA_STREAM_END) {
            break;
        }
        if (eof && strm.avail_in == 0) {
            break;
        }
    }
    lzma_end(&strm);
}
#endif

void CompressArchive(const std::filesystem::path& tar_path,
                     const std::filesystem::path& archive_path,
                     PackMode mode) {
    if (mode == PackMode::Tgz) {
        CompressGzip(tar_path, archive_path, 1);
        return;
    }
    if (mode == PackMode::Txz) {
#if BASEFWX_HAS_LZMA
        CompressXz(tar_path, archive_path);
#else
        throw std::runtime_error("XZ support unavailable (liblzma missing)");
#endif
    }
}

void DecompressArchive(const std::filesystem::path& archive_path,
                       const std::filesystem::path& tar_path,
                       PackMode mode) {
    if (mode == PackMode::Tgz) {
        DecompressGzip(archive_path, tar_path);
        return;
    }
    if (mode == PackMode::Txz) {
#if BASEFWX_HAS_LZMA
        DecompressXz(archive_path, tar_path);
#else
        throw std::runtime_error("XZ support unavailable (liblzma missing)");
#endif
    }
}

}  // namespace

PackMode DecidePackMode(const std::filesystem::path& input, bool compress) {
    std::error_code ec;
    bool is_dir = std::filesystem::is_directory(input, ec);
    if (is_dir) {
        return compress ? PackMode::Txz : PackMode::Tgz;
    }
    if (compress) {
        return PackMode::Txz;
    }
    return PackMode::None;
}

PackMode PackModeFromFlag(const std::string& flag) {
    std::string lower = ToLower(flag);
    if (lower == "g") {
        return PackMode::Tgz;
    }
    if (lower == "x") {
        return PackMode::Txz;
    }
    return PackMode::None;
}

PackMode PackModeFromExtension(const std::filesystem::path& path) {
    std::string ext = ToLower(path.extension().string());
    if (ext == std::string(constants::kPackTgzExt)) {
        return PackMode::Tgz;
    }
    if (ext == std::string(constants::kPackTxzExt)) {
        return PackMode::Txz;
    }
    return PackMode::None;
}

std::string PackFlag(PackMode mode) {
    if (mode == PackMode::Tgz) {
        return "g";
    }
    if (mode == PackMode::Txz) {
        return "x";
    }
    return {};
}

PackResult PackInput(const std::filesystem::path& input, bool compress) {
    PackMode mode = DecidePackMode(input, compress);
    if (mode == PackMode::None) {
        return {input, mode, false, {}};
    }
    auto temp_dir = CreateTempDir("basefwx-pack");
    std::string base_name;
    if (std::filesystem::is_directory(input)) {
        base_name = input.filename().string();
    } else {
        base_name = input.stem().string();
    }
    if (base_name.empty()) {
        base_name = "archive";
    }
    auto tar_path = temp_dir / (base_name + ".tar");
    auto archive_ext = (mode == PackMode::Txz) ? std::string(constants::kPackTxzExt)
                                              : std::string(constants::kPackTgzExt);
    auto archive_path = temp_dir / (base_name + archive_ext);
    try {
        WriteTarArchive(input, tar_path);
        CompressArchive(tar_path, archive_path, mode);
        std::error_code ec;
        std::filesystem::remove(tar_path, ec);
        return {archive_path, mode, true, temp_dir};
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir, ec);
        throw;
    }
}

void CleanupPack(const PackResult& result) {
    if (!result.used || result.temp_dir.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::remove_all(result.temp_dir, ec);
}

std::filesystem::path UnpackArchive(const std::filesystem::path& archive,
                                    PackMode mode,
                                    const std::filesystem::path& dest_dir) {
    if (mode == PackMode::None) {
        return archive;
    }
    auto temp_dir = CreateTempDir("basefwx-unpack");
    auto tar_path = temp_dir / "payload.tar";
    DecompressArchive(archive, tar_path, mode);
    auto output_dir = dest_dir.empty() ? archive.parent_path() : dest_dir;
    auto extracted_root = ExtractTar(tar_path, output_dir);
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    std::filesystem::remove(archive, ec);
    return extracted_root;
}

}  // namespace basefwx::archive
