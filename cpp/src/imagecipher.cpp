#include "basefwx/imagecipher.hpp"

#include "basefwx/constants.hpp"
#include "basefwx/crypto.hpp"
#include "basefwx/env.hpp"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_FAILURE_USERMSG
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace basefwx::imagecipher {

namespace {

using basefwx::crypto::Bytes;

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::filesystem::path NormalizePath(const std::string& path) {
    std::filesystem::path p(path);
    p = p.lexically_normal();
    if (p.is_relative()) {
        return std::filesystem::absolute(p);
    }
    return p;
}

Bytes ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    std::streamoff size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to read file size: " + path.string());
    }
    input.seekg(0, std::ios::beg);
    Bytes data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!input) {
            throw std::runtime_error("Failed to read file: " + path.string());
        }
    }
    return data;
}

void WriteFileBytes(const std::filesystem::path& path, const Bytes& data) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to open output file: " + path.string());
    }
    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!output) {
            throw std::runtime_error("Failed to write output file: " + path.string());
        }
    }
}

std::string ExtensionLower(const std::filesystem::path& path) {
    std::string ext = path.extension().string();
    if (!ext.empty() && ext[0] == '.') {
        ext.erase(0, 1);
    }
    return ToLower(ext);
}

std::uint32_t ParseIterations(const std::string& raw, std::uint32_t fallback) {
    if (raw.empty()) {
        return fallback;
    }
    try {
        std::uint64_t parsed = static_cast<std::uint64_t>(std::stoul(raw));
        if (parsed == 0) {
            return fallback;
        }
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            return std::numeric_limits<std::uint32_t>::max();
        }
        return static_cast<std::uint32_t>(parsed);
    } catch (const std::exception&) {
        return fallback;
    }
}

std::uint32_t ResolveImageKdfIterations() {
    std::string raw = basefwx::env::Get("BASEFWX_USER_KDF_ITERS");
    if (raw.empty()) {
        raw = basefwx::env::Get("BASEFWX_TEST_KDF_ITERS");
    }
    std::uint32_t parsed = ParseIterations(raw, basefwx::constants::kUserKdfIterations);
    return std::max<std::uint32_t>(200000, parsed);
}

Bytes DeriveMaterial(const std::string& password) {
    Bytes salt(basefwx::constants::kImageCipherStreamInfo.begin(),
               basefwx::constants::kImageCipherStreamInfo.end());
    std::uint32_t iters = ResolveImageKdfIterations();
    return basefwx::crypto::Pbkdf2HmacSha256(password, salt, iters, 64);
}

std::uint64_t ReadU64Be(const std::uint8_t* data) {
    return (static_cast<std::uint64_t>(data[0]) << 56)
           | (static_cast<std::uint64_t>(data[1]) << 48)
           | (static_cast<std::uint64_t>(data[2]) << 40)
           | (static_cast<std::uint64_t>(data[3]) << 32)
           | (static_cast<std::uint64_t>(data[4]) << 24)
           | (static_cast<std::uint64_t>(data[5]) << 16)
           | (static_cast<std::uint64_t>(data[6]) << 8)
           | (static_cast<std::uint64_t>(data[7]));
}

struct Xoroshiro128Plus {
    std::uint64_t s0 = 0;
    std::uint64_t s1 = 0;

    static std::uint64_t Rotl(std::uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }

    std::uint64_t Next() {
        std::uint64_t result = s0 + s1;
        std::uint64_t t = s1 ^ s0;
        s0 = Rotl(s0, 55) ^ t ^ (t << 14);
        s1 = Rotl(t, 36);
        return result;
    }

    std::uint64_t NextBounded(std::uint64_t bound) {
        if (bound == 0) {
            return 0;
        }
        std::uint64_t threshold = (~bound + 1) % bound;
        while (true) {
            std::uint64_t value = Next();
            if (value >= threshold) {
                return value % bound;
            }
        }
    }
};

struct ImageBuffer {
    int width = 0;
    int height = 0;
    int channels = 0;
    Bytes pixels;
};

ImageBuffer DecodeImage(const Bytes& blob, const std::filesystem::path& path_hint) {
    int width = 0;
    int height = 0;
    int channels_in_file = 0;
    if (!stbi_info_from_memory(blob.data(), static_cast<int>(blob.size()),
                               &width, &height, &channels_in_file)) {
        throw std::runtime_error("Unsupported image input: " + path_hint.string());
    }
    int target_channels = 0;
    if (channels_in_file == 1) {
        target_channels = 1;
    } else if (channels_in_file >= 4) {
        target_channels = 4;
    } else {
        target_channels = 3;
    }

    int loaded_channels = 0;
    unsigned char* data = stbi_load_from_memory(blob.data(), static_cast<int>(blob.size()),
                                                &width, &height, &loaded_channels,
                                                target_channels);
    if (!data) {
        const char* reason = stbi_failure_reason();
        std::string msg = reason ? reason : "unknown error";
        throw std::runtime_error("Failed to decode image: " + msg);
    }
    std::size_t total = static_cast<std::size_t>(width) * static_cast<std::size_t>(height)
                        * static_cast<std::size_t>(target_channels);
    Bytes pixels(data, data + total);
    stbi_image_free(data);

    ImageBuffer buffer;
    buffer.width = width;
    buffer.height = height;
    buffer.channels = target_channels;
    buffer.pixels = std::move(pixels);
    return buffer;
}

void WriteImage(const std::filesystem::path& path,
                const ImageBuffer& image,
                const std::string& format) {
    std::filesystem::create_directories(path.parent_path());
    std::string fmt = ToLower(format);

    const int width = image.width;
    const int height = image.height;
    int channels = image.channels;
    Bytes pixels = image.pixels;

    if ((fmt == "jpg" || fmt == "jpeg") && channels == 4) {
        Bytes rgb;
        rgb.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 3);
        for (int i = 0; i < width * height; ++i) {
            rgb[i * 3] = pixels[i * 4];
            rgb[i * 3 + 1] = pixels[i * 4 + 1];
            rgb[i * 3 + 2] = pixels[i * 4 + 2];
        }
        pixels.swap(rgb);
        channels = 3;
    }

    std::filesystem::path temp = path;
    temp += "._tmp";

    int ok = 0;
    if (fmt == "png") {
        ok = stbi_write_png(temp.string().c_str(), width, height, channels,
                            pixels.data(), width * channels);
    } else if (fmt == "jpg" || fmt == "jpeg") {
        ok = stbi_write_jpg(temp.string().c_str(), width, height, channels,
                            pixels.data(), 90);
    } else if (fmt == "bmp") {
        ok = stbi_write_bmp(temp.string().c_str(), width, height, channels,
                            pixels.data());
    } else if (fmt == "tga") {
        ok = stbi_write_tga(temp.string().c_str(), width, height, channels,
                            pixels.data());
    } else {
        throw std::runtime_error("Unsupported image format: " + format);
    }

    if (ok == 0) {
        throw std::runtime_error("Failed to write image: " + path.string());
    }

    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        throw std::runtime_error("Failed to finalize image output: " + path.string());
    }
}

void AppendTrailer(const std::filesystem::path& path, const Bytes& blob) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) {
        throw std::runtime_error("Failed to append trailer: " + path.string());
    }
    const auto magic = basefwx::constants::kImageCipherTrailerMagic;
    out.write(magic.data(), static_cast<std::streamsize>(magic.size()));
    std::array<std::uint8_t, 4> len_bytes{};
    std::uint32_t len = static_cast<std::uint32_t>(blob.size());
    len_bytes[0] = static_cast<std::uint8_t>((len >> 24) & 0xFF);
    len_bytes[1] = static_cast<std::uint8_t>((len >> 16) & 0xFF);
    len_bytes[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    len_bytes[3] = static_cast<std::uint8_t>(len & 0xFF);
    out.write(reinterpret_cast<const char*>(len_bytes.data()),
              static_cast<std::streamsize>(len_bytes.size()));
    if (!blob.empty()) {
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }
    if (!out) {
        throw std::runtime_error("Failed to append trailer: " + path.string());
    }
}

bool ExtractTrailer(const Bytes& data, Bytes& payload, Bytes& trailer) {
    std::string magic(basefwx::constants::kImageCipherTrailerMagic.begin(),
                      basefwx::constants::kImageCipherTrailerMagic.end());
    if (magic.size() != 4) {
        return false;
    }
    std::size_t idx = data.size();
    bool found = false;
    for (std::size_t i = data.size(); i-- > 0;) {
        if (i + magic.size() > data.size()) {
            continue;
        }
        if (std::memcmp(data.data() + i, magic.data(), magic.size()) == 0) {
            idx = i;
            found = true;
            break;
        }
    }
    if (!found) {
        payload = data;
        return false;
    }
    if (idx + magic.size() + 4 > data.size()) {
        payload = data;
        return false;
    }
    std::uint32_t len = (static_cast<std::uint32_t>(data[idx + 4]) << 24)
                        | (static_cast<std::uint32_t>(data[idx + 5]) << 16)
                        | (static_cast<std::uint32_t>(data[idx + 6]) << 8)
                        | static_cast<std::uint32_t>(data[idx + 7]);
    std::size_t blob_start = idx + magic.size() + 4;
    std::size_t blob_end = blob_start + len;
    if (blob_end > data.size()) {
        payload = data;
        return false;
    }
    payload.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(idx));
    trailer.assign(data.begin() + static_cast<std::ptrdiff_t>(blob_start),
                   data.begin() + static_cast<std::ptrdiff_t>(blob_end));
    return true;
}

void BuildMaskAndShuffle(const std::string& password,
                         std::size_t num_pixels,
                         int channels,
                         std::vector<std::uint8_t>& mask,
                         std::vector<std::uint8_t>& rotations,
                         std::vector<std::size_t>& perm,
                         Bytes& material) {
    material = DeriveMaterial(password);
    Bytes key(material.begin(), material.begin() + 32);
    Bytes nonce(material.begin() + 32, material.begin() + 48);
    std::array<std::uint8_t, 16> seed_bytes{};
    std::copy(material.begin() + 48, material.begin() + 64, seed_bytes.begin());

    std::uint64_t s0 = ReadU64Be(seed_bytes.data());
    std::uint64_t s1 = ReadU64Be(seed_bytes.data() + 8);
    if (s0 == 0 && s1 == 0) {
        s1 = 1;
    }
    Xoroshiro128Plus rng{ s0, s1 };

    std::size_t total = num_pixels * static_cast<std::size_t>(channels);
    Bytes zeros(total, 0);
    Bytes mask_bytes = basefwx::crypto::AesCtrTransform(key, nonce, zeros);
    mask.assign(mask_bytes.begin(), mask_bytes.end());

    rotations.clear();
    if (channels > 1) {
        rotations.resize(num_pixels);
        for (std::size_t i = 0; i < num_pixels; ++i) {
            rotations[i] = static_cast<std::uint8_t>(rng.NextBounded(static_cast<std::uint64_t>(channels)));
        }
    }

    perm.resize(num_pixels);
    for (std::size_t i = 0; i < num_pixels; ++i) {
        perm[i] = i;
    }
    if (num_pixels > 1) {
        for (std::size_t i = num_pixels - 1; i > 0; --i) {
            std::size_t j = static_cast<std::size_t>(rng.NextBounded(static_cast<std::uint64_t>(i + 1)));
            std::swap(perm[i], perm[j]);
        }
    }
}

void ApplyRotation(std::vector<std::uint8_t>& data,
                   std::size_t num_pixels,
                   int channels,
                   const std::vector<std::uint8_t>& rotations,
                   bool invert) {
    if (channels <= 1) {
        return;
    }
    std::array<std::uint8_t, 4> tmp{};
    for (std::size_t i = 0; i < num_pixels; ++i) {
        std::uint8_t r = rotations[i];
        if (r == 0) {
            continue;
        }
        std::uint8_t* row = data.data() + i * static_cast<std::size_t>(channels);
        for (int c = 0; c < channels; ++c) {
            int idx = invert ? (c + channels - r) % channels : (c + r) % channels;
            tmp[c] = row[idx];
        }
        for (int c = 0; c < channels; ++c) {
            row[c] = tmp[c];
        }
    }
}

void ApplyPermutation(std::vector<std::uint8_t>& data,
                      std::size_t num_pixels,
                      int channels,
                      const std::vector<std::size_t>& perm,
                      bool invert) {
    std::vector<std::uint8_t> out(data.size());
    if (!invert) {
        for (std::size_t i = 0; i < num_pixels; ++i) {
            std::size_t src = perm[i];
            std::memcpy(out.data() + i * static_cast<std::size_t>(channels),
                        data.data() + src * static_cast<std::size_t>(channels),
                        static_cast<std::size_t>(channels));
        }
    } else {
        std::vector<std::size_t> inv_perm(num_pixels);
        for (std::size_t i = 0; i < num_pixels; ++i) {
            inv_perm[perm[i]] = i;
        }
        for (std::size_t i = 0; i < num_pixels; ++i) {
            std::size_t src = inv_perm[i];
            std::memcpy(out.data() + i * static_cast<std::size_t>(channels),
                        data.data() + src * static_cast<std::size_t>(channels),
                        static_cast<std::size_t>(channels));
        }
    }
    data.swap(out);
}

void ApplyMask(std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& mask) {
    if (data.size() != mask.size()) {
        throw std::runtime_error("Image mask length mismatch");
    }
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(data[i] ^ mask[i]);
    }
}

}  // namespace

std::string EncryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output) {
    if (password.empty()) {
        throw std::runtime_error("Password is required for image encryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }

    Bytes original_bytes = ReadFileBytes(input_path);
    ImageBuffer image = DecodeImage(original_bytes, input_path);

    std::size_t num_pixels = static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height);
    std::vector<std::uint8_t> mask;
    std::vector<std::uint8_t> rotations;
    std::vector<std::size_t> perm;
    Bytes material;

    BuildMaskAndShuffle(password, num_pixels, image.channels, mask, rotations, perm, material);

    ApplyMask(image.pixels, mask);
    ApplyRotation(image.pixels, num_pixels, image.channels, rotations, false);
    ApplyPermutation(image.pixels, num_pixels, image.channels, perm, false);

    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    if (output_path.extension().empty()) {
        output_path.replace_extension(input_path.extension());
    }
    std::string fmt = ExtensionLower(output_path);
    if (fmt.empty()) {
        fmt = ExtensionLower(input_path);
    }

    WriteImage(output_path, image, fmt);

    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo,
                                                   material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());
    Bytes archive_blob = basefwx::crypto::AeadEncrypt(archive_key, original_bytes, aad);
    AppendTrailer(output_path, archive_blob);

    return output_path.string();
}

std::string DecryptImageInv(const std::string& path,
                            const std::string& password,
                            const std::string& output) {
    if (password.empty()) {
        throw std::runtime_error("Password is required for image decryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }

    Bytes file_bytes = ReadFileBytes(input_path);
    Bytes payload;
    Bytes trailer;
    bool has_trailer = ExtractTrailer(file_bytes, payload, trailer);

    Bytes material = DeriveMaterial(password);
    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo,
                                                   material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());

    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    if (has_trailer && !trailer.empty()) {
        try {
            Bytes original_bytes = basefwx::crypto::AeadDecrypt(archive_key, trailer, aad);
            WriteFileBytes(output_path, original_bytes);
            return output_path.string();
        } catch (const std::exception&) {
        }
    }

    ImageBuffer image = DecodeImage(payload.empty() ? file_bytes : payload, input_path);
    std::size_t num_pixels = static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height);
    std::vector<std::uint8_t> mask;
    std::vector<std::uint8_t> rotations;
    std::vector<std::size_t> perm;
    Bytes material_unused;
    BuildMaskAndShuffle(password, num_pixels, image.channels, mask, rotations, perm, material_unused);

    ApplyPermutation(image.pixels, num_pixels, image.channels, perm, true);
    ApplyRotation(image.pixels, num_pixels, image.channels, rotations, true);
    ApplyMask(image.pixels, mask);

    if (output_path.extension().empty()) {
        output_path.replace_extension(input_path.extension());
    }
    std::string fmt = ExtensionLower(output_path);
    if (fmt.empty()) {
        fmt = ExtensionLower(input_path);
    }

    WriteImage(output_path, image, fmt);
    return output_path.string();
}

namespace {

struct VideoInfo {
    int width = 0;
    int height = 0;
    double fps = 0.0;
    bool valid = false;
};

struct AudioInfo {
    int sample_rate = 0;
    int channels = 0;
    bool valid = false;
};

std::string QuoteArg(const std::string& arg) {
    std::string out;
    out.reserve(arg.size() + 2);
    out.push_back('"');
    for (char ch : arg) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

std::string JoinArgs(const std::vector<std::string>& args) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& arg : args) {
        if (!first) {
            oss << ' ';
        }
        first = false;
        oss << QuoteArg(arg);
    }
    return oss.str();
}

std::string RunCommandCapture(const std::vector<std::string>& args) {
    std::string cmd = JoinArgs(args);
    std::array<char, 4096> buffer{};
    std::string output;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to run command: " + cmd);
    }
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        output.append(buffer.data());
    }
    int rc = pclose(pipe);
    if (rc != 0) {
        throw std::runtime_error("Command failed: " + cmd);
    }
    return output;
}

void RunCommand(const std::vector<std::string>& args) {
    std::string cmd = JoinArgs(args);
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        throw std::runtime_error("Command failed: " + cmd);
    }
}

double ParseRate(const std::string& rate) {
    if (rate.empty()) {
        return 0.0;
    }
    auto pos = rate.find('/');
    try {
        if (pos == std::string::npos) {
            return std::stod(rate);
        }
        double num = std::stod(rate.substr(0, pos));
        double den = std::stod(rate.substr(pos + 1));
        return den == 0.0 ? 0.0 : num / den;
    } catch (const std::exception&) {
        return 0.0;
    }
}

std::vector<std::string> SplitLines(const std::string& input) {
    std::vector<std::string> lines;
    std::istringstream iss(input);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

VideoInfo ProbeVideo(const std::filesystem::path& path) {
    VideoInfo info;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,avg_frame_rate,r_frame_rate",
        "-of", "default=nw=1:nk=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return info;
    }
    auto lines = SplitLines(out);
    if (lines.size() < 2) {
        return info;
    }
    try {
        info.width = std::stoi(lines[0]);
        info.height = std::stoi(lines[1]);
    } catch (const std::exception&) {
        return info;
    }
    double fps = 0.0;
    if (lines.size() >= 3) {
        fps = ParseRate(lines[2]);
    }
    if (fps <= 0.0 && lines.size() >= 4) {
        fps = ParseRate(lines[3]);
    }
    info.fps = fps;
    info.valid = info.width > 0 && info.height > 0;
    return info;
}

AudioInfo ProbeAudio(const std::filesystem::path& path) {
    AudioInfo info;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-select_streams", "a:0",
        "-show_entries", "stream=sample_rate,channels",
        "-of", "default=nw=1:nk=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return info;
    }
    auto lines = SplitLines(out);
    if (lines.size() < 2) {
        return info;
    }
    try {
        info.sample_rate = std::stoi(lines[0]);
        info.channels = std::stoi(lines[1]);
    } catch (const std::exception&) {
        return info;
    }
    info.valid = info.sample_rate > 0 && info.channels > 0;
    return info;
}

std::map<std::string, std::string> ProbeMetadata(const std::filesystem::path& path) {
    std::map<std::string, std::string> tags;
    std::vector<std::string> cmd = {
        "ffprobe", "-v", "error",
        "-show_entries", "format_tags",
        "-of", "default=nw=1",
        path.string()
    };
    std::string out;
    try {
        out = RunCommandCapture(cmd);
    } catch (const std::exception&) {
        return tags;
    }
    auto lines = SplitLines(out);
    for (const auto& line : lines) {
        constexpr std::string_view prefix = "TAG:";
        if (line.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        auto pos = line.find('=');
        if (pos == std::string::npos || pos <= prefix.size()) {
            continue;
        }
        std::string key = line.substr(prefix.size(), pos - prefix.size());
        std::string value = line.substr(pos + 1);
        if (!key.empty() && !value.empty()) {
            tags.emplace(std::move(key), std::move(value));
        }
    }
    return tags;
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

Bytes BaseKeyFromPassword(const std::string& password) {
    Bytes material = DeriveMaterial(password);
    return Bytes(material.begin(), material.begin() + 32);
}

Bytes UnitMaterial(const Bytes& base_key, const std::string& label, std::uint64_t index, std::size_t length) {
    Bytes info(label.begin(), label.end());
    info.push_back(static_cast<std::uint8_t>((index >> 56) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 48) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 40) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 32) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 24) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 16) & 0xFF));
    info.push_back(static_cast<std::uint8_t>((index >> 8) & 0xFF));
    info.push_back(static_cast<std::uint8_t>(index & 0xFF));
    std::string info_str(reinterpret_cast<const char*>(info.data()), info.size());
    return basefwx::crypto::HkdfSha256(info_str, base_key, length);
}

std::uint64_t SplitMix64(std::uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t x = state;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

std::vector<std::size_t> PermuteIndices(std::size_t count, std::uint64_t seed) {
    std::vector<std::size_t> order(count);
    for (std::size_t i = 0; i < count; ++i) {
        order[i] = i;
    }
    std::uint64_t state = seed;
    if (count <= 1) {
        return order;
    }
    for (std::size_t i = count - 1; i > 0; --i) {
        std::uint64_t rnd = SplitMix64(state);
        std::size_t j = static_cast<std::size_t>(rnd % (i + 1));
        if (j != i) {
            std::swap(order[i], order[j]);
        }
    }
    return order;
}

Bytes ShuffleFrameBlocks(const Bytes& frame,
                         int width,
                         int height,
                         int channels,
                         std::uint64_t seed,
                         int block_size) {
    int blocks_x = (width + block_size - 1) / block_size;
    int blocks_y = (height + block_size - 1) / block_size;
    std::size_t total_blocks = static_cast<std::size_t>(blocks_x) * static_cast<std::size_t>(blocks_y);
    auto perm = PermuteIndices(total_blocks, seed);
    Bytes out(frame.size());
    for (std::size_t dest_idx = 0; dest_idx < total_blocks; ++dest_idx) {
        std::size_t src_idx = perm[dest_idx];
        int dx = static_cast<int>(dest_idx % blocks_x) * block_size;
        int dy = static_cast<int>(dest_idx / blocks_x) * block_size;
        int sx = static_cast<int>(src_idx % blocks_x) * block_size;
        int sy = static_cast<int>(src_idx / blocks_x) * block_size;
        int copy_w = std::min(block_size, width - dx);
        copy_w = std::min(copy_w, width - sx);
        int copy_h = std::min(block_size, height - dy);
        copy_h = std::min(copy_h, height - sy);
        for (int row = 0; row < copy_h; ++row) {
            std::size_t src_off = static_cast<std::size_t>(((sy + row) * width + sx) * channels);
            std::size_t dst_off = static_cast<std::size_t>(((dy + row) * width + dx) * channels);
            std::size_t span = static_cast<std::size_t>(copy_w * channels);
            std::memcpy(out.data() + dst_off, frame.data() + src_off, span);
        }
    }
    return out;
}

void ScrambleVideoRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const VideoInfo& video,
                      const Bytes& base_key) {
    std::size_t frame_size = static_cast<std::size_t>(video.width) * static_cast<std::size_t>(video.height) * 3u;
    if (frame_size == 0) {
        throw std::runtime_error("Invalid video dimensions");
    }
    int group_frames = static_cast<int>(std::max(2.0, std::round((video.fps > 0.0 ? video.fps : 30.0) * 1.0)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw video buffers");
    }
    std::uint64_t frame_index = 0;
    std::uint64_t group_index = 0;
    while (true) {
        std::uint64_t group_start_index = frame_index;
        std::vector<Bytes> frames;
        frames.reserve(static_cast<std::size_t>(group_frames));
        for (int i = 0; i < group_frames; ++i) {
            Bytes frame(frame_size);
            input.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
            if (input.gcount() != static_cast<std::streamsize>(frame.size())) {
                break;
            }
            Bytes material = UnitMaterial(base_key, "jmg-frame", frame_index, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            Bytes masked = basefwx::crypto::AesCtrTransform(key, iv, frame);
            Bytes seed_bytes = UnitMaterial(base_key, "jmg-fblk", frame_index, 16);
            std::uint64_t seed = 0;
            for (std::uint8_t b : seed_bytes) {
                seed = (seed << 8) | b;
            }
            Bytes shuffled = ShuffleFrameBlocks(masked, video.width, video.height, 3, seed, 16);
            frames.push_back(std::move(shuffled));
            ++frame_index;
        }
        if (frames.empty()) {
            break;
        }
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, "jmg-fgrp", seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(frames.size(), seed);
        for (auto idx : perm) {
            output.write(reinterpret_cast<const char*>(frames[idx].data()),
                         static_cast<std::streamsize>(frames[idx].size()));
        }
        ++group_index;
    }
}

void ScrambleAudioRaw(const std::filesystem::path& raw_in,
                      const std::filesystem::path& raw_out,
                      const AudioInfo& audio,
                      const Bytes& base_key) {
    int samples_per_block = std::max(1, static_cast<int>(std::round(audio.sample_rate * 0.05)));
    std::size_t block_size = static_cast<std::size_t>(samples_per_block * audio.channels * 2);
    int group_blocks = std::max(2, static_cast<int>(std::round(1.0 / 0.05)));
    std::ifstream input(raw_in, std::ios::binary);
    std::ofstream output(raw_out, std::ios::binary);
    if (!input || !output) {
        throw std::runtime_error("Failed to open raw audio buffers");
    }
    std::uint64_t block_index = 0;
    std::uint64_t group_index = 0;
    while (true) {
        std::uint64_t group_start_index = block_index;
        std::vector<Bytes> blocks;
        blocks.reserve(static_cast<std::size_t>(group_blocks));
        for (int i = 0; i < group_blocks; ++i) {
            Bytes block(block_size);
            input.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(block.size()));
            if (input.gcount() == 0) {
                break;
            }
            block.resize(static_cast<std::size_t>(input.gcount()));
            Bytes material = UnitMaterial(base_key, "jmg-ablock", block_index, 48);
            Bytes key(material.begin(), material.begin() + 32);
            Bytes iv(material.begin() + 32, material.begin() + 48);
            Bytes masked = basefwx::crypto::AesCtrTransform(key, iv, block);
            blocks.push_back(std::move(masked));
            ++block_index;
        }
        if (blocks.empty()) {
            break;
        }
        std::uint64_t seed_index = (group_index * 0x9E3779B97F4A7C15ULL) ^ group_start_index;
        Bytes seed_bytes = UnitMaterial(base_key, "jmg-agrp", seed_index, 16);
        std::uint64_t seed = 0;
        for (std::uint8_t b : seed_bytes) {
            seed = (seed << 8) | b;
        }
        auto perm = PermuteIndices(blocks.size(), seed);
        for (auto idx : perm) {
            output.write(reinterpret_cast<const char*>(blocks[idx].data()),
                         static_cast<std::streamsize>(blocks[idx].size()));
        }
        ++group_index;
    }
}

std::vector<std::string> EncryptMetadataArgs(const std::map<std::string, std::string>& tags,
                                             const std::string& password) {
    std::vector<std::string> args;
    for (const auto& kv : tags) {
        try {
            std::string enc = basefwx::B512Encode(kv.second, password, false, {});
            args.push_back(kv.first + "=" + enc);
        } catch (const std::exception&) {
        }
    }
    return args;
}

bool IsImageExt(const std::filesystem::path& path) {
    static const std::set<std::string> exts = {
        ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp", ".tif", ".tiff", ".heic", ".heif", ".avif", ".ico"
    };
    std::string ext = ToLower(path.extension().string());
    return exts.count(ext) > 0;
}

}  // namespace

std::string EncryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output,
                         bool keep_meta,
                         bool keep_input) {
    if (password.empty()) {
        throw std::runtime_error("Password is required for media encryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }
    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    std::filesystem::path temp_output = output_path;
    if (NormalizePath(output_path.string()) == NormalizePath(input_path.string())) {
        temp_output = output_path.parent_path() / (output_path.stem().string() + "._jmg" + output_path.extension().string());
    }
    Bytes original_bytes = ReadFileBytes(input_path);

    if (IsImageExt(input_path)) {
        std::string result = EncryptImageInv(input_path.string(), password, temp_output.string());
        std::filesystem::path result_path = NormalizePath(result);
        if (result_path != temp_output) {
            temp_output = result_path;
        }
        if (NormalizePath(output_path.string()) != NormalizePath(temp_output.string())) {
            std::filesystem::rename(temp_output, output_path);
            temp_output = output_path;
        }
        if (!keep_input && NormalizePath(output_path.string()) != NormalizePath(input_path.string())) {
            std::error_code ec;
            std::filesystem::remove(input_path, ec);
        }
        return temp_output.string();
    }

    VideoInfo video = ProbeVideo(input_path);
    AudioInfo audio = ProbeAudio(input_path);
    if (!video.valid && !audio.valid) {
        throw std::runtime_error("Unsupported media format");
    }

    std::filesystem::path temp_dir = CreateTempDir("basefwx-media");
    try {
        std::filesystem::path raw_video = temp_dir / "video.raw";
        std::filesystem::path raw_video_out = temp_dir / "video.scr.raw";
        std::filesystem::path raw_audio = temp_dir / "audio.raw";
        std::filesystem::path raw_audio_out = temp_dir / "audio.scr.raw";
        if (video.valid) {
            RunCommand({
                "ffmpeg", "-y", "-i", input_path.string(),
                "-map", "0:v:0",
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                raw_video.string()
            });
        }
        if (audio.valid) {
            RunCommand({
                "ffmpeg", "-y", "-i", input_path.string(),
                "-map", "0:a:0",
                "-f", "s16le",
                "-acodec", "pcm_s16le",
                "-ar", std::to_string(audio.sample_rate),
                "-ac", std::to_string(audio.channels),
                raw_audio.string()
            });
        }

        Bytes base_key = BaseKeyFromPassword(password);
        if (video.valid) {
            ScrambleVideoRaw(raw_video, raw_video_out, video, base_key);
        }
        if (audio.valid) {
            ScrambleAudioRaw(raw_audio, raw_audio_out, audio, base_key);
        }

        std::vector<std::string> cmd = {
            "ffmpeg", "-y"
        };
        if (video.valid) {
            cmd.insert(cmd.end(), {
                "-f", "rawvideo",
                "-pix_fmt", "rgb24",
                "-s", std::to_string(video.width) + "x" + std::to_string(video.height),
                "-r", std::to_string(video.fps > 0.0 ? video.fps : 30.0),
                "-i", raw_video_out.string()
            });
        }
        if (audio.valid) {
            cmd.insert(cmd.end(), {
                "-f", "s16le",
                "-ar", std::to_string(audio.sample_rate),
                "-ac", std::to_string(audio.channels),
                "-i", raw_audio_out.string(),
                "-shortest"
            });
        }
        if (keep_meta) {
            auto tags = ProbeMetadata(input_path);
            for (const auto& meta : EncryptMetadataArgs(tags, password)) {
                cmd.push_back("-metadata");
                cmd.push_back(meta);
            }
        } else {
            cmd.push_back("-map_metadata");
            cmd.push_back("-1");
        }
        cmd.push_back(temp_output.string());
        RunCommand(cmd);
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir, ec);
        throw;
    }
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    Bytes material = DeriveMaterial(password);
    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo, material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());
    Bytes archive_blob = basefwx::crypto::AeadEncrypt(archive_key, original_bytes, aad);
    AppendTrailer(temp_output, archive_blob);

    if (NormalizePath(output_path.string()) != NormalizePath(temp_output.string())) {
        std::filesystem::rename(temp_output, output_path);
        temp_output = output_path;
    }
    if (!keep_input && NormalizePath(output_path.string()) != NormalizePath(input_path.string())) {
        std::filesystem::remove(input_path, ec);
    }
    return temp_output.string();
}

std::string DecryptMedia(const std::string& path,
                         const std::string& password,
                         const std::string& output) {
    if (password.empty()) {
        throw std::runtime_error("Password is required for media decryption");
    }
    std::filesystem::path input_path = NormalizePath(path);
    if (!std::filesystem::exists(input_path)) {
        throw std::runtime_error("Input file not found: " + input_path.string());
    }
    Bytes file_bytes = ReadFileBytes(input_path);
    Bytes payload;
    Bytes trailer;
    bool has_trailer = ExtractTrailer(file_bytes, payload, trailer);
    if (!has_trailer || trailer.empty()) {
        throw std::runtime_error("No media trailer found");
    }
    Bytes material = DeriveMaterial(password);
    Bytes archive_key = basefwx::crypto::HkdfSha256(basefwx::constants::kImageCipherArchiveInfo, material, 32);
    Bytes aad(basefwx::constants::kImageCipherArchiveInfo.begin(),
              basefwx::constants::kImageCipherArchiveInfo.end());
    Bytes original_bytes = basefwx::crypto::AeadDecrypt(archive_key, trailer, aad);
    std::filesystem::path output_path = output.empty() ? input_path : NormalizePath(output);
    WriteFileBytes(output_path, original_bytes);
    return output_path.string();
}

}  // namespace basefwx::imagecipher
