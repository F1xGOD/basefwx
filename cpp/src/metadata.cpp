#include "basefwx/metadata.hpp"

#include "basefwx/base64.hpp"
#include "basefwx/constants.hpp"

#include <chrono>
#include <ctime>
#include <sstream>
#include <vector>

namespace basefwx::metadata {

namespace {

std::string UtcTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buffer[32];
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        return {};
    }
    return std::string(buffer);
}

std::string EscapeJson(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (char ch : input) {
        if (ch == '\\' || ch == '"') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    return out;
}

}  // namespace

std::string Build(const std::string& method,
                  bool strip,
                  bool use_master,
                  std::string_view aead,
                  std::string_view kdf_label,
                  std::string_view mode,
                  std::optional<bool> obfuscation,
                  std::optional<std::uint32_t> kdf_iters,
                  std::optional<std::uint32_t> argon2_time,
                  std::optional<std::uint32_t> argon2_mem,
                  std::optional<std::uint32_t> argon2_par,
                  std::string_view pack) {
    if (strip) {
        return {};
    }
    std::vector<std::pair<std::string, std::string>> fields;
    fields.emplace_back("ENC-TIME", UtcTimestamp());
    fields.emplace_back("ENC-VERSION", std::string(constants::kEngineVersion));
    fields.emplace_back("ENC-METHOD", method);
    fields.emplace_back("ENC-MASTER", use_master ? "yes" : "no");
    fields.emplace_back("ENC-KEM", use_master ? std::string(constants::kMasterPqAlg) : "none");
    fields.emplace_back("ENC-AEAD", std::string(aead));
    fields.emplace_back("ENC-KDF", std::string(kdf_label));
    if (!mode.empty()) {
        fields.emplace_back("ENC-MODE", std::string(mode));
    }
    if (obfuscation.has_value()) {
        fields.emplace_back("ENC-OBF", obfuscation.value() ? "yes" : "no");
    }
    if (kdf_iters.has_value()) {
        fields.emplace_back("ENC-KDF-ITER", std::to_string(kdf_iters.value()));
    }
    if (argon2_time.has_value()) {
        fields.emplace_back("ENC-ARGON2-TC", std::to_string(argon2_time.value()));
    }
    if (argon2_mem.has_value()) {
        fields.emplace_back("ENC-ARGON2-MEM", std::to_string(argon2_mem.value()));
    }
    if (argon2_par.has_value()) {
        fields.emplace_back("ENC-ARGON2-PAR", std::to_string(argon2_par.value()));
    }
    if (!pack.empty()) {
        fields.emplace_back(std::string(constants::kPackMetaKey), std::string(pack));
    }

    std::string json;
    json.reserve(fields.size() * 32);
    json.push_back('{');
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i > 0) {
            json.push_back(',');
        }
        json.push_back('"');
        json += EscapeJson(fields[i].first);
        json += "\":\"";
        json += EscapeJson(fields[i].second);
        json.push_back('"');
    }
    json.push_back('}');

    std::vector<std::uint8_t> json_bytes(json.begin(), json.end());
    return basefwx::base64::Encode(json_bytes);
}

MetadataMap Decode(const std::string& blob) {
    MetadataMap result;
    if (blob.empty()) {
        return result;
    }
    bool ok = false;
    std::vector<std::uint8_t> decoded = basefwx::base64::Decode(blob, &ok);
    if (!ok) {
        return result;
    }
    std::string json(decoded.begin(), decoded.end());
    std::size_t pos = 0;
    while (true) {
        pos = json.find('"', pos);
        if (pos == std::string::npos) {
            break;
        }
        std::size_t key_end = json.find('"', pos + 1);
        if (key_end == std::string::npos) {
            break;
        }
        std::string key = json.substr(pos + 1, key_end - pos - 1);
        std::size_t colon = json.find(':', key_end + 1);
        if (colon == std::string::npos) {
            break;
        }
        std::size_t val_start = json.find('"', colon + 1);
        if (val_start == std::string::npos) {
            break;
        }
        std::size_t val_end = json.find('"', val_start + 1);
        if (val_end == std::string::npos) {
            break;
        }
        std::string value = json.substr(val_start + 1, val_end - val_start - 1);
        result[key] = value;
        pos = val_end + 1;
    }
    return result;
}

std::string GetValue(const MetadataMap& meta, std::string_view key) {
    auto it = meta.find(std::string(key));
    if (it == meta.end()) {
        return {};
    }
    return it->second;
}

}  // namespace basefwx::metadata
