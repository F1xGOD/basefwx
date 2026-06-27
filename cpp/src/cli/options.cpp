/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "basefwx/cli/options.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace basefwx::cli {

namespace {

void ApplyMasterPubPath(const std::string& path) {
    if (path.empty()) {
        return;
    }
#if defined(_WIN32)
    _putenv_s("BASEFWX_MASTER_PQ_PUB", path.c_str());
#else
    setenv("BASEFWX_MASTER_PQ_PUB", path.c_str(), 1);
#endif
}

void EnableMasterEcAutogen() {
    // 3.7.0: silent EC master autogeneration removed. This flag only
    // opts into useMaster=true; provision the EC keypair explicitly.
    std::cerr << "basefwx: --master-autogen is deprecated and has no effect "
                 "since 3.7.0; provision the EC master keypair manually.\n";
}

void EnableEmbeddedMaster() {
    // 3.7.0: build-time embedding via BASEFWX_MASTER_PQ_PUB_B64 is
    // picked up automatically in pq.cpp; the old ALLOW_BAKED env-var
    // opt-in path is gone. This flag only opts into useMaster=true.
}

}  // namespace

bool HandleMasterFlag(const std::string& flag,
                      int argc,
                      char** argv,
                      int* idx,
                      bool* use_master) {
    if (flag == "--use-master") {
        if (use_master) {
            *use_master = true;
        }
        return true;
    }
    if (flag == "--no-master") {
        if (use_master) {
            *use_master = false;
        }
        return true;
    }
    if (flag == "--master-autogen") {
        EnableMasterEcAutogen();
        if (use_master) {
            *use_master = true;
        }
        return true;
    }
    if (flag == "--allow-embedded-master") {
        EnableEmbeddedMaster();
        if (use_master) {
            *use_master = true;
        }
        return true;
    }
    if (flag == "--master-pub" || flag == "--use-master-pub") {
        if (!idx || *idx + 1 >= argc) {
            throw std::runtime_error("Missing master public key path");
        }
        ApplyMasterPubPath(argv[*idx + 1]);
        if (use_master) {
            *use_master = true;
        }
        *idx += 1;
        return true;
    }
    return false;
}

ParsedOptions ParseCodecArgs(int argc, char** argv, int start_index) {
    ParsedOptions opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing payload");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            opts.password_provided = true;
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--kdf") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing kdf label");
            }
            opts.kdf.label = argv[idx + 1];
            idx += 2;
        } else if (flag == "--pbkdf2-iters") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing pbkdf2 iteration count");
            }
            opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--no-fallback") {
            opts.kdf.allow_pbkdf2_fallback = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

FileArgs ParseFileArgs(int argc, char** argv, int start_index) {
    FileArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            opts.password_provided = true;
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--strip-meta") {
            opts.strip_metadata = true;
            idx += 1;
        } else if (flag == "--no-aead") {
            opts.enable_aead = false;
            idx += 1;
        } else if (flag == "--no-obf") {
            opts.enable_obf = false;
            idx += 1;
        } else if (flag == "--compress") {
            opts.compress = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--kdf") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing kdf label");
            }
            opts.kdf.label = argv[idx + 1];
            idx += 2;
        } else if (flag == "--pbkdf2-iters") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing pbkdf2 iteration count");
            }
            opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--no-fallback") {
            opts.kdf.allow_pbkdf2_fallback = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

FwxAesArgs ParseFwxAesArgs(int argc, char** argv, int start_index) {
    FwxAesArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            opts.password_provided = true;
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--kdf") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing kdf label");
            }
            opts.kdf.label = argv[idx + 1];
            idx += 2;
        } else if (flag == "--pbkdf2-iters") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing pbkdf2 iteration count");
            }
            opts.kdf.pbkdf2_iterations = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--argon2-time") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing argon2 time cost");
            }
            opts.kdf.argon2_time_cost = static_cast<std::uint32_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--argon2-mem") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing argon2 memory cost");
            }
            opts.kdf.argon2_memory_cost = static_cast<std::uint32_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--argon2-par") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing argon2 parallelism");
            }
            opts.kdf.argon2_parallelism = static_cast<std::uint32_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--no-fallback") {
            opts.kdf.allow_pbkdf2_fallback = false;
            idx += 1;
        } else if (flag == "--legacy-pbkdf2" || flag == "--no-wrap-kdf") {
            opts.force_legacy_pbkdf2 = true;
            idx += 1;
        } else if (flag == "--normalize") {
            opts.normalize = true;
            idx += 1;
        } else if (flag == "--heavy") {
            opts.heavy = true;
            idx += 1;
        } else if (flag == "--light") {
            opts.heavy = false;
            idx += 1;
        } else if (flag == "--threshold") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing threshold value");
            }
            opts.threshold = static_cast<std::size_t>(std::stoul(argv[idx + 1]));
            idx += 2;
        } else if (flag == "--cover-phrase") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing cover phrase value");
            }
            opts.cover_phrase = argv[idx + 1];
            idx += 2;
        } else if (flag == "--compress") {
            opts.compress = true;
            idx += 1;
        } else if (flag == "--ignore-media") {
            opts.ignore_media = true;
            idx += 1;
        } else if (flag == "--keep-meta") {
            opts.keep_meta = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--archive") {
            opts.archive_original = true;
            idx += 1;
        } else if (flag == "--no-archive") {
            opts.archive_original = false;
            idx += 1;
        } else if (flag == "--plugin") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing plugin path");
            }
            opts.plugin_path = argv[idx + 1];
            idx += 2;
        } else if (flag == "--plugin-id") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing plugin id hex");
            }
            opts.plugin_id_hex = argv[idx + 1];
            idx += 2;
        } else if (flag == "--plugin-pos") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing plugin position");
            }
            opts.plugin_pos = argv[idx + 1];
            idx += 2;
        } else if (flag == "--plugin-config") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing plugin config path");
            }
            opts.plugin_config_file = argv[idx + 1];
            idx += 2;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

ImageArgs ParseImageArgs(int argc, char** argv, int start_index) {
    ImageArgs opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            opts.password_provided = true;
            idx += 2;
        } else if (HandleMasterFlag(flag, argc, argv, &idx, &opts.use_master)) {
            idx += 1;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--keep-meta") {
            opts.keep_meta = true;
            idx += 1;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--archive") {
            opts.archive_original = true;
            idx += 1;
        } else if (flag == "--no-archive") {
            opts.archive_original = false;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

An7Args ParseAn7Args(int argc, char** argv, int start_index, bool allow_force_any) {
    An7Args opts;
    if (start_index >= argc) {
        throw std::runtime_error("Missing input path");
    }
    opts.input = argv[start_index];
    int idx = start_index + 1;
    while (idx < argc) {
        std::string flag(argv[idx]);
        if (flag == "-p" || flag == "--password") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing password value");
            }
            opts.password = argv[idx + 1];
            opts.password_provided = true;
            idx += 2;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--keep-input") {
            opts.keep_input = true;
            idx += 1;
        } else if (flag == "--force-any") {
            if (!allow_force_any) {
                throw std::runtime_error("--force-any is only valid for an7");
            }
            opts.force_any = true;
            idx += 1;
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

}  // namespace basefwx::cli
