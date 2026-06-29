/*
 * BaseFWX - Cryptography Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0 or later.
 */

#pragma once

#include "basefwx/basefwx.hpp"
#include "basefwx/cli/globals.hpp"
#include <cstddef>
#include <string>

namespace basefwx::cli {

struct ParsedOptions {
    std::string input;
    std::string password;
    bool password_provided = false;
    bool use_master = false;
    basefwx::KdfOptions kdf;
};

struct FwxAesArgs {
    std::string input;
    std::string output;
    std::string password;
    bool password_provided = false;
    bool use_master = false;
    basefwx::pb512::KdfOptions kdf;
    bool force_legacy_pbkdf2 = false;
    bool heavy = false;
    bool normalize = false;
    std::size_t threshold = 8 * 1024;
    std::string cover_phrase = "low taper fade";
    bool compress = false;
    bool ignore_media = false;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = false;
    std::string plugin_path;
    std::string plugin_id_hex;
    std::string plugin_pos;
    std::string plugin_config_file;
};

struct ImageArgs {
    std::string input;
    std::string output;
    std::string password;
    bool password_provided = false;
    bool use_master = false;
    bool keep_meta = false;
    bool keep_input = false;
    bool archive_original = false;
};

struct An7Args {
    std::string input;
    std::string output;
    std::string password;
    bool password_provided = false;
    bool keep_input = false;
    bool force_any = false;
};

struct FileArgs {
    std::string input;
    std::string password;
    bool password_provided = false;
    bool use_master = false;
    bool strip_metadata = false;
    bool enable_aead = true;
    bool enable_obf = true;
    bool compress = false;
    bool keep_input = false;
    basefwx::pb512::KdfOptions kdf;
};

bool HandleMasterFlag(const std::string& flag,
                      int argc,
                      char** argv,
                      int* idx,
                      bool* use_master);

ParsedOptions ParseCodecArgs(int argc, char** argv, int start_index);
FileArgs ParseFileArgs(int argc, char** argv, int start_index);
FwxAesArgs ParseFwxAesArgs(int argc, char** argv, int start_index);
ImageArgs ParseImageArgs(int argc, char** argv, int start_index);
An7Args ParseAn7Args(int argc, char** argv, int start_index, bool allow_force_any);

}  // namespace basefwx::cli
