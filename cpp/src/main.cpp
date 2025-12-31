#include "basefwx/basefwx.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

void PrintUsage() {
    std::cout << "Usage:\n";
    std::cout << "  basefwx_cpp info <file.fwx>\n";
    std::cout << "  basefwx_cpp b256-enc <text>\n";
    std::cout << "  basefwx_cpp b256-dec <text>\n";
    std::cout << "  basefwx_cpp b512-enc <text> -p <password> [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512-dec <text> -p <password> [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512-enc <text> -p <password> [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512-dec <text> -p <password> [--no-master] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512file-enc <file> -p <password> [--no-master] [--strip-meta] [--no-aead] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp b512file-dec <file.fwx> -p <password> [--no-master] [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512file-enc <file> -p <password> [--no-master] [--strip-meta] [--no-obf] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp pb512file-dec <file.fwx> -p <password> [--no-master] [--strip-meta] [--kdf <label>] [--pbkdf2-iters <n>]\n";
    std::cout << "  basefwx_cpp fwxaes-enc <file> -p <password> [--out <path>] [--normalize] [--threshold <n>] [--cover-phrase <text>]\n";
    std::cout << "  basefwx_cpp fwxaes-dec <file> -p <password> [--out <path>]\n";
}

struct ParsedOptions {
    std::string input;
    std::string password;
    bool use_master = true;
    basefwx::KdfOptions kdf;
};

struct FwxAesArgs {
    std::string input;
    std::string output;
    std::string password;
    bool normalize = false;
    std::size_t threshold = 8 * 1024;
    std::string cover_phrase = "low taper fade";
};

struct FileArgs {
    std::string input;
    std::string password;
    bool use_master = true;
    bool strip_metadata = false;
    bool enable_aead = true;
    bool enable_obf = true;
    basefwx::pb512::KdfOptions kdf;
};

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
            idx += 2;
        } else if (flag == "--no-master") {
            opts.use_master = false;
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
            idx += 2;
        } else if (flag == "--no-master") {
            opts.use_master = false;
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
            idx += 2;
        } else if (flag == "--out" || flag == "-o") {
            if (idx + 1 >= argc) {
                throw std::runtime_error("Missing output path");
            }
            opts.output = argv[idx + 1];
            idx += 2;
        } else if (flag == "--normalize") {
            opts.normalize = true;
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
        } else {
            throw std::runtime_error("Unknown flag: " + flag);
        }
    }
    return opts;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    std::string command(argv[1]);
    try {
        if (command == "info") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            auto data = basefwx::ReadFile(argv[2]);
            auto info = basefwx::InspectBlob(data);
            std::cout << "user_blob_len: " << info.user_blob_len << " bytes\n";
            std::cout << "master_blob_len: " << info.master_blob_len << " bytes\n";
            std::cout << "payload_len: " << info.payload_len << " bytes\n";
            if (info.has_metadata) {
                std::cout << "metadata_len: " << info.metadata_len << " bytes\n";
                if (!info.metadata_json.empty()) {
                    std::cout << "metadata_json: " << info.metadata_json << "\n";
                } else if (info.metadata_len == 0) {
                    std::cout << "metadata_json: <empty>\n";
                } else {
                    std::cout << "metadata_json: <unavailable>\n";
                }
            } else {
                std::cout << "metadata_json: <unavailable>\n";
            }
            return 0;
        }
        if (command == "b256-enc") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Encode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b256-dec") {
            if (argc < 3) {
                PrintUsage();
                return 2;
            }
            std::cout << basefwx::B256Decode(argv[2]) << "\n";
            return 0;
        }
        if (command == "b512-enc" || command == "b512-dec" || command == "pb512-enc" || command == "pb512-dec") {
            ParsedOptions opts = ParseCodecArgs(argc, argv, 2);
            if (command == "b512-enc") {
                std::cout << basefwx::B512Encode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "b512-dec") {
                std::cout << basefwx::B512Decode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "pb512-enc") {
                std::cout << basefwx::Pb512Encode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            } else if (command == "pb512-dec") {
                std::cout << basefwx::Pb512Decode(opts.input, opts.password, opts.use_master, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "b512file-enc" || command == "b512file-dec"
            || command == "pb512file-enc" || command == "pb512file-dec") {
            FileArgs opts = ParseFileArgs(argc, argv, 2);
            basefwx::filecodec::FileOptions file_opts;
            file_opts.strip_metadata = opts.strip_metadata;
            file_opts.use_master = opts.use_master;
            file_opts.enable_aead = opts.enable_aead;
            file_opts.enable_obfuscation = opts.enable_obf;
            if (command == "b512file-enc") {
                std::cout << basefwx::filecodec::B512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "b512file-dec") {
                std::cout << basefwx::filecodec::B512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-enc") {
                std::cout << basefwx::filecodec::Pb512EncodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            } else if (command == "pb512file-dec") {
                std::cout << basefwx::filecodec::Pb512DecodeFile(opts.input, opts.password, file_opts, opts.kdf) << "\n";
            }
            return 0;
        }
        if (command == "fwxaes-enc" || command == "fwxaes-dec") {
            FwxAesArgs opts = ParseFwxAesArgs(argc, argv, 2);
            if (opts.password.empty()) {
                throw std::runtime_error("Password is required for fwxaes");
            }
            if (opts.output.empty()) {
                if (command == "fwxaes-enc") {
                    opts.output = opts.input + ".fwx";
                } else if (opts.input.size() >= 4 && opts.input.rfind(".fwx") == opts.input.size() - 4) {
                    opts.output = opts.input.substr(0, opts.input.size() - 4);
                } else {
                    opts.output = opts.input + ".out";
                }
            }
            if (command == "fwxaes-enc") {
                basefwx::fwxaes::NormalizeOptions norm;
                norm.enabled = opts.normalize;
                norm.threshold = opts.threshold;
                norm.cover_phrase = opts.cover_phrase;
                basefwx::fwxaes::EncryptFile(opts.input, opts.output, opts.password, {}, norm);
            } else {
                basefwx::fwxaes::DecryptFile(opts.input, opts.output, opts.password);
            }
            return 0;
        }
        PrintUsage();
        return 2;
    } catch (const std::exception& exc) {
        std::cerr << "Error: " << exc.what() << "\n";
        return 1;
    }
}
