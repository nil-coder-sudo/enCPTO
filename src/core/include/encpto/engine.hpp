#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "encpto/error.hpp"
#include "encpto/format.hpp"
#include "encpto/progress.hpp"

namespace encpto {

/// What can be learned about a file *without* the password.
struct ContainerInfo {
    enum class Kind {
        V7,           // supported
        LegacyV2toV6, // older enCPTO formats: use legacy/enCPTO-v7.py
        Unknown,      // not recognised (could be a V1 file without magic)
    };
    Kind kind = Kind::Unknown;
    int version = 0;
};

ContainerInfo inspect(const std::filesystem::path& file);

/// Encrypts a single file into a V7 container at `out`.
/// Output is written to a temporary file and atomically renamed on success.
void encrypt_file(const std::filesystem::path& in, const std::filesystem::path& out,
                  std::string_view password, const Options& opts = {});

/// Packs a folder into a ZIP in memory and encrypts it into `out`.
void encrypt_directory(const std::filesystem::path& dir, const std::filesystem::path& out,
                       std::string_view password, const Options& opts = {});

struct DecryptResult {
    std::filesystem::path path;  // restored file or folder
    bool is_directory = false;
    std::string original_name;
};

/// Decrypts a V7 container into `out_dir`, restoring the original file or
/// folder name (never overwriting: "name (1).ext" is used if it exists).
/// The whole container is authenticated before any plaintext is written.
DecryptResult decrypt(const std::filesystem::path& in, const std::filesystem::path& out_dir,
                      std::string_view password, const Options& opts = {});

namespace detail {
/// Lowest-level entry point (used by tests for known-answer vectors):
/// encrypts `payload` with a caller-supplied header.
std::vector<std::uint8_t> encrypt_buffer(const std::vector<std::uint8_t>& payload,
                                         const v7::Meta& meta, std::string_view password,
                                         const v7::Header& header, const Options& opts = {});
}  // namespace detail

}  // namespace encpto
