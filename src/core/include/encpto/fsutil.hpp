#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace encpto::fsutil {

/// UTF-8 std::string ⇄ std::filesystem::path, correct on Windows too.
std::filesystem::path from_utf8(const std::string& s);
std::string to_utf8(const std::filesystem::path& p);

/// Makes an untrusted name (from decrypted metadata) safe to use as a single
/// path component. Falls back to `fallback` if nothing usable remains.
std::string safe_output_name(const std::string& name, const std::string& fallback);

/// Returns `path`, or "name (1).ext", "name (2).ext", … if it already exists.
std::filesystem::path unique_path(const std::filesystem::path& path);

/// "12.3 MB"
std::string human_size(std::uint64_t bytes);

struct DirStats {
    std::uint64_t files = 0;
    std::uint64_t bytes = 0;
};
DirStats scan_directory(const std::filesystem::path& dir);

/// Random hex string for temporary names.
std::string random_hex(std::size_t bytes);

}  // namespace encpto::fsutil
