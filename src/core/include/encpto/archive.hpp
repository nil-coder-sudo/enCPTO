#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#include "encpto/progress.hpp"

namespace encpto::archive {

/// Packs `dir` into an in-memory ZIP (entries are stored as "<dir name>/…",
/// exactly like the Python tool). Plaintext never touches the disk.
/// Small files are deflated in parallel; already-compressed media is stored.
std::vector<std::uint8_t> pack_directory(const std::filesystem::path& dir, const Options& opts);

/// Safely extracts a ZIP held in memory into `out_dir` (rejects path
/// traversal, absolute paths and drive letters).
void extract(const std::vector<std::uint8_t>& zip, const std::filesystem::path& out_dir,
             const Options& opts);

/// Extracts so that `target` *is* the restored folder (archives contain
/// "<folder>/…", which would otherwise nest it twice).
void restore_folder(const std::vector<std::uint8_t>& zip, const std::filesystem::path& target,
                    const Options& opts);

}  // namespace encpto::archive
