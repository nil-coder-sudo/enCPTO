#pragma once

#include <filesystem>

#include "encpto/progress.hpp"

namespace encpto::shred {

/// DoD 5220.22-M style 3-pass overwrite (0x00 → 0xFF → random), then the
/// file is renamed to a random name, truncated and deleted.
///
/// NOTE: on SSDs, copy-on-write / journaling file systems and snapshots,
/// overwriting cannot guarantee the old blocks are gone.
void shred_file(const std::filesystem::path& file, const Options& opts = {});

/// Shreds every file below `dir`, then removes the folder tree.
void shred_directory(const std::filesystem::path& dir, const Options& opts = {});

}  // namespace encpto::shred
