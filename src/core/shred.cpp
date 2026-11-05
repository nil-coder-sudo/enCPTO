#include "encpto/shred.hpp"

#include "encpto/crypto.hpp"
#include "encpto/error.hpp"
#include "encpto/file.hpp"
#include "encpto/fsutil.hpp"

#include <algorithm>
#include <vector>

namespace fs = std::filesystem;

namespace encpto::shred {
namespace {

constexpr std::size_t kBlock = 4 * 1024 * 1024;

void overwrite(const fs::path& file, std::uint64_t& done, std::uint64_t total,
               const Options& opts) {
    File f(file, File::Mode::ReadWrite);
    const std::uint64_t size = f.size();
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(std::min<std::uint64_t>(size, kBlock)));

    for (int pass = 0; pass < 3 && size > 0; ++pass) {
        if (pass < 2) {
            std::fill(buf.begin(), buf.end(), pass == 0 ? 0x00 : 0xFF);
        }
        f.seek(0);
        for (std::uint64_t off = 0; off < size;) {
            if (opts.is_cancelled()) {
                throw Error(ErrorCode::Cancelled, "Operation cancelled.");
            }
            const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(kBlock, size - off));
            if (pass == 2) {
                crypto::random_bytes(std::span(buf.data(), n));
            }
            f.write(buf.data(), n);
            off += n;
            done += n;
            opts.report(Phase::Shredding, done, total);
        }
        f.sync();  // one fsync per pass, not per block: far faster, same effect
    }
    f.truncate(0);
    f.sync();
}

void shred_one(const fs::path& file, std::uint64_t& done, std::uint64_t total,
               const Options& opts) {
    overwrite(file, done, total, opts);
    // Hide the original name before unlinking it.
    fs::path victim = file;
    std::error_code ec;
    const fs::path renamed = file.parent_path() / fsutil::from_utf8(fsutil::random_hex(8));
    fs::rename(file, renamed, ec);
    if (!ec) {
        victim = renamed;
    }
    if (!fs::remove(victim, ec) || ec) {
        throw Error(ErrorCode::Io, "Cannot delete " + fsutil::to_utf8(file));
    }
}

}  // namespace

void shred_file(const fs::path& file, const Options& opts) {
    std::uint64_t done = 0;
    const std::uint64_t total = fs::file_size(file) * 3;
    shred_one(file, done, total, opts);
    opts.report(Phase::Shredding, total, total);
}

void shred_directory(const fs::path& dir, const Options& opts) {
    std::vector<fs::path> files;
    std::uint64_t total = 0;
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        std::error_code ec;
        if (e.is_regular_file(ec) && !e.is_symlink(ec)) {
            files.push_back(e.path());
            total += e.file_size(ec) * 3;
        }
    }
    std::uint64_t done = 0;
    for (const auto& f : files) {
        shred_one(f, done, total, opts);
    }
    fs::remove_all(dir);
    opts.report(Phase::Shredding, total, total);
}

}  // namespace encpto::shred
