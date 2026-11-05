#include "encpto/archive.hpp"

#include "encpto/error.hpp"
#include "encpto/file.hpp"
#include "encpto/fsutil.hpp"
#include "encpto/secure_memory.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include <libdeflate.h>
#include <miniz.h>

namespace fs = std::filesystem;

namespace encpto::archive {
namespace {

// Files up to this size are compressed in parallel in memory (libdeflate);
// bigger ones are streamed from disk straight into the archive.
constexpr std::uint64_t kParallelLimit = 256ULL * 1024 * 1024;
constexpr std::uint64_t kBatchBudget = 512ULL * 1024 * 1024;
constexpr int kDeflateLevel = 6;  // same ratio target as the Python tool, ~3× faster

std::uint32_t crc32(const void* data, std::size_t n) {
    return libdeflate_crc32(0, data, n);  // SIMD (PCLMUL / ARM CRC) accelerated
}

/// Reusable compressors per worker thread: level 0 emits DEFLATE "stored"
/// blocks (≈ memcpy) for media / incompressible data.
libdeflate_compressor* thread_compressor(bool store) {
    struct Holder {
        libdeflate_compressor* c[2] = {libdeflate_alloc_compressor(kDeflateLevel),
                                       libdeflate_alloc_compressor(0)};
        ~Holder() {
            libdeflate_free_compressor(c[0]);
            libdeflate_free_compressor(c[1]);
        }
    };
    thread_local Holder h;
    libdeflate_compressor* c = h.c[store ? 1 : 0];
    if (c == nullptr) {
        throw std::bad_alloc();
    }
    return c;
}

struct Entry {
    fs::path source;
    std::string name;  // UTF-8 archive name, '/'-separated
    bool is_dir = false;
    std::uint64_t size = 0;
    std::time_t mtime = 0;
};

// Formats that do not compress further: store them as-is (much faster).
bool already_compressed(const fs::path& p) {
    static constexpr std::array<std::string_view, 38> exts = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".avif", ".jxl", ".mp3",
        ".m4a", ".aac", ".ogg", ".opus", ".flac", ".mp4", ".m4v", ".mkv", ".mov", ".avi",
        ".webm", ".wmv", ".zip", ".7z", ".rar", ".gz", ".tgz", ".bz2", ".xz", ".zst",
        ".dat", ".docx", ".xlsx", ".pptx", ".odt", ".epub", ".apk", ".dmg"};
    std::string e = fsutil::to_utf8(p.extension());
    std::transform(e.begin(), e.end(), e.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return std::find(exts.begin(), exts.end(), e) != exts.end();
}

std::time_t to_time_t(fs::file_time_type ft) {
    using namespace std::chrono;
    const auto sys = time_point_cast<system_clock::duration>(ft - fs::file_time_type::clock::now() +
                                                             system_clock::now());
    return system_clock::to_time_t(sys);
}

void collect(const fs::path& dir, const std::string& prefix, std::vector<Entry>& out) {
    std::vector<fs::directory_entry> children;
    std::error_code ec;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        children.push_back(*it);
    }
    if (ec) {
        throw Error(ErrorCode::Io, "Cannot read folder: " + fsutil::to_utf8(dir));
    }
    std::sort(children.begin(), children.end(),
              [](const auto& a, const auto& b) { return a.path().filename() < b.path().filename(); });

    // Files first, then sub-folders (same order as Python's os.walk).
    std::vector<fs::path> subdirs;
    for (const auto& c : children) {
        std::error_code e2;
        const std::string name = prefix + fsutil::to_utf8(c.path().filename());
        if (c.is_symlink(e2) && c.is_directory(e2)) {
            continue;  // never follow directory links (loops, escapes)
        }
        if (c.is_directory(e2)) {
            subdirs.push_back(c.path());
        } else if (c.is_regular_file(e2)) {
            Entry e;
            e.source = c.path();
            e.name = name;
            e.size = c.file_size(e2);
            e.mtime = to_time_t(c.last_write_time(e2));
            out.push_back(std::move(e));
        }
    }
    for (const auto& sd : subdirs) {
        Entry d;
        d.source = sd;
        d.name = prefix + fsutil::to_utf8(sd.filename()) + "/";
        d.is_dir = true;
        std::error_code e2;
        d.mtime = to_time_t(fs::last_write_time(sd, e2));
        out.push_back(d);
        collect(sd, d.name, out);
    }
}

// ── ZIP writer into a std::vector (random-access writes for header patching)
struct VectorSink {
    std::vector<std::uint8_t> data;
};

std::size_t sink_write(void* opaque, mz_uint64 ofs, const void* buf, std::size_t n) {
    auto* s = static_cast<VectorSink*>(opaque);
    const auto end = static_cast<std::size_t>(ofs) + n;
    if (end > s->data.size()) {
        if (end > s->data.capacity()) {
            // Grow manually so the old block can be wiped (plaintext!).
            std::vector<std::uint8_t> bigger;
            bigger.reserve(std::max(end, s->data.capacity() * 2));
            bigger.assign(s->data.begin(), s->data.end());
            secure_zero(s->data.data(), s->data.size());
            s->data.swap(bigger);
        }
        s->data.resize(end);
    }
    std::memcpy(s->data.data() + ofs, buf, n);
    return n;
}

struct FileReader {
    File file;
    const Options* opts;
    std::uint64_t* progress_done;
    std::uint64_t progress_total;
};

std::size_t reader_read(void* opaque, mz_uint64 ofs, void* buf, std::size_t n) {
    auto* r = static_cast<FileReader*>(opaque);
    if (r->opts->is_cancelled()) {
        return 0;  // makes miniz fail → we throw Cancelled afterwards
    }
    r->file.seek(ofs);
    const std::size_t got = r->file.read(buf, n);
    *r->progress_done += got;
    r->opts->report(Phase::Packing, *r->progress_done, r->progress_total);
    return got;
}

struct Compressed {
    std::vector<std::uint8_t> deflated;  // raw DEFLATE stream
    std::uint32_t crc = 0;
    std::uint64_t size = 0;
    std::exception_ptr error;

    void reset() { std::vector<std::uint8_t>().swap(deflated); }
};

std::size_t deflate_into(libdeflate_compressor* c, const std::vector<std::uint8_t>& in,
                         std::vector<std::uint8_t>& out) {
    out.resize(libdeflate_deflate_compress_bound(c, in.size()));
    const std::size_t n =
        libdeflate_deflate_compress(c, in.data(), in.size(), out.data(), out.size());
    out.resize(n);
    return n;
}

void compress_one(const Entry& e, Compressed& out) {
    std::vector<std::uint8_t> raw;
    try {
        raw.resize(static_cast<std::size_t>(e.size));
        File f(e.source, File::Mode::Read);
        raw.resize(f.read(raw.data(), raw.size()));  // tolerate files that shrank
        out.size = raw.size();
        out.crc = crc32(raw.data(), raw.size());

        bool store = already_compressed(e.source) || raw.size() < 64;
        if (!store && raw.size() > (1U << 20)) {
            // Cheap probe: skip the full pass for data that clearly won't shrink.
            libdeflate_compressor* c = thread_compressor(false);
            std::vector<std::uint8_t> probe(libdeflate_deflate_compress_bound(c, 1U << 16));
            const std::size_t p =
                libdeflate_deflate_compress(c, raw.data(), 1U << 16, probe.data(), probe.size());
            store = p == 0 || p > (1U << 16) * 97 / 100;
        }
        if (!store) {
            const std::size_t n = deflate_into(thread_compressor(false), raw, out.deflated);
            store = n == 0 || n >= raw.size();
        }
        if (store && deflate_into(thread_compressor(true), raw, out.deflated) == 0) {
            throw Error(ErrorCode::Internal, "DEFLATE failed for " + e.name);
        }
    } catch (...) {
        out.error = std::current_exception();
    }
    secure_zero(raw.data(), raw.size());
}

[[noreturn]] void zip_fail(mz_zip_archive& zip, const Options& opts, const std::string& what) {
    if (opts.is_cancelled()) {
        throw Error(ErrorCode::Cancelled, "Operation cancelled.");
    }
    throw Error(ErrorCode::Io,
                what + ": " + mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
}

}  // namespace

std::vector<std::uint8_t> pack_directory(const fs::path& dir, const Options& opts) {
    const fs::path root = fs::absolute(dir);
    std::string root_name = fsutil::to_utf8(root.filename());
    if (root_name.empty()) {
        root_name = fsutil::to_utf8(root.parent_path().filename());
    }

    std::vector<Entry> entries;
    {
        Entry top;
        top.source = root;
        top.name = root_name + "/";
        top.is_dir = true;
        std::error_code ec;
        top.mtime = to_time_t(fs::last_write_time(root, ec));
        entries.push_back(top);
    }
    collect(root, root_name + "/", entries);

    std::uint64_t total = 0;
    for (const auto& e : entries) {
        total += e.size;
    }
    std::uint64_t done = 0;
    opts.report(Phase::Packing, 0, total);

    VectorSink sink;
    sink.data.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(total + 4096, 1ULL << 30)));
    mz_zip_archive zip{};
    zip.m_pWrite = sink_write;
    zip.m_pIO_opaque = &sink;
    if (!mz_zip_writer_init_v2(&zip, 0, 0)) {
        zip_fail(zip, opts, "Cannot create ZIP");
    }

    struct Guard {
        mz_zip_archive* z;
        ~Guard() { mz_zip_writer_end(z); }
    } guard{&zip};

    const unsigned workers = opts.worker_count();
    std::size_t i = 0;
    while (i < entries.size()) {
        if (opts.is_cancelled()) {
            throw Error(ErrorCode::Cancelled, "Operation cancelled.");
        }
        const Entry& e = entries[i];

        if (e.is_dir) {
            std::time_t t = e.mtime;
            if (!mz_zip_writer_add_mem_ex_v2(&zip, e.name.c_str(), nullptr, 0, nullptr, 0, 0, 0, 0,
                                             &t, nullptr, 0, nullptr, 0)) {
                zip_fail(zip, opts, "Cannot add folder " + e.name);
            }
            ++i;
            continue;
        }

        if (e.size > kParallelLimit) {
            // Large file: stream straight from disk into the archive.
            FileReader r{File(e.source, File::Mode::Read), &opts, &done, total};
            const std::time_t t = e.mtime;
            const mz_uint level = already_compressed(e.source) ? 0 : 1;
            if (!mz_zip_writer_add_read_buf_callback(&zip, e.name.c_str(), reader_read, &r, e.size,
                                                     &t, nullptr, 0, level, nullptr, 0, nullptr,
                                                     0)) {
                zip_fail(zip, opts, "Cannot add " + e.name);
            }
            ++i;
            continue;
        }

        // Batch of consecutive small files → compress in parallel, add in order.
        std::size_t j = i;
        std::uint64_t batch_bytes = 0;
        while (j < entries.size() && !entries[j].is_dir && entries[j].size <= kParallelLimit &&
               (j - i) < static_cast<std::size_t>(workers) * 8 && batch_bytes < kBatchBudget) {
            batch_bytes += entries[j].size;
            ++j;
        }
        std::vector<Compressed> results(j - i);
        std::atomic<std::size_t> next{0};
        {
            std::vector<std::thread> pool;
            const unsigned n = std::min<unsigned>(workers, static_cast<unsigned>(results.size()));
            for (unsigned w = 0; w < n; ++w) {
                pool.emplace_back([&] {
                    for (std::size_t k; (k = next.fetch_add(1)) < results.size();) {
                        if (opts.is_cancelled()) {
                            return;
                        }
                        compress_one(entries[i + k], results[k]);
                    }
                });
            }
            for (auto& t : pool) {
                t.join();
            }
        }
        try {
            if (opts.is_cancelled()) {
                throw Error(ErrorCode::Cancelled, "Operation cancelled.");
            }
            for (std::size_t k = 0; k < results.size(); ++k) {
                auto& r = results[k];
                const Entry& fe = entries[i + k];
                if (r.error) {
                    std::rethrow_exception(r.error);
                }
                std::time_t t = fe.mtime;
                const bool ok = mz_zip_writer_add_mem_ex_v2(
                    &zip, fe.name.c_str(), r.deflated.data(), r.deflated.size(), nullptr, 0,
                    static_cast<mz_uint>(kDeflateLevel) | MZ_ZIP_FLAG_COMPRESSED_DATA, r.size,
                    r.crc, &t, nullptr, 0, nullptr, 0);
                if (!ok) {
                    zip_fail(zip, opts, "Cannot add " + fe.name);
                }
                done += r.size;
                r.reset();
                opts.report(Phase::Packing, done, total);
            }
        } catch (...) {
            for (auto& r : results) {
                r.reset();
            }
            throw;
        }
        i = j;
    }

    if (!mz_zip_writer_finalize_archive(&zip)) {
        zip_fail(zip, opts, "Cannot finalise ZIP");
    }
    opts.report(Phase::Packing, total, total);
    return std::move(sink.data);
}

// ── Extraction ──────────────────────────────────────────────────────────

namespace {

struct ExtractSink {
    File file;
    const Options* opts;
};

std::size_t extract_write(void* opaque, mz_uint64, const void* buf, std::size_t n) {
    auto* s = static_cast<ExtractSink*>(opaque);
    if (s->opts->is_cancelled()) {
        return 0;
    }
    s->file.write(buf, n);
    return n;
}

std::string sanitize_component(std::string c) {
#ifdef _WIN32
    for (char& ch : c) {
        if (ch == '<' || ch == '>' || ch == ':' || ch == '"' || ch == '|' || ch == '?' ||
            ch == '*' || static_cast<unsigned char>(ch) < 0x20) {
            ch = '_';
        }
    }
    while (!c.empty() && (c.back() == '.' || c.back() == ' ')) {
        c.pop_back();
    }
#endif
    return c;
}

/// Turns an archive member name into a safe relative path, or throws.
fs::path safe_member_path(const std::string& name) {
    fs::path rel;
    std::string part;
    const auto flush = [&] {
        if (part.empty() || part == ".") {
            part.clear();
            return;
        }
        if (part == ".." || part.find(':') != std::string::npos) {
            throw Error(ErrorCode::Corrupted, "Unsafe ZIP path detected: " + name);
        }
        const std::string clean = sanitize_component(part);
        if (!clean.empty()) {
            rel /= fsutil::from_utf8(clean);
        }
        part.clear();
    };
    if (!name.empty() && (name[0] == '/' || name[0] == '\\')) {
        throw Error(ErrorCode::Corrupted, "Unsafe ZIP path detected: " + name);
    }
    for (const char c : name) {
        if (c == '/' || c == '\\') {
            flush();
        } else {
            part.push_back(c);
        }
    }
    flush();
    return rel;
}

/// Inflates one entry straight from the in-memory archive with libdeflate
/// (several times faster than miniz) and verifies its CRC-32.
/// Returns false if the entry should be handled by miniz instead.
bool extract_fast(mz_zip_archive&, const std::vector<std::uint8_t>& zip,
                  const mz_zip_archive_file_stat& st, File& out) {
    if (st.m_uncomp_size > kParallelLimit || (st.m_method != 0 && st.m_method != MZ_DEFLATED) ||
        (st.m_bit_flag & 1) != 0) {
        return false;
    }
    const std::uint64_t ofs = st.m_local_header_ofs;
    if (ofs + 30 > zip.size()) {
        throw Error(ErrorCode::Corrupted, "Corrupted ZIP entry.");
    }
    const std::uint8_t* h = zip.data() + ofs;
    const auto le16 = [](const std::uint8_t* p) { return std::uint32_t{p[0]} | (std::uint32_t{p[1]} << 8); };
    const std::uint32_t sig = le16(h) | (le16(h + 2) << 16);
    const std::uint64_t data_ofs = ofs + 30 + le16(h + 26) + le16(h + 28);
    if (sig != 0x04034b50 || data_ofs + st.m_comp_size > zip.size()) {
        throw Error(ErrorCode::Corrupted, "Corrupted ZIP entry.");
    }
    const std::uint8_t* data = zip.data() + data_ofs;
    const auto size = static_cast<std::size_t>(st.m_uncomp_size);

    if (st.m_method == 0) {
        if (st.m_comp_size != st.m_uncomp_size || crc32(data, size) != st.m_crc32) {
            throw Error(ErrorCode::Corrupted, "CRC mismatch in ZIP entry.");
        }
        out.write(data, size);
        return true;
    }
    struct Holder {
        libdeflate_decompressor* d = libdeflate_alloc_decompressor();
        ~Holder() { libdeflate_free_decompressor(d); }
    };
    thread_local Holder dec;
    if (dec.d == nullptr) {
        throw std::bad_alloc();
    }
    std::vector<std::uint8_t> plain(size);
    std::size_t got = 0;
    const auto rc = libdeflate_deflate_decompress(dec.d, data, static_cast<std::size_t>(st.m_comp_size),
                                                  plain.data(), plain.size(), &got);
    if (rc != LIBDEFLATE_SUCCESS || got != size || crc32(plain.data(), size) != st.m_crc32) {
        secure_zero(plain.data(), plain.size());
        throw Error(ErrorCode::Corrupted, "Corrupted ZIP entry.");
    }
    out.write(plain.data(), size);
    secure_zero(plain.data(), plain.size());
    return true;
}

}  // namespace

void extract(const std::vector<std::uint8_t>& zip_data, const fs::path& out_dir,
             const Options& opts) {
    mz_zip_archive zip{};
    if (!mz_zip_reader_init_mem(&zip, zip_data.data(), zip_data.size(), 0)) {
        throw Error(ErrorCode::Corrupted, "Decrypted payload is not a valid ZIP archive.");
    }
    struct Guard {
        mz_zip_archive* z;
        ~Guard() { mz_zip_reader_end(z); }
    } guard{&zip};

    fs::create_directories(out_dir);
    const mz_uint count = mz_zip_reader_get_num_files(&zip);
    std::uint64_t total = 0;
    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat st;
        if (mz_zip_reader_file_stat(&zip, i, &st)) {
            total += st.m_uncomp_size;
        }
    }
    std::uint64_t done = 0;
    for (mz_uint i = 0; i < count; ++i) {
        if (opts.is_cancelled()) {
            throw Error(ErrorCode::Cancelled, "Operation cancelled.");
        }
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            throw Error(ErrorCode::Corrupted, "Corrupted ZIP entry.");
        }
        const fs::path rel = safe_member_path(st.m_filename);
        if (rel.empty()) {
            continue;
        }
        const fs::path dest = out_dir / rel;
        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            fs::create_directories(dest);
            continue;
        }
        fs::create_directories(dest.parent_path());
        File out(dest, File::Mode::Write);
        if (!extract_fast(zip, zip_data, st, out)) {
            // Rare cases (huge entries, unusual methods): let miniz stream it.
            ExtractSink sink{std::move(out), &opts};
            if (!mz_zip_reader_extract_to_callback(&zip, i, extract_write, &sink, 0)) {
                if (opts.is_cancelled()) {
                    throw Error(ErrorCode::Cancelled, "Operation cancelled.");
                }
                throw Error(ErrorCode::Corrupted,
                            std::string("Cannot extract ") + st.m_filename + ": " +
                                mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
            }
            out = std::move(sink.file);
        }
        out.close();
        done += st.m_uncomp_size;
        opts.report(Phase::Extracting, done, total);
    }
}

void restore_folder(const std::vector<std::uint8_t>& zip, const fs::path& target,
                    const Options& opts) {
    const fs::path parent = target.parent_path();
    const fs::path staging = parent / fsutil::from_utf8(".encpto_extract_" + fsutil::random_hex(6));
    try {
        extract(zip, staging, opts);
        std::vector<fs::path> top;
        for (const auto& e : fs::directory_iterator(staging)) {
            top.push_back(e.path());
        }
        if (top.size() == 1 && fs::is_directory(top[0])) {
            fs::rename(top[0], target);
        } else {
            fs::rename(staging, target);
        }
    } catch (...) {
        std::error_code ec;
        fs::remove_all(staging, ec);
        throw;
    }
    std::error_code ec;
    fs::remove_all(staging, ec);
}

}  // namespace encpto::archive
