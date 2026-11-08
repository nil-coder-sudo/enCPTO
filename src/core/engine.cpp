#include "encpto/engine.hpp"

#include "encpto/archive.hpp"
#include "encpto/crypto.hpp"
#include "encpto/file.hpp"
#include "encpto/fsutil.hpp"
#include "encpto/secure_memory.hpp"
#include "pipeline.hpp"
#include "gpu/session.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>
#include <thread>

namespace fs = std::filesystem;

namespace encpto {

unsigned Options::worker_count() const {
    if (threads != 0) {
        return threads;
    }
    const unsigned hw = std::thread::hardware_concurrency();
    return hw == 0 ? 2 : hw;
}

namespace {

using v7::kTag;

// ── Keys ────────────────────────────────────────────────────────────────

struct Keys {
    SecureBytes okm{v7::kSubkeyBytes};  // k_aes(0:32) ‖ k_xcc(32:64) ‖ k_mac(64:128)
    [[nodiscard]] crypto::Bytes aes() const { return okm.sub(0, 32); }
    [[nodiscard]] crypto::Bytes xcc() const { return okm.sub(32, 32); }
    [[nodiscard]] crypto::Bytes mac() const { return okm.sub(64, 64); }
};

std::unique_ptr<Keys> derive_keys(std::string_view password, const v7::HeaderBytes& hdr,
                                  const v7::Header& h, const Options& opts) {
    opts.report(Phase::DerivingKey, 0, 1);
    SecureBytes master(64);
    crypto::argon2id({reinterpret_cast<const std::uint8_t*>(password.data()), password.size()},
                     h.salt, h.kdf.time_cost, h.kdf.memory_kib, h.kdf.parallelism, master.span());
    const auto salt = crypto::sha512(hdr);
    auto keys = std::make_unique<Keys>();
    crypto::hkdf_sha512(master.span(), salt,
                        {reinterpret_cast<const std::uint8_t*>(v7::kHkdfInfo),
                         sizeof(v7::kHkdfInfo) - 1},
                        keys->okm.span());
    opts.report(Phase::DerivingKey, 1, 1);
    return keys;
}

// ── Chunk cipher (CPU or experimental GPU) ──────────────────────────────

/// Both cipher layers for one container. With Options::use_gpu the keystreams
/// come from an OpenCL device and only Poly1305 runs on the CPU; the bytes are
/// identical either way.
class ChunkCipher {
public:
    ChunkCipher(const Keys& keys, const v7::Header& header, const std::array<std::uint8_t, 64>& hdr_hash,
                const Options& opts)
        : keys_(keys), header_(header), hdr_hash_(hdr_hash) {
        if (opts.use_gpu) {
            gpu_ = std::make_unique<gpu::detail::Session>(opts.gpu_device, keys.aes(), keys.xcc(),
                                                          header.aes_prefix, header.xcc_prefix, kGpuLanes);
            workers_ = kGpuLanes;
        } else {
            workers_ = opts.worker_count();
        }
    }

    [[nodiscard]] unsigned workers() const { return workers_; }

    void seal(detail::Job& job) const {
        const auto aad = v7::chunk_aad(hdr_hash_, job.index, job.final);
        std::uint8_t* d = job.buffer.data();
        if (gpu_) {
            gpu_->xor_keystreams(job.index, d, job.length);
            crypto::poly1305_aead_tag(gpu_->chacha_subkey(), nonce(job.index), aad, d, job.length,
                                      d + job.length);
            return;
        }
        crypto::aes256_ctr_xor(keys_.aes(), v7::aes_iv(header_.aes_prefix, static_cast<std::uint32_t>(job.index)),
                               d, job.length);
        crypto::xchacha_seal(keys_.xcc(), v7::xcc_nonce(header_.xcc_prefix, job.index), aad, d,
                             job.length, d + job.length);
    }

    void open(detail::Job& job) const {
        const auto aad = v7::chunk_aad(hdr_hash_, job.index, job.final);
        std::uint8_t* d = job.buffer.data();
        if (gpu_) {
            // Authenticate first, then let the GPU strip both layers.
            std::array<std::uint8_t, kTag> tag{};
            crypto::poly1305_aead_tag(gpu_->chacha_subkey(), nonce(job.index), aad, d, job.length, tag.data());
            if (!crypto::equal(tag, crypto::Bytes(d + job.length, kTag))) {
                throw Error(ErrorCode::Tampered, "Chunk authentication failed — file tampered.");
            }
            gpu_->xor_keystreams(job.index, d, job.length);
            return;
        }
        if (!crypto::xchacha_open(keys_.xcc(), v7::xcc_nonce(header_.xcc_prefix, job.index), aad, d,
                                  job.length, d + job.length)) {
            throw Error(ErrorCode::Tampered, "Chunk authentication failed — file tampered.");
        }
        crypto::aes256_ctr_xor(keys_.aes(), v7::aes_iv(header_.aes_prefix, static_cast<std::uint32_t>(job.index)),
                               d, job.length);
    }

private:
    static constexpr unsigned kGpuLanes = 4;

    [[nodiscard]] std::array<std::uint8_t, 12> nonce(std::uint64_t index) const {
        return crypto::ietf_nonce(v7::xcc_nonce(header_.xcc_prefix, index));
    }

    const Keys& keys_;
    const v7::Header& header_;
    const std::array<std::uint8_t, 64>& hdr_hash_;
    std::unique_ptr<gpu::detail::Session> gpu_;
    unsigned workers_ = 1;
};

// ── Sources & sinks ─────────────────────────────────────────────────────

using ReadFn = std::function<std::size_t(std::uint8_t*, std::size_t)>;
using WriteFn = std::function<void(const std::uint8_t*, std::size_t)>;

/// Core V7 writer shared by files, folders and tests.
void encrypt_stream(const ReadFn& read, std::uint64_t size, const WriteFn& write,
                    const v7::Meta& meta_in, std::string_view password, const v7::Header& header,
                    const Options& opts) {
    const std::uint64_t chunks = v7::chunk_count(size);
    if (chunks >= 0xFFFFFFFFULL) {
        throw Error(ErrorCode::InvalidArgument, "Input too large for a V7 container.");
    }
    const auto hdr = header.serialize();
    const auto hdr_hash = crypto::sha512(hdr);
    const auto keys = derive_keys(password, hdr, header, opts);

    crypto::HmacSha512 mac(keys->mac());
    mac.update(hdr);
    write(hdr.data(), hdr.size());

    // Metadata block (original name, flags, size) — encrypted & authenticated
    v7::Meta meta = meta_in;
    meta.size = size;
    auto meta_buf = meta.pack();
    std::array<std::uint8_t, v7::kMetaSize> meta_blob{};
    std::memcpy(meta_blob.data(), meta_buf.data(), meta_buf.size());
    crypto::xchacha_seal(keys->xcc(), v7::xcc_nonce(header.xcc_prefix, v7::kMetaIndex),
                         v7::meta_aad(hdr_hash), meta_blob.data(), v7::kMetaPlain,
                         meta_blob.data() + v7::kMetaPlain);
    secure_zero(meta_buf.data(), meta_buf.size());
    mac.update(meta_blob);
    write(meta_blob.data(), meta_blob.size());

    std::uint64_t next_index = 0;
    std::uint64_t remaining = size;
    std::uint64_t done = 0;
    opts.report(Phase::Encrypting, 0, size);

    const ChunkCipher cipher(*keys, header, hdr_hash, opts);
    detail::ChunkPipeline::run(
        cipher.workers(), opts.cancel,
        // reader: plaintext chunk i
        [&](detail::Job& job) {
            if (next_index == chunks) {
                return false;
            }
            const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(v7::kChunkSize, remaining));
            job.buffer.resize(n + kTag);
            if (read(job.buffer.data(), n) != n) {
                throw Error(ErrorCode::Io, "The source changed size while it was being encrypted.");
            }
            job.length = n;
            job.index = next_index++;
            job.final = job.index + 1 == chunks;
            remaining -= n;
            return true;
        },
        // workers: layer 1 AES-256-CTR, layer 2 XChaCha20-Poly1305 (in place)
        [&](detail::Job& job) { cipher.seal(job); },
        // caller thread: HMAC-SHA512, strictly in order
        [&](detail::Job& job) {
            mac.update(job.buffer.data(), job.length + kTag);
            done += job.length;
            opts.report(Phase::Encrypting, done, size);
        },
        // writer thread: the same ciphertext goes to disk concurrently
        [&](detail::Job& job) { write(job.buffer.data(), job.length + kTag); });

    const auto tag = mac.finish();
    write(tag.data(), tag.size());
}

v7::Header random_header(const Options& opts) {
    v7::Header h;
    h.kdf = opts.kdf;
    crypto::random_bytes(h.salt);
    crypto::random_bytes(h.aes_prefix);
    crypto::random_bytes(h.xcc_prefix);
    return h;
}

fs::path temp_sibling(const fs::path& target, const char* tag) {
    fs::path t = target;
    t += fsutil::from_utf8(std::string(".") + tag + "-" + fsutil::random_hex(4));
    return t;
}

/// Writes through a temp file and renames on success; removes it on failure.
void write_container(const fs::path& out, const std::function<void(const WriteFn&)>& body) {
    const fs::path tmp = temp_sibling(out, "encpto-tmp");
    try {
        File f(tmp, File::Mode::Write);
        body([&](const std::uint8_t* p, std::size_t n) { f.write(p, n); });
        f.sync();
        f.close();
        std::error_code ec;
        fs::rename(tmp, out, ec);
        if (ec) {
            fs::remove(out, ec);  // some platforms refuse to replace
            fs::rename(tmp, out);
        }
    } catch (...) {
        std::error_code ec;
        fs::remove(tmp, ec);
        throw;
    }
}

std::string name_of(const fs::path& p) {
    fs::path clean = p;
    if (!clean.has_filename()) {
        clean = clean.parent_path();  // "folder/" → "folder"
    }
    return fsutil::to_utf8(clean.filename());
}

}  // namespace

// ── Public API ──────────────────────────────────────────────────────────

ContainerInfo inspect(const fs::path& file) {
    ContainerInfo info;
    std::array<std::uint8_t, 8> magic{};
    File f(file, File::Mode::Read);
    if (f.read(magic.data(), magic.size()) != magic.size()) {
        return info;
    }
    if (magic == v7::kMagic) {
        info.kind = ContainerInfo::Kind::V7;
        info.version = 7;
    } else if (std::memcmp(magic.data(), "ENCPTO", 6) == 0 && magic[7] == 0 && magic[6] >= '2' &&
               magic[6] <= '6') {
        info.kind = ContainerInfo::Kind::LegacyV2toV6;
        info.version = magic[6] - '0';
    }
    return info;
}

void encrypt_file(const fs::path& in, const fs::path& out, std::string_view password,
                  const Options& opts) {
    File src(in, File::Mode::Read);
    const std::uint64_t size = src.size();
    v7::Meta meta;
    meta.flags = v7::kFlagFile;
    meta.name = name_of(in);
    const auto header = random_header(opts);
    write_container(out, [&](const WriteFn& write) {
        encrypt_stream([&](std::uint8_t* p, std::size_t n) { return src.read(p, n); }, size,
                       write, meta, password, header, opts);
    });
}

void encrypt_directory(const fs::path& dir, const fs::path& out, std::string_view password,
                       const Options& opts) {
    std::vector<std::uint8_t> zip = archive::pack_directory(dir, opts);
    struct Wipe {
        std::vector<std::uint8_t>& z;
        ~Wipe() { secure_zero(z.data(), z.size()); }
    } wipe{zip};

    v7::Meta meta;
    meta.flags = v7::kFlagZip;
    meta.name = name_of(fs::absolute(dir));
    const auto header = random_header(opts);
    std::size_t pos = 0;
    write_container(out, [&](const WriteFn& write) {
        encrypt_stream(
            [&](std::uint8_t* p, std::size_t n) {
                const std::size_t k = std::min(n, zip.size() - pos);
                std::memcpy(p, zip.data() + pos, k);
                pos += k;
                return k;
            },
            zip.size(), write, meta, password, header, opts);
    });
}

DecryptResult decrypt(const fs::path& in, const fs::path& out_dir, std::string_view password,
                      const Options& opts) {
    File f(in, File::Mode::Read);
    const std::uint64_t file_size = f.size();

    v7::HeaderBytes hdr{};
    if (f.read(hdr.data(), hdr.size()) < 8 ||
        !std::equal(v7::kMagic.begin(), v7::kMagic.end(), hdr.begin())) {
        const auto info = inspect(in);
        if (info.kind == ContainerInfo::Kind::LegacyV2toV6) {
            throw Error(ErrorCode::UnsupportedFormat,
                        "This is a V" + std::to_string(info.version) +
                            " container. Decrypt it once with legacy/enCPTO-v7.py.");
        }
        throw Error(ErrorCode::UnsupportedFormat, "Not an enCPTO V7 container.");
    }
    if (file_size < v7::kMinContainerSize) {
        throw Error(ErrorCode::Corrupted, "File too short — corrupted V7 container.");
    }
    const v7::Header header = v7::Header::parse(hdr);
    const auto hdr_hash = crypto::sha512(hdr);

    std::array<std::uint8_t, v7::kMetaSize> meta_blob{};
    f.read_exact(meta_blob.data(), meta_blob.size());
    std::array<std::uint8_t, v7::kMacSize> mac_stored{};
    f.seek(file_size - v7::kMacSize);
    f.read_exact(mac_stored.data(), mac_stored.size());

    const std::uint64_t body_start = v7::kHeaderSize + v7::kMetaSize;
    const std::uint64_t body_size = file_size - v7::kMacSize - body_start;

    const auto keys = derive_keys(password, hdr, header, opts);

    // 1) Metadata: authenticates the password in well under a second.
    std::array<std::uint8_t, v7::kMetaSize> meta_plain = meta_blob;
    if (!crypto::xchacha_open(keys->xcc(), v7::xcc_nonce(header.xcc_prefix, v7::kMetaIndex),
                              v7::meta_aad(hdr_hash), meta_plain.data(), v7::kMetaPlain,
                              meta_blob.data() + v7::kMetaPlain)) {
        throw Error(ErrorCode::WrongPassword,
                    "Wrong password or file tampered (metadata authentication failed).");
    }
    const v7::Meta meta = v7::Meta::unpack(std::span(meta_plain).first(v7::kMetaPlain));
    secure_zero(meta_plain.data(), meta_plain.size());
    if (meta.size > body_size) {
        throw Error(ErrorCode::Corrupted, "Size mismatch — file truncated or tampered.");
    }

    // Set up the cipher (and the GPU, if requested) before the long HMAC pass,
    // so an unavailable GPU is reported immediately.
    const ChunkCipher cipher(*keys, header, hdr_hash, opts);

    // 2) Whole-file HMAC-SHA512 before a single byte of plaintext is written.
    {
        crypto::HmacSha512 mac(keys->mac());
        mac.update(hdr);
        mac.update(meta_blob);
        f.seek(body_start);
        // Double-buffered: the disk read of block n+1 overlaps hashing block n.
        std::vector<std::uint8_t> a(v7::kChunkSize), b(v7::kChunkSize);
        std::uint64_t remaining = body_size, verified = 0;
        auto pending = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, a.size()));
        f.read_exact(a.data(), pending);
        remaining -= pending;
        while (pending != 0) {
            if (opts.is_cancelled()) {
                throw Error(ErrorCode::Cancelled, "Operation cancelled.");
            }
            const auto next = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, b.size()));
            std::exception_ptr read_error;
            std::thread reader;
            if (next != 0) {
                reader = std::thread([&] {
                    try {
                        f.read_exact(b.data(), next);
                    } catch (...) {
                        read_error = std::current_exception();
                    }
                });
            }
            mac.update(a.data(), pending);
            if (reader.joinable()) {
                reader.join();
            }
            if (read_error) {
                std::rethrow_exception(read_error);
            }
            verified += pending;
            remaining -= next;
            opts.report(Phase::Verifying, verified, body_size);
            a.swap(b);
            pending = next;
        }
        const auto tag = mac.finish();
        if (!crypto::equal(tag, mac_stored)) {
            throw Error(ErrorCode::Tampered,
                        "HMAC-SHA512 mismatch — the file was modified or is corrupted.");
        }
    }

    // 3) Decrypt: XChaCha20-Poly1305 open → AES-256-CTR, in parallel
    const bool is_zip = meta.flags == v7::kFlagZip;
    std::string fallback = fsutil::to_utf8(in.stem());
    if (fallback.empty()) {
        fallback = "decrypted";
    }
    fs::create_directories(out_dir);
    const fs::path target =
        fsutil::unique_path(out_dir / fsutil::from_utf8(fsutil::safe_output_name(meta.name, fallback)));

    std::vector<std::uint8_t> zip;  // folder payloads are restored from memory
    std::unique_ptr<File> out_file;
    const fs::path tmp = temp_sibling(target, "dec-tmp");
    if (is_zip) {
        zip.reserve(static_cast<std::size_t>(meta.size));
    } else {
        out_file = std::make_unique<File>(tmp, File::Mode::Write);
    }
    struct Cleanup {
        std::vector<std::uint8_t>& zip;
        std::unique_ptr<File>& file;
        const fs::path& tmp;
        bool keep = false;
        ~Cleanup() {
            secure_zero(zip.data(), zip.size());
            file.reset();
            if (!keep) {
                std::error_code ec;
                fs::remove(tmp, ec);
            }
        }
    } cleanup{zip, out_file, tmp};

    f.seek(body_start);
    std::uint64_t remaining = body_size;
    std::uint64_t next_index = 0;
    std::uint64_t written = 0;
    opts.report(Phase::Decrypting, 0, body_size);

    detail::ChunkPipeline::run(
        cipher.workers(), opts.cancel,
        [&](detail::Job& job) {
            if (remaining == 0) {
                return false;
            }
            const auto n = static_cast<std::size_t>(
                std::min<std::uint64_t>(v7::kChunkSize + kTag, remaining));
            if (n < kTag) {
                throw Error(ErrorCode::Corrupted, "Truncated chunk — corrupted V7 container.");
            }
            job.buffer.resize(n);
            f.read_exact(job.buffer.data(), n);
            remaining -= n;
            job.length = n - kTag;
            job.index = next_index++;
            job.final = remaining == 0;
            return true;
        },
        [&](detail::Job& job) { cipher.open(job); },
        [&](detail::Job& job) {
            if (written + job.length > meta.size) {
                throw Error(ErrorCode::Corrupted, "Size mismatch — file truncated or tampered.");
            }
            written += job.length;
            opts.report(Phase::Decrypting, written, meta.size);
        },
        [&](detail::Job& job) {
            if (is_zip) {
                if (zip.size() + job.length > meta.size) {
                    throw Error(ErrorCode::Corrupted, "Size mismatch — file truncated or tampered.");
                }
                zip.insert(zip.end(), job.buffer.begin(),
                           job.buffer.begin() + static_cast<std::ptrdiff_t>(job.length));
            } else {
                out_file->write(job.buffer.data(), job.length);
            }
        });

    if (written != meta.size) {
        throw Error(ErrorCode::Corrupted, "Size mismatch — file truncated or tampered.");
    }

    DecryptResult result;
    result.path = target;
    result.is_directory = is_zip;
    result.original_name = meta.name;
    if (is_zip) {
        archive::restore_folder(zip, target, opts);
    } else {
        out_file->sync();
        out_file->close();
        fs::rename(tmp, target);
        cleanup.keep = true;
    }
    return result;
}

namespace detail {

std::vector<std::uint8_t> encrypt_buffer(const std::vector<std::uint8_t>& payload,
                                         const v7::Meta& meta, std::string_view password,
                                         const v7::Header& header, const Options& opts) {
    std::vector<std::uint8_t> out;
    std::size_t pos = 0;
    encrypt_stream(
        [&](std::uint8_t* p, std::size_t n) {
            const std::size_t k = std::min(n, payload.size() - pos);
            std::memcpy(p, payload.data() + pos, k);
            pos += k;
            return k;
        },
        payload.size(), [&](const std::uint8_t* p, std::size_t n) { out.insert(out.end(), p, p + n); },
        meta, password, header, opts);
    return out;
}

}  // namespace detail
}  // namespace encpto
