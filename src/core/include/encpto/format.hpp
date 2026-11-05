#pragma once

// enCPTO V7 container format — byte-for-byte compatible with enCPTO v7.0 (Python).
//
//   Password ─► Argon2id(t, m, p; 32-byte salt) ─► 64-byte master
//   master  ─► HKDF-SHA512(salt = SHA-512(header), info = "enCPTO-v7 subkeys")
//                 ├─ k_aes (32 B)  layer 1  AES-256-CTR
//                 ├─ k_xcc (32 B)  layer 2  XChaCha20-Poly1305
//                 └─ k_mac (64 B)  HMAC-SHA512 over the whole container
//
//   ┌──────────────────────────────────────────────────────────────┐
//   │ Header 74 B  magic(8) kdf_id(1) t(4) m_kib(4) p(1) salt(32)   │
//   │              aes_iv_prefix(8) xcc_nonce_prefix(16)            │
//   │ Meta   528 B XChaCha20-Poly1305(flags, filename, size)        │
//   │ Chunks       [ct(≤ 4 MiB) + tag(16)] × N   (N ≥ 1)            │
//   │ Trailer 64 B HMAC-SHA512(header ‖ meta ‖ all chunks)          │
//   └──────────────────────────────────────────────────────────────┘
//   All integers are big-endian.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace encpto::v7 {

inline constexpr std::array<std::uint8_t, 8> kMagic = {'E', 'N', 'C', 'P', 'T', 'O', '7', 0};

inline constexpr std::size_t kSaltLen = 32;
inline constexpr std::size_t kAesPrefixLen = 8;
inline constexpr std::size_t kXccPrefixLen = 16;
inline constexpr std::size_t kHeaderSize = 8 + 1 + 4 + 4 + 1 + kSaltLen + kAesPrefixLen + kXccPrefixLen;  // 74
inline constexpr std::size_t kMetaPlain = 512;
inline constexpr std::size_t kTag = 16;
inline constexpr std::size_t kMetaSize = kMetaPlain + kTag;  // 528
inline constexpr std::size_t kMacSize = 64;
inline constexpr std::size_t kChunkSize = 4 * 1024 * 1024;
inline constexpr std::size_t kSubkeyBytes = 128;  // k_aes ‖ k_xcc ‖ k_mac
inline constexpr std::uint64_t kMetaIndex = 0xFFFFFFFFFFFFFFFFULL;
inline constexpr std::size_t kMaxNameBytes = 255;
inline constexpr std::uint64_t kMinContainerSize = kHeaderSize + kMetaSize + kTag + kMacSize;

inline constexpr std::uint8_t kKdfArgon2id = 0x01;
inline constexpr std::uint8_t kFlagFile = 0x00;
inline constexpr std::uint8_t kFlagZip = 0x01;

inline constexpr char kHkdfInfo[] = "enCPTO-v7 subkeys";

struct KdfParams {
    std::uint32_t time_cost = 4;
    std::uint32_t memory_kib = 256 * 1024;  // 256 MiB
    std::uint8_t parallelism = 4;
};

// Sanity limits applied to untrusted headers (DoS protection).
inline constexpr std::uint32_t kLimitTime = 64;
inline constexpr std::uint32_t kLimitMemKib = 4 * 1024 * 1024;  // 4 GiB
inline constexpr std::uint32_t kLimitPar = 64;
inline constexpr std::uint32_t kMinMemKib = 65536;  // never weaker than the V3–V6 profile

using HeaderBytes = std::array<std::uint8_t, kHeaderSize>;

struct Header {
    KdfParams kdf;
    std::array<std::uint8_t, kSaltLen> salt{};
    std::array<std::uint8_t, kAesPrefixLen> aes_prefix{};
    std::array<std::uint8_t, kXccPrefixLen> xcc_prefix{};

    [[nodiscard]] HeaderBytes serialize() const;
    /// Throws Error(Corrupted / UnsupportedFormat) for invalid or hostile input.
    static Header parse(std::span<const std::uint8_t> bytes);
};

struct Meta {
    std::uint8_t flags = kFlagFile;
    std::string name;  // UTF-8, ≤ 255 bytes
    std::uint64_t size = 0;

    [[nodiscard]] std::array<std::uint8_t, kMetaPlain> pack() const;
    static Meta unpack(std::span<const std::uint8_t> plain);
};

/// Truncates UTF-8 to at most `max_bytes` without splitting a code point.
std::string truncate_utf8(const std::string& s, std::size_t max_bytes);

std::array<std::uint8_t, 24> xcc_nonce(const std::array<std::uint8_t, kXccPrefixLen>& prefix,
                                       std::uint64_t index);
/// prefix(8) ‖ chunk index(4) ‖ 32-bit block counter starting at 0
std::array<std::uint8_t, 16> aes_iv(const std::array<std::uint8_t, kAesPrefixLen>& prefix,
                                    std::uint32_t index);
/// SHA-512(header) ‖ index(8) ‖ final(1)
std::array<std::uint8_t, 73> chunk_aad(const std::array<std::uint8_t, 64>& header_hash,
                                       std::uint64_t index, bool final);
/// SHA-512(header) ‖ "meta"
std::array<std::uint8_t, 68> meta_aad(const std::array<std::uint8_t, 64>& header_hash);

/// Number of chunks for a payload of `size` bytes (an empty payload is one empty chunk).
std::uint64_t chunk_count(std::uint64_t payload_size);

}  // namespace encpto::v7
