#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace encpto::crypto {

using Bytes = std::span<const std::uint8_t>;

/// Initialises libsodium / OpenSSL. Thread-safe and idempotent.
void init();

void random_bytes(std::span<std::uint8_t> out);
/// Uniform random integer in [0, upper_bound).
std::uint32_t random_below(std::uint32_t upper_bound);

std::array<std::uint8_t, 64> sha512(Bytes data);

/// Incremental HMAC-SHA512 (OpenSSL, uses SIMD-accelerated SHA-512).
class HmacSha512 {
public:
    explicit HmacSha512(Bytes key);
    ~HmacSha512();
    HmacSha512(const HmacSha512&) = delete;
    HmacSha512& operator=(const HmacSha512&) = delete;

    void update(Bytes data);
    void update(const void* data, std::size_t size);
    std::array<std::uint8_t, 64> finish();

private:
    void* ctx_ = nullptr;  // EVP_MAC_CTX*
};

/// RFC 5869 HKDF with SHA-512 (extract + expand).
void hkdf_sha512(Bytes ikm, Bytes salt, Bytes info, std::span<std::uint8_t> out);

/// Argon2id v1.3 (RFC 9106), multi-threaded across `parallelism` lanes.
void argon2id(Bytes password, Bytes salt, std::uint32_t time_cost, std::uint32_t memory_kib,
              std::uint32_t parallelism, std::span<std::uint8_t> out);

/// AES-256-CTR keystream XOR, in place. `iv` is the full 16-byte initial
/// counter block (big-endian increment, AES-NI accelerated via OpenSSL).
void aes256_ctr_xor(Bytes key, const std::array<std::uint8_t, 16>& iv, std::uint8_t* data,
                    std::size_t size);

constexpr std::size_t kXChaChaKeyLen = 32;
constexpr std::size_t kXChaChaNonceLen = 24;
constexpr std::size_t kTagLen = 16;

/// XChaCha20-Poly1305 (IETF), in place, detached tag (OpenSSL assembly via HChaCha20).
void xchacha_seal(Bytes key, const std::array<std::uint8_t, 24>& nonce, Bytes ad,
                  std::uint8_t* data, std::size_t size, std::uint8_t* tag_out);

/// Decrypts in place and verifies the tag. Returns false (and wipes the
/// buffer) if authentication fails.
[[nodiscard]] bool xchacha_open(Bytes key, const std::array<std::uint8_t, 24>& nonce, Bytes ad,
                                std::uint8_t* data, std::size_t size, const std::uint8_t* tag);

/// HChaCha20 sub-key derivation (first step of XChaCha20).
std::array<std::uint8_t, 32> hchacha20(Bytes key, Bytes nonce16);
/// 0x00000000 ‖ xnonce[16:24] — the IETF ChaCha20 nonce used after HChaCha20.
std::array<std::uint8_t, 12> ietf_nonce(const std::array<std::uint8_t, 24>& xnonce);
/// RFC 8439 AEAD tag over `ad` and ciphertext `ct`, computed separately from
/// the encryption (used by the GPU path, which only produces keystream).
void poly1305_aead_tag(Bytes subkey, const std::array<std::uint8_t, 12>& nonce, Bytes ad,
                       const std::uint8_t* ct, std::size_t size, std::uint8_t* tag_out);

/// Constant-time comparison.
[[nodiscard]] bool equal(Bytes a, Bytes b);

}  // namespace encpto::crypto
