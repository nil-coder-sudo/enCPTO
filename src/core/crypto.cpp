#include "encpto/crypto.hpp"

#include "encpto/error.hpp"

#include <algorithm>
#include <climits>
#include <mutex>
#include <string>

#include <argon2.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sodium.h>

namespace encpto::crypto {
namespace {

[[noreturn]] void fail(const char* what) {
    std::string msg = std::string("Crypto error: ") + what;
    if (const unsigned long e = ERR_get_error(); e != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof buf);
        msg += " (";
        msg += buf;
        msg += ")";
    }
    throw Error(ErrorCode::Internal, msg);
}

EVP_MAC* hmac_algorithm() {
    static EVP_MAC* mac = [] {
        EVP_MAC* m = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (m == nullptr) {
            fail("HMAC unavailable");
        }
        return m;
    }();
    return mac;
}

}  // namespace

void init() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (sodium_init() < 0) {
            throw Error(ErrorCode::Internal, "libsodium initialisation failed");
        }
    });
}

void random_bytes(std::span<std::uint8_t> out) {
    init();
    randombytes_buf(out.data(), out.size());
}

std::uint32_t random_below(std::uint32_t upper_bound) {
    init();
    return randombytes_uniform(upper_bound);
}

std::array<std::uint8_t, 64> sha512(Bytes data) {
    std::array<std::uint8_t, 64> out{};
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha512(), nullptr) != 1 ||
        len != out.size()) {
        fail("SHA-512");
    }
    return out;
}

// ── HMAC-SHA512 ─────────────────────────────────────────────────────────

HmacSha512::HmacSha512(Bytes key) {
    auto* ctx = EVP_MAC_CTX_new(hmac_algorithm());
    if (ctx == nullptr) {
        fail("EVP_MAC_CTX_new");
    }
    char digest[] = "SHA512";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1) {
        EVP_MAC_CTX_free(ctx);
        fail("HMAC init");
    }
    ctx_ = ctx;
}

HmacSha512::~HmacSha512() { EVP_MAC_CTX_free(static_cast<EVP_MAC_CTX*>(ctx_)); }

void HmacSha512::update(Bytes data) { update(data.data(), data.size()); }

void HmacSha512::update(const void* data, std::size_t size) {
    if (size != 0 &&
        EVP_MAC_update(static_cast<EVP_MAC_CTX*>(ctx_), static_cast<const unsigned char*>(data),
                       size) != 1) {
        fail("HMAC update");
    }
}

std::array<std::uint8_t, 64> HmacSha512::finish() {
    std::array<std::uint8_t, 64> out{};
    std::size_t len = 0;
    if (EVP_MAC_final(static_cast<EVP_MAC_CTX*>(ctx_), out.data(), &len, out.size()) != 1 ||
        len != out.size()) {
        fail("HMAC final");
    }
    return out;
}

// ── HKDF-SHA512 ─────────────────────────────────────────────────────────

void hkdf_sha512(Bytes ikm, Bytes salt, Bytes info, std::span<std::uint8_t> out) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) {
        fail("HKDF unavailable");
    }
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) {
        fail("EVP_KDF_CTX_new");
    }
    char digest[] = "SHA512";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(ikm.data()),
                                          ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          const_cast<std::uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          const_cast<std::uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end(),
    };
    const int rc = EVP_KDF_derive(ctx, out.data(), out.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (rc != 1) {
        fail("HKDF derive");
    }
}

// ── Argon2id ────────────────────────────────────────────────────────────

void argon2id(Bytes password, Bytes salt, std::uint32_t time_cost, std::uint32_t memory_kib,
              std::uint32_t parallelism, std::span<std::uint8_t> out) {
    const int rc = argon2_hash(time_cost, memory_kib, parallelism, password.data(),
                               password.size(), salt.data(), salt.size(), out.data(), out.size(),
                               nullptr, 0, Argon2_id, ARGON2_VERSION_13);
    if (rc != ARGON2_OK) {
        throw Error(rc == ARGON2_MEMORY_ALLOCATION_ERROR ? ErrorCode::Io : ErrorCode::Internal,
                    std::string("Argon2id failed: ") + argon2_error_message(rc));
    }
}

// ── AES-256-CTR ─────────────────────────────────────────────────────────

void aes256_ctr_xor(Bytes key, const std::array<std::uint8_t, 16>& iv, std::uint8_t* data,
                    std::size_t size) {
    if (size == 0) {
        return;
    }
    if (key.size() != 32) {
        throw Error(ErrorCode::InvalidArgument, "AES-256 key must be 32 bytes");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fail("AES-CTR init");
    }
    std::size_t done = 0;
    while (done < size) {
        const int n = static_cast<int>(std::min<std::size_t>(size - done, INT_MAX / 2));
        int outl = 0;
        if (EVP_EncryptUpdate(ctx, data + done, &outl, data + done, n) != 1 || outl != n) {
            EVP_CIPHER_CTX_free(ctx);
            fail("AES-CTR update");
        }
        done += static_cast<std::size_t>(n);
    }
    EVP_CIPHER_CTX_free(ctx);
}

// ── XChaCha20-Poly1305 ──────────────────────────────────────────────────

void xchacha_seal(Bytes key, const std::array<std::uint8_t, 24>& nonce, Bytes ad,
                  std::uint8_t* data, std::size_t size, std::uint8_t* tag_out) {
    if (key.size() != kXChaChaKeyLen) {
        throw Error(ErrorCode::InvalidArgument, "XChaCha20 key must be 32 bytes");
    }
    unsigned long long taglen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(data, tag_out, &taglen, data, size,
                                                        ad.data(), ad.size(), nullptr,
                                                        nonce.data(), key.data());
}

bool xchacha_open(Bytes key, const std::array<std::uint8_t, 24>& nonce, Bytes ad,
                  std::uint8_t* data, std::size_t size, const std::uint8_t* tag) {
    if (key.size() != kXChaChaKeyLen) {
        throw Error(ErrorCode::InvalidArgument, "XChaCha20 key must be 32 bytes");
    }
    return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(data, nullptr, data, size, tag,
                                                               ad.data(), ad.size(), nonce.data(),
                                                               key.data()) == 0;
}

bool equal(Bytes a, Bytes b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace encpto::crypto
