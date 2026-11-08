#pragma once

#include "encpto/crypto.hpp"
#include "encpto/format.hpp"

#include <array>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace encpto::gpu::detail {

/// One encryption/decryption job on an OpenCL device.
///
/// A single kernel produces BOTH layers' keystreams for a chunk and XORs them
/// into the data:   data ^= AES-256-CTR(k_aes, chunk i) ^ ChaCha20(subkey, chunk i)
/// so each chunk crosses the bus only once in each direction. Poly1305 (the
/// authenticator) stays on the CPU, using OpenSSL's assembly.
///
/// Several "lanes" (command queue + device buffer) let uploads, kernels and
/// downloads of different chunks overlap.
class Session {
public:
    Session(int device_index, crypto::Bytes k_aes, crypto::Bytes k_xcc,
            const std::array<std::uint8_t, v7::kAesPrefixLen>& aes_prefix,
            const std::array<std::uint8_t, v7::kXccPrefixLen>& xcc_prefix, unsigned lanes);
    ~Session();  // zero-fills every device buffer before releasing it

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    [[nodiscard]] unsigned lanes() const { return static_cast<unsigned>(lanes_.size()); }

    /// In place, thread-safe. `size` ≤ v7::kChunkSize.
    void xor_keystreams(std::uint64_t chunk_index, std::uint8_t* data, std::size_t size);

    /// HChaCha20 sub-key (for the CPU-side Poly1305 one-time key).
    [[nodiscard]] crypto::Bytes chacha_subkey() const { return subkey_; }

private:
    struct Lane;
    void cleanup() noexcept;
    Lane* acquire();
    void release(Lane* lane);

    void* context_ = nullptr;  // cl_context (shared, not owned)
    void* keys_ = nullptr;     // cl_mem: Te0 ‖ S-box ‖ AES round keys ‖ ChaCha sub-key
    void* kernel_ = nullptr;   // cl_kernel, shared by all lanes
    std::mutex launch_mu_;     // guards kernel arguments + launch (see xor_keystreams)
    void* last_run_ = nullptr; // cl_event of the previous kernel run (chains runs)
    std::array<std::uint32_t, 2> aes_prefix_words_{};
    std::array<std::uint8_t, 32> subkey_{};
    std::vector<std::unique_ptr<Lane>> lanes_;
    std::vector<Lane*> free_;
    std::mutex mu_;
    std::condition_variable cv_;
};

/// AES-256 key schedule (FIPS-197), 60 big-endian words. Exposed for tests.
std::array<std::uint32_t, 60> aes256_expand_key(crypto::Bytes key);

}  // namespace encpto::gpu::detail
