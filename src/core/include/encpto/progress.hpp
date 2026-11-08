#pragma once

#include <atomic>
#include <cstdint>
#include <functional>

#include "encpto/format.hpp"

namespace encpto {

enum class Phase {
    DerivingKey,  // Argon2id (~0.5 s, fixed cost)
    Packing,      // folder → ZIP
    Encrypting,
    Verifying,    // HMAC-SHA512 pass before any plaintext is written
    Decrypting,
    Extracting,   // ZIP → folder
    Shredding,
};

struct Progress {
    Phase phase;
    std::uint64_t done;
    std::uint64_t total;
};

using ProgressCallback = std::function<void(const Progress&)>;

struct Options {
    /// Worker threads for the cipher layers; 0 = all hardware threads.
    unsigned threads = 0;
    /// Called from worker context — keep it cheap and thread-safe.
    ProgressCallback on_progress;
    /// Set to true from any thread to abort; the operation throws
    /// Error(ErrorCode::Cancelled) and removes partial output.
    const std::atomic_bool* cancel = nullptr;
    /// Argon2id profile used for *new* containers (stored in the header).
    v7::KdfParams kdf{};
    /// EXPERIMENTAL: run both cipher layers' keystreams on an OpenCL device.
    /// Output is byte-identical to the CPU path. Throws Error(ErrorCode::Gpu)
    /// if no usable device exists.
    bool use_gpu = false;
    /// gpu::Device::index, or -1 for gpu::default_device().
    int gpu_device = -1;

    void report(Phase phase, std::uint64_t done, std::uint64_t total) const {
        if (on_progress) {
            on_progress(Progress{phase, done, total});
        }
    }
    [[nodiscard]] bool is_cancelled() const { return cancel != nullptr && cancel->load(); }
    [[nodiscard]] unsigned worker_count() const;
};

}  // namespace encpto
