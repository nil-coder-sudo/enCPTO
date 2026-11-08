#pragma once

// Built-in benchmark: measures every stage of the pipeline on this machine
// and names the one that limits end-to-end speed.

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace encpto::bench {

enum class StageId {
    Argon2id,     // key derivation with the default profile (seconds, not MiB/s)
    AesOneCore,   // layer 1, one core
    ChaChaOneCore,// layer 2 incl. Poly1305, one core
    Hmac,         // HMAC-SHA512 — sequential by design, one core
    LayersCpu,    // both layers, all worker threads
    LayersGpu,    // both layers on the OpenCL device (incl. bus transfers)
    PipelineCpu,  // whole encryption pipeline in memory, CPU
    PipelineGpu,  // whole encryption pipeline in memory, GPU
};

struct Stage {
    StageId id;
    double mib_per_s = 0;  // 0 for Argon2id
    double seconds = 0;
};

struct Settings {
    std::size_t mib = 512;      // data per throughput stage
    unsigned threads = 0;       // 0 = all hardware threads
    bool gpu = false;
    int gpu_device = -1;
    const std::atomic_bool* cancel = nullptr;
    std::function<void(int step, int total)> on_step;
};

struct Report {
    std::vector<Stage> stages;
    unsigned threads = 0;
    std::string gpu_device;  // name of the device used, if any
    std::string gpu_error;   // why the GPU stages were skipped
    /// Slowest stage on the fastest end-to-end path (Hmac, LayersCpu or LayersGpu).
    StageId bottleneck = StageId::Hmac;

    [[nodiscard]] const Stage* find(StageId id) const {
        for (const auto& s : stages) {
            if (s.id == id) return &s;
        }
        return nullptr;
    }
};

/// Takes roughly 5–15 seconds. Throws Error(ErrorCode::Cancelled) if cancelled.
Report run(const Settings& settings);

}  // namespace encpto::bench
