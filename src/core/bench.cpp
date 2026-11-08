#include "encpto/bench.hpp"

#include "encpto/crypto.hpp"
#include "encpto/engine.hpp"
#include "encpto/error.hpp"
#include "encpto/format.hpp"
#include "encpto/gpu.hpp"
#include "encpto/secure_memory.hpp"
#include "gpu/session.hpp"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <thread>

namespace encpto::bench {
namespace {

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t) {
    return std::chrono::duration<double>(Clock::now() - t).count();
}

constexpr std::size_t kChunk = v7::kChunkSize;
const char* const kPassword = "benchmark-password";

/// Runs `per_chunk(buffer, chunk_index)` over `total` bytes on `threads` threads.
template <typename F>
double parallel_mibps(unsigned threads, std::size_t total, const std::vector<std::uint8_t>& src,
                      const std::atomic_bool* cancel, F&& per_chunk) {
    const std::size_t chunks = total / kChunk;
    std::atomic<std::size_t> next{0};
    std::exception_ptr error;
    std::mutex mu;
    const auto t0 = Clock::now();
    std::vector<std::thread> pool;
    for (unsigned w = 0; w < threads; ++w) {
        pool.emplace_back([&] {
            try {
                std::vector<std::uint8_t> buf(src.begin(), src.begin() + static_cast<std::ptrdiff_t>(kChunk));
                buf.resize(kChunk + v7::kTag);
                for (std::size_t i; (i = next.fetch_add(1)) < chunks;) {
                    if (cancel != nullptr && cancel->load()) return;
                    per_chunk(buf.data(), static_cast<std::uint64_t>(i));
                }
            } catch (...) {
                std::lock_guard lk(mu);
                if (!error) error = std::current_exception();
                next = chunks;
            }
        });
    }
    for (auto& t : pool) t.join();
    if (error) std::rethrow_exception(error);
    return static_cast<double>(total) / 1048576.0 / seconds_since(t0);
}

}  // namespace

Report run(const Settings& s) {
    crypto::init();
    Report r;
    r.threads = s.threads != 0 ? s.threads : std::max(1U, std::thread::hardware_concurrency());
    const std::size_t total = std::max<std::size_t>(s.mib, 16) / 4 * 4 * 1048576;  // whole chunks
    const std::size_t single = std::max<std::size_t>(total / 2, 16 * 1048576);
    const int steps = s.gpu ? 8 : 6;
    int step = 0;
    const auto tick = [&] {
        if (s.cancel != nullptr && s.cancel->load()) throw Error(ErrorCode::Cancelled, "Benchmark cancelled.");
        if (s.on_step) s.on_step(++step, steps);
    };
    if (s.on_step) s.on_step(0, steps);

    std::vector<std::uint8_t> src(64 * 1048576);
    crypto::random_bytes(src);
    SecureBytes keys(128);
    crypto::random_bytes(keys.span());
    const auto k_aes = keys.sub(0, 32), k_xcc = keys.sub(32, 32), k_mac = keys.sub(64, 64);
    std::array<std::uint8_t, 24> xnonce{};
    crypto::random_bytes(xnonce);
    std::array<std::uint8_t, 73> aad{};

    // 1. Argon2id, default profile
    {
        const v7::KdfParams k;
        std::array<std::uint8_t, 64> out{};
        std::array<std::uint8_t, 32> salt{};
        const auto t0 = Clock::now();
        crypto::argon2id(k_xcc, salt, k.time_cost, k.memory_kib, k.parallelism, out);
        r.stages.push_back({StageId::Argon2id, 0, seconds_since(t0)});
    }
    tick();

    // 2–4. Single-core stages
    {
        std::vector<std::uint8_t> buf(src.begin(), src.begin() + static_cast<std::ptrdiff_t>(kChunk));
        buf.resize(kChunk + 16);
        const auto run_single = [&](StageId id, auto&& fn) {
            const auto t0 = Clock::now();
            for (std::size_t done = 0; done < single; done += kChunk) fn();
            const double secs = seconds_since(t0);
            r.stages.push_back({id, static_cast<double>(single) / 1048576.0 / secs, secs});
            tick();
        };
        std::array<std::uint8_t, 16> iv{};
        run_single(StageId::AesOneCore, [&] { crypto::aes256_ctr_xor(k_aes, iv, buf.data(), kChunk); });
        run_single(StageId::ChaChaOneCore,
                   [&] { crypto::xchacha_seal(k_xcc, xnonce, aad, buf.data(), kChunk, buf.data() + kChunk); });
        crypto::HmacSha512 mac(k_mac);
        run_single(StageId::Hmac, [&] { mac.update(buf.data(), kChunk); });
        (void)mac.finish();
    }

    // 5. Both layers on every core
    {
        std::array<std::uint8_t, 16> iv{};
        const double v = parallel_mibps(r.threads, total, src, s.cancel, [&](std::uint8_t* b, std::uint64_t) {
            crypto::aes256_ctr_xor(k_aes, iv, b, kChunk);
            crypto::xchacha_seal(k_xcc, xnonce, aad, b, kChunk, b + kChunk);
        });
        r.stages.push_back({StageId::LayersCpu, v, 0});
        tick();
    }

    // 6. Full pipeline, CPU
    const auto pipeline = [&](bool gpu) {
        Options o;
        o.threads = s.threads;
        o.cancel = s.cancel;
        o.kdf = {1, 65536, 1};  // Argon2id is measured separately
        o.use_gpu = gpu;
        o.gpu_device = s.gpu_device;
        Clock::time_point start{};
        std::once_flag started;
        o.on_progress = [&](const Progress& p) {
            if (p.phase == Phase::Encrypting) std::call_once(started, [&] { start = Clock::now(); });
        };
        detail::encrypt_discard(src, total, kPassword, o);
        const double secs = seconds_since(start);
        return static_cast<double>(total) / 1048576.0 / secs;
    };
    r.stages.push_back({StageId::PipelineCpu, pipeline(false), 0});
    tick();

    // 7–8. GPU
    if (s.gpu) {
        try {
            const int dev = s.gpu_device >= 0 ? s.gpu_device : gpu::default_device();
            if (dev < 0) throw Error(ErrorCode::Gpu, gpu::probe().message);
            r.gpu_device = gpu::probe().devices.at(static_cast<std::size_t>(dev)).name;
            std::array<std::uint8_t, v7::kAesPrefixLen> ap{};
            std::array<std::uint8_t, v7::kXccPrefixLen> xp{};
            gpu::detail::Session session(dev, k_aes, k_xcc, ap, xp, 4);
            std::vector<std::uint8_t> warm(kChunk);
            session.xor_keystreams(0, warm.data(), warm.size());  // first run may JIT / page in
            const auto n12 = crypto::ietf_nonce(xnonce);
            const double v = parallel_mibps(session.lanes(), total, src, s.cancel, [&](std::uint8_t* b, std::uint64_t i) {
                session.xor_keystreams(i, b, kChunk);
                crypto::poly1305_aead_tag(session.chacha_subkey(), n12, aad, b, kChunk, b + kChunk);
            });
            r.stages.push_back({StageId::LayersGpu, v, 0});
            tick();
            r.stages.push_back({StageId::PipelineGpu, pipeline(true), 0});
            tick();
        } catch (const Error& e) {
            if (e.code() == ErrorCode::Cancelled) throw;
            r.gpu_error = e.what();
        }
    }

    // Bottleneck of the fastest end-to-end path
    const auto v = [&](StageId id) {
        const Stage* st = r.find(id);
        return st != nullptr ? st->mib_per_s : 0.0;
    };
    const bool gpu_wins = v(StageId::PipelineGpu) > v(StageId::PipelineCpu);
    const StageId layers = gpu_wins ? StageId::LayersGpu : StageId::LayersCpu;
    r.bottleneck = v(StageId::Hmac) <= v(layers) ? StageId::Hmac : layers;
    return r;
}

}  // namespace encpto::bench
