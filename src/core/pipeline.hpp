#pragma once

// Ordered parallel chunk pipeline.
//
//   reader thread ─► N worker threads ─┬─► caller thread  consume()  (in order)
//     produce()        transform()     └─► writer thread  write()    (in order)
//
// Chunks of a V7 container are independent for both cipher layers, so they
// are encrypted/decrypted on every core. The HMAC-SHA512 over the whole
// container is inherently sequential; it runs in consume() while the writer
// thread stores the very same (read-only) buffer, so hashing, disk I/O and
// the cipher work all overlap.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "encpto/error.hpp"
#include "encpto/secure_memory.hpp"

namespace encpto::detail {

struct Job {
    std::uint64_t index = 0;
    bool final = false;
    std::size_t length = 0;  // payload bytes in `buffer` (excluding any tag)
    std::vector<std::uint8_t> buffer;

    // bookkeeping (owned by the pipeline)
    std::uint64_t seq = 0;
    int pending = 0;
};

class ChunkPipeline {
public:
    /// Fills `job`; returns false when there is nothing more to produce.
    using Produce = std::function<bool(Job&)>;
    using Stage = std::function<void(Job&)>;

    /// `consume` (caller thread) and `write` (writer thread) may be empty.
    static void run(unsigned workers, const std::atomic_bool* cancel, const Produce& produce,
                    const Stage& transform, const Stage& consume, const Stage& write) {
        workers = workers == 0 ? 1 : workers;
        ChunkPipeline p(workers + 4, cancel);
        p.execute(workers, produce, transform, consume, write);
    }

private:
    ChunkPipeline(std::size_t buffers, const std::atomic_bool* cancel) : cancel_(cancel) {
        for (std::size_t i = 0; i < buffers; ++i) {
            storage_.push_back(std::make_unique<Job>());
            free_.push_back(storage_.back().get());
        }
    }

    ~ChunkPipeline() {
        for (auto& j : storage_) {  // plaintext may have passed through these buffers
            secure_zero(j->buffer.data(), j->buffer.size());
        }
    }

    [[nodiscard]] bool cancelled() const { return cancel_ != nullptr && cancel_->load(); }

    static void throw_cancelled() { throw Error(ErrorCode::Cancelled, "Operation cancelled."); }

    void set_error(std::exception_ptr e) {
        std::lock_guard lk(mu_);
        if (!error_) {
            error_ = std::move(e);
        }
        stop_ = true;
        cv_.notify_all();
    }

    void release(Job* job) {
        std::lock_guard lk(mu_);
        if (--job->pending == 0) {
            free_.push_back(job);
            cv_.notify_all();
        }
    }

    void execute(unsigned workers, const Produce& produce, const Stage& transform,
                 const Stage& consume, const Stage& write) {
        // ── reader ──────────────────────────────────────────────────────
        std::thread reader([&] {
            try {
                for (std::uint64_t seq = 0;; ++seq) {
                    Job* job = nullptr;
                    {
                        std::unique_lock lk(mu_);
                        cv_.wait(lk, [&] { return stop_ || !free_.empty(); });
                        if (stop_) return;
                        job = free_.front();
                        free_.pop_front();
                    }
                    if (cancelled()) throw_cancelled();
                    const bool more = produce(*job);
                    std::lock_guard lk(mu_);
                    if (!more) {
                        free_.push_back(job);
                        producer_done_ = true;
                        produced_ = seq;
                        cv_.notify_all();
                        return;
                    }
                    job->seq = seq;
                    work_.push_back(job);
                    if (job->final) {
                        producer_done_ = true;
                        produced_ = seq + 1;
                    }
                    cv_.notify_all();
                    if (job->final) return;
                }
            } catch (...) {
                set_error(std::current_exception());
            }
        });

        // ── workers ─────────────────────────────────────────────────────
        std::vector<std::thread> pool;
        pool.reserve(workers);
        for (unsigned w = 0; w < workers; ++w) {
            pool.emplace_back([&] {
                try {
                    for (;;) {
                        Job* job = nullptr;
                        {
                            std::unique_lock lk(mu_);
                            cv_.wait(lk, [&] { return stop_ || !work_.empty() || producer_done_; });
                            if (stop_ || work_.empty()) return;
                            job = work_.front();
                            work_.pop_front();
                        }
                        transform(*job);
                        std::lock_guard lk(mu_);
                        done_[job->seq] = job;
                        cv_.notify_all();
                    }
                } catch (...) {
                    set_error(std::current_exception());
                }
            });
        }

        // ── writer ──────────────────────────────────────────────────────
        std::thread writer;
        if (write) {
            writer = std::thread([&] {
                try {
                    for (;;) {
                        Job* job = nullptr;
                        {
                            std::unique_lock lk(mu_);
                            cv_.wait(lk, [&] { return stop_ || !write_q_.empty() || consumer_done_; });
                            if (stop_ || write_q_.empty()) return;
                            job = write_q_.front();
                            write_q_.pop_front();
                        }
                        write(*job);
                        release(job);
                    }
                } catch (...) {
                    set_error(std::current_exception());
                }
            });
        }

        // ── consumer (this thread) ──────────────────────────────────────
        try {
            for (std::uint64_t next = 0;; ++next) {
                Job* job = nullptr;
                {
                    std::unique_lock lk(mu_);
                    cv_.wait(lk, [&] {
                        return stop_ || done_.count(next) != 0 ||
                               (producer_done_ && next >= produced_);
                    });
                    if (stop_ || done_.count(next) == 0) break;
                    job = done_[next];
                    done_.erase(next);
                    job->pending = write ? 2 : 1;
                    if (write) {
                        write_q_.push_back(job);
                        cv_.notify_all();
                    }
                }
                if (cancelled()) throw_cancelled();
                const bool last = job->final;
                if (consume) consume(*job);
                release(job);
                if (last) break;
            }
        } catch (...) {
            set_error(std::current_exception());
        }

        {
            std::lock_guard lk(mu_);
            consumer_done_ = true;
            cv_.notify_all();
        }
        if (writer.joinable()) writer.join();  // drains the queue (or stops on error)
        {
            std::lock_guard lk(mu_);
            stop_ = true;
            cv_.notify_all();
        }
        reader.join();
        for (auto& t : pool) t.join();
        if (error_) std::rethrow_exception(error_);
    }

    const std::atomic_bool* cancel_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
    bool producer_done_ = false;
    bool consumer_done_ = false;
    std::uint64_t produced_ = 0;
    std::exception_ptr error_;
    std::vector<std::unique_ptr<Job>> storage_;
    std::deque<Job*> free_;
    std::deque<Job*> work_;
    std::deque<Job*> write_q_;
    std::map<std::uint64_t, Job*> done_;
};

}  // namespace encpto::detail
