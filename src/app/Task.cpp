#include "Task.hpp"

#include <encpto/error.hpp>

Task::Task(Body body, unsigned threads, QObject* parent)
    : QThread(parent), body_(std::move(body)), threads_(threads) {}

void Task::onProgress(const encpto::Progress& p) {
    std::lock_guard lk(mu_);
    const int phase = static_cast<int>(p.phase);
    const bool changed = phase != lastPhase_;
    if (changed) {
        lastPhase_ = phase;
        phaseTimer_.start();
    }
    const bool finished = p.done >= p.total;
    if (!changed && !finished && emitTimer_.isValid() && emitTimer_.elapsed() < 50) {
        return;  // at most ~20 UI updates per second
    }
    emitTimer_.start();
    const double fraction = p.total == 0 ? 1.0 : static_cast<double>(p.done) / static_cast<double>(p.total);
    const double secs = static_cast<double>(phaseTimer_.nsecsElapsed()) / 1e9;
    const bool byteBased = p.phase != encpto::Phase::DerivingKey && p.total > 1;
    const double rate = (byteBased && secs > 0.15) ? static_cast<double>(p.done) / secs : -1.0;
    emit progress(phase, fraction, rate);
}

void Task::run() {
    encpto::Options opts;
    opts.threads = threads_;
    opts.cancel = &cancel_;
    opts.on_progress = [this](const encpto::Progress& p) { onProgress(p); };
    QElapsedTimer total;
    total.start();
    try {
        const Result r = body_(opts);
        emit succeeded(r.path, r.isDirectory, static_cast<double>(total.nsecsElapsed()) / 1e9);
    } catch (const encpto::Error& e) {
        emit failed(static_cast<int>(e.code()), QString::fromUtf8(e.what()));
    } catch (const std::exception& e) {
        emit failed(static_cast<int>(encpto::ErrorCode::Internal), QString::fromUtf8(e.what()));
    }
}
