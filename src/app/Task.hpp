#pragma once

#include <encpto/progress.hpp>

#include <QElapsedTimer>
#include <QString>
#include <QThread>

#include <atomic>
#include <functional>
#include <mutex>

/// Runs one engine operation off the UI thread.
class Task : public QThread {
    Q_OBJECT
public:
    struct Result {
        QString path;
        bool isDirectory = false;
    };
    using Body = std::function<Result(const encpto::Options&)>;

    Task(Body body, unsigned threads, QObject* parent = nullptr);

    void cancel() { cancel_ = true; }

signals:
    /// fraction in [0, 1]; bytesPerSecond < 0 when not meaningful
    void progress(int phase, double fraction, double bytesPerSecond);
    void succeeded(const QString& path, bool isDirectory, double seconds);
    void failed(int errorCode, const QString& message);

protected:
    void run() override;

private:
    void onProgress(const encpto::Progress& p);

    Body body_;
    unsigned threads_;
    std::atomic_bool cancel_{false};

    std::mutex mu_;
    int lastPhase_ = -1;
    QElapsedTimer phaseTimer_;
    QElapsedTimer emitTimer_;
};
