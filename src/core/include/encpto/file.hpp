#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>

namespace encpto {

/// Minimal binary file wrapper: Unicode paths on every platform, 64-bit
/// offsets, and a real fsync() — none of which std::fstream guarantees.
class File {
public:
    enum class Mode {
        Read,       // existing file, read-only
        Write,      // create or truncate, write-only
        ReadWrite,  // existing file, read + write (used by the shredder)
    };

    File() = default;
    File(const std::filesystem::path& path, Mode mode);
    ~File();

    File(File&& other) noexcept;
    File& operator=(File&& other) noexcept;
    File(const File&) = delete;
    File& operator=(const File&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return fp_ != nullptr; }

    /// Reads up to `size` bytes; returns fewer only at end of file.
    std::size_t read(void* buffer, std::size_t size);
    /// Reads exactly `size` bytes or throws (ErrorCode::Corrupted).
    void read_exact(void* buffer, std::size_t size);
    void write(const void* data, std::size_t size);
    void seek(std::uint64_t offset);
    [[nodiscard]] std::uint64_t size();
    void truncate(std::uint64_t size);
    /// Flushes user-space buffers and asks the OS to persist the data.
    void sync();
    void close();

private:
    std::FILE* fp_ = nullptr;
    std::filesystem::path path_;
};

}  // namespace encpto
