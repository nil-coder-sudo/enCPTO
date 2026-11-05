#include "encpto/file.hpp"

#include "encpto/error.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace encpto {
namespace {

std::string describe(const std::filesystem::path& path, const char* what) {
    const int err = errno;
    std::string msg = std::string(what) + ": ";
    const auto u8 = path.u8string();
    msg.append(reinterpret_cast<const char*>(u8.data()), u8.size());
    if (err != 0) {
        msg += " (";
        msg += std::strerror(err);
        msg += ")";
    }
    return msg;
}

}  // namespace

File::File(const std::filesystem::path& path, Mode mode) : path_(path) {
#ifdef _WIN32
    const wchar_t* m = mode == Mode::Read ? L"rb" : mode == Mode::Write ? L"wb" : L"r+b";
    fp_ = _wfopen(path.c_str(), m);
#else
    const char* m = mode == Mode::Read ? "rb" : mode == Mode::Write ? "wb" : "r+b";
    fp_ = std::fopen(path.c_str(), m);
#endif
    if (fp_ == nullptr) {
        throw Error(ErrorCode::Io, describe(path, "Cannot open file"));
    }
    // Large stdio buffer: we mostly move 4 MiB blocks anyway.
    std::setvbuf(fp_, nullptr, _IOFBF, 1 << 20);
}

File::~File() {
    if (fp_ != nullptr) {
        std::fclose(fp_);
    }
}

File::File(File&& other) noexcept
    : fp_(std::exchange(other.fp_, nullptr)), path_(std::move(other.path_)) {}

File& File::operator=(File&& other) noexcept {
    if (this != &other) {
        if (fp_ != nullptr) {
            std::fclose(fp_);
        }
        fp_ = std::exchange(other.fp_, nullptr);
        path_ = std::move(other.path_);
    }
    return *this;
}

std::size_t File::read(void* buffer, std::size_t size) {
    auto* out = static_cast<unsigned char*>(buffer);
    std::size_t total = 0;
    while (total < size) {
        const std::size_t n = std::fread(out + total, 1, size - total, fp_);
        if (n == 0) {
            if (std::ferror(fp_) != 0) {
                throw Error(ErrorCode::Io, describe(path_, "Read error"));
            }
            break;  // EOF
        }
        total += n;
    }
    return total;
}

void File::read_exact(void* buffer, std::size_t size) {
    if (read(buffer, size) != size) {
        throw Error(ErrorCode::Corrupted, "Unexpected end of file — the container is truncated.");
    }
}

void File::write(const void* data, std::size_t size) {
    if (size != 0 && std::fwrite(data, 1, size, fp_) != size) {
        throw Error(ErrorCode::Io, describe(path_, "Write error (disk full?)"));
    }
}

void File::seek(std::uint64_t offset) {
#ifdef _WIN32
    const int rc = _fseeki64(fp_, static_cast<__int64>(offset), SEEK_SET);
#else
    const int rc = fseeko(fp_, static_cast<off_t>(offset), SEEK_SET);
#endif
    if (rc != 0) {
        throw Error(ErrorCode::Io, describe(path_, "Seek error"));
    }
}

std::uint64_t File::size() {
    std::fflush(fp_);
#ifdef _WIN32
    const __int64 n = _filelengthi64(_fileno(fp_));
#else
    const off_t cur = ftello(fp_);
    fseeko(fp_, 0, SEEK_END);
    const off_t n = ftello(fp_);
    fseeko(fp_, cur, SEEK_SET);
#endif
    if (n < 0) {
        throw Error(ErrorCode::Io, describe(path_, "Cannot determine file size"));
    }
    return static_cast<std::uint64_t>(n);
}

void File::truncate(std::uint64_t size) {
    std::fflush(fp_);
#ifdef _WIN32
    const int rc = _chsize_s(_fileno(fp_), static_cast<__int64>(size));
#else
    const int rc = ftruncate(fileno(fp_), static_cast<off_t>(size));
#endif
    if (rc != 0) {
        throw Error(ErrorCode::Io, describe(path_, "Cannot truncate file"));
    }
}

void File::sync() {
    if (std::fflush(fp_) != 0) {
        throw Error(ErrorCode::Io, describe(path_, "Write error (disk full?)"));
    }
#ifdef _WIN32
    _commit(_fileno(fp_));
#else
    fsync(fileno(fp_));
#endif
}

void File::close() {
    if (fp_ != nullptr) {
        const int rc = std::fclose(fp_);
        fp_ = nullptr;
        if (rc != 0) {
            throw Error(ErrorCode::Io, describe(path_, "Error closing file"));
        }
    }
}

}  // namespace encpto
