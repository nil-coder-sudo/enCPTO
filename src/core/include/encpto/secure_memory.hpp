#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace encpto {

/// Overwrites memory in a way the optimiser cannot remove (sodium_memzero).
void secure_zero(void* data, std::size_t size) noexcept;

/// Fixed-size buffer for key material.
///
/// Backed by sodium_malloc(): guard pages on both sides, mlock()ed so it is
/// never swapped to disk, and wiped automatically when destroyed.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t size);
    ~SecureBytes();

    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    [[nodiscard]] std::uint8_t* data() noexcept { return data_; }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }

    [[nodiscard]] std::span<std::uint8_t> span() noexcept { return {data_, size_}; }
    [[nodiscard]] std::span<const std::uint8_t> span() const noexcept { return {data_, size_}; }
    [[nodiscard]] std::span<const std::uint8_t> sub(std::size_t offset, std::size_t count) const {
        return span().subspan(offset, count);
    }

private:
    void release() noexcept;

    std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

}  // namespace encpto
