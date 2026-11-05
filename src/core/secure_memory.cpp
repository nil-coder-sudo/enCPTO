#include "encpto/secure_memory.hpp"

#include "encpto/crypto.hpp"

#include <new>
#include <utility>

#include <sodium.h>

namespace encpto {

void secure_zero(void* data, std::size_t size) noexcept {
    if (data != nullptr && size != 0) {
        sodium_memzero(data, size);
    }
}

SecureBytes::SecureBytes(std::size_t size) : size_(size) {
    crypto::init();
    if (size_ == 0) {
        return;
    }
    data_ = static_cast<std::uint8_t*>(sodium_malloc(size_));
    if (data_ == nullptr) {
        throw std::bad_alloc();
    }
    sodium_memzero(data_, size_);
}

SecureBytes::~SecureBytes() { release(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
        release();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

void SecureBytes::release() noexcept {
    if (data_ != nullptr) {
        sodium_free(data_);  // wipes before unmapping
        data_ = nullptr;
        size_ = 0;
    }
}

}  // namespace encpto
