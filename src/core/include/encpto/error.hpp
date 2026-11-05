#pragma once

#include <stdexcept>
#include <string>

namespace encpto {

enum class ErrorCode {
    WrongPassword,      // metadata authentication failed
    Tampered,           // password OK, but HMAC / chunk authentication failed
    Corrupted,          // truncated or structurally invalid container
    UnsupportedFormat,  // not a V7 container (legacy V1–V6 or not enCPTO at all)
    Io,                 // file system error
    Cancelled,          // user pressed "cancel"
    InvalidArgument,
    Internal,
};

class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    [[nodiscard]] ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

}  // namespace encpto
