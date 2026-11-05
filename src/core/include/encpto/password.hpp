#pragma once

#include <string>
#include <string_view>

namespace encpto::password {

struct GeneratorOptions {
    int length = 20;
    bool upper = true;
    bool lower = true;
    bool digits = true;
    bool symbols = true;
    bool avoid_ambiguous = false;  // 0 O 1 l I
};

/// Cryptographically secure password with at least one character from every
/// selected set. Throws Error(InvalidArgument) for impossible options.
std::string generate(const GeneratorOptions& opts);

enum class Strength {
    Empty,
    TooShort,   // < 8 characters
    Weak,       // fewer than 3 of {lower, upper, digit, symbol}
    Fair,       // meets the policy, < 60 bits of estimated entropy
    Good,       // < 80 bits
    Excellent,  // ≥ 80 bits
};

struct Assessment {
    Strength strength = Strength::Empty;
    int classes = 0;
    double entropy_bits = 0;
    [[nodiscard]] bool acceptable() const { return strength >= Strength::Fair; }
};

/// Policy (unchanged from v7): length ≥ 8 and ≥ 3 character classes.
Assessment assess(std::string_view pwd);

}  // namespace encpto::password
