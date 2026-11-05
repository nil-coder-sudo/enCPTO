#include "encpto/password.hpp"

#include "encpto/crypto.hpp"
#include "encpto/error.hpp"

#include <algorithm>
#include <cmath>
#include <vector>

namespace encpto::password {
namespace {

constexpr std::string_view kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view kLower = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view kDigits = "0123456789";
// string.punctuation without backslash and backtick (as in v7)
constexpr std::string_view kSymbols = "!\"#$%&'()*+,-./:;<=>?@[]^_{|}~";
constexpr std::string_view kAmbiguous = "0O1lI";

std::string filtered(std::string_view set, bool avoid) {
    std::string out;
    for (const char c : set) {
        if (!avoid || kAmbiguous.find(c) == std::string_view::npos) {
            out.push_back(c);
        }
    }
    return out;
}

char pick(const std::string& pool) {
    return pool[crypto::random_below(static_cast<std::uint32_t>(pool.size()))];
}

}  // namespace

std::string generate(const GeneratorOptions& o) {
    std::vector<std::string> pools;
    if (o.upper) pools.push_back(filtered(kUpper, o.avoid_ambiguous));
    if (o.lower) pools.push_back(filtered(kLower, o.avoid_ambiguous));
    if (o.digits) pools.push_back(filtered(kDigits, o.avoid_ambiguous));
    if (o.symbols) pools.push_back(filtered(kSymbols, o.avoid_ambiguous));
    std::erase_if(pools, [](const std::string& p) { return p.empty(); });
    if (pools.empty()) {
        throw Error(ErrorCode::InvalidArgument, "At least one character set must be selected.");
    }
    const int min_len = std::max<int>(8, static_cast<int>(pools.size()));
    if (o.length < min_len || o.length > 4096) {
        throw Error(ErrorCode::InvalidArgument,
                    "Length must be between " + std::to_string(min_len) + " and 4096.");
    }
    std::string all;
    for (const auto& p : pools) all += p;

    std::string out;
    out.reserve(static_cast<std::size_t>(o.length));
    for (const auto& p : pools) out.push_back(pick(p));  // one of each set
    while (out.size() < static_cast<std::size_t>(o.length)) out.push_back(pick(all));
    // Fisher–Yates shuffle with a CSPRNG
    for (std::size_t i = out.size() - 1; i > 0; --i) {
        const auto j = crypto::random_below(static_cast<std::uint32_t>(i + 1));
        std::swap(out[i], out[j]);
    }
    return out;
}

Assessment assess(std::string_view pwd) {
    Assessment a;
    if (pwd.empty()) {
        return a;
    }
    bool lo = false, up = false, di = false, sy = false;
    std::size_t chars = 0;
    for (std::size_t i = 0; i < pwd.size(); ++i) {
        const auto c = static_cast<unsigned char>(pwd[i]);
        if ((c & 0xC0) != 0x80) ++chars;  // count code points, not bytes
        if (c >= 'a' && c <= 'z') lo = true;
        else if (c >= 'A' && c <= 'Z') up = true;
        else if (c >= '0' && c <= '9') di = true;
        else sy = true;
    }
    a.classes = int{lo} + int{up} + int{di} + int{sy};
    const double pool = (lo ? 26 : 0) + (up ? 26 : 0) + (di ? 10 : 0) + (sy ? 33 : 0);
    a.entropy_bits = static_cast<double>(chars) * std::log2(std::max(pool, 2.0));
    // Policy uses the same length measure as the Python tool (characters).
    if (chars < 8) a.strength = Strength::TooShort;
    else if (a.classes < 3) a.strength = Strength::Weak;
    else if (a.entropy_bits < 60) a.strength = Strength::Fair;
    else if (a.entropy_bits < 80) a.strength = Strength::Good;
    else a.strength = Strength::Excellent;
    return a;
}

}  // namespace encpto::password
