#include "encpto/fsutil.hpp"

#include "encpto/crypto.hpp"

#include <array>
#include <cstdio>
#include <vector>

namespace fs = std::filesystem;

namespace encpto::fsutil {

fs::path from_utf8(const std::string& s) {
    return fs::path(std::u8string(reinterpret_cast<const char8_t*>(s.data()), s.size()));
}

std::string to_utf8(const fs::path& p) {
    const std::u8string u = p.u8string();
    return {reinterpret_cast<const char*>(u.data()), u.size()};
}

std::string safe_output_name(const std::string& name, const std::string& fallback) {
    // Keep only the last path component (accept both separators).
    std::string base = name;
    for (char& c : base) {
        if (c == '\\') {
            c = '/';
        }
    }
    if (const auto slash = base.rfind('/'); slash != std::string::npos) {
        base = base.substr(slash + 1);
    }
    std::string out;
    out.reserve(base.size());
    for (const char c : base) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) {
            continue;
        }
        if (c == '<' || c == '>' || c == ':' || c == '"' || c == '|' || c == '?' || c == '*') {
            continue;
        }
        out.push_back(c);
    }
    // Strip surrounding whitespace, then dots (matches the Python tool).
    const auto trim = [](std::string& s, const char* chars) {
        const auto b = s.find_first_not_of(chars);
        if (b == std::string::npos) {
            s.clear();
            return;
        }
        s = s.substr(b, s.find_last_not_of(chars) - b + 1);
    };
    trim(out, " \t\r\n\v\f");
    trim(out, ".");
    return out.empty() ? fallback : out;
}

fs::path unique_path(const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        return path;
    }
    const bool is_dir = fs::is_directory(path, ec);
    const fs::path parent = path.parent_path();
    const std::string stem = to_utf8(is_dir ? path.filename() : path.stem());
    const std::string ext = is_dir ? std::string() : to_utf8(path.extension());
    for (unsigned i = 1;; ++i) {
        fs::path candidate = parent / from_utf8(stem + " (" + std::to_string(i) + ")" + ext);
        if (!fs::exists(candidate, ec)) {
            return candidate;
        }
    }
}

std::string human_size(std::uint64_t bytes) {
    static constexpr std::array<const char*, 6> units = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = static_cast<double>(bytes);
    std::size_t u = 0;
    while (v >= 1024.0 && u + 1 < units.size()) {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
    return buf;
}

DirStats scan_directory(const fs::path& dir) {
    DirStats st;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code e2;
        if (it->is_regular_file(e2)) {
            ++st.files;
            st.bytes += it->file_size(e2);
        }
    }
    return st;
}

std::string random_hex(std::size_t bytes) {
    std::vector<std::uint8_t> raw(bytes);
    crypto::random_bytes(raw);
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (const auto b : raw) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

}  // namespace encpto::fsutil
