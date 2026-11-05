#include "encpto/format.hpp"

#include "encpto/error.hpp"

#include <algorithm>
#include <cstring>

namespace encpto::v7 {
namespace {

void put_be32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) {
        p[i] = static_cast<std::uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

void put_be64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<std::uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

std::uint32_t get_be32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
           (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}

std::uint64_t get_be64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

}  // namespace

HeaderBytes Header::serialize() const {
    HeaderBytes out{};
    std::uint8_t* p = out.data();
    std::memcpy(p, kMagic.data(), kMagic.size());
    p += 8;
    *p++ = kKdfArgon2id;
    put_be32(p, kdf.time_cost);
    p += 4;
    put_be32(p, kdf.memory_kib);
    p += 4;
    *p++ = kdf.parallelism;
    std::memcpy(p, salt.data(), salt.size());
    p += salt.size();
    std::memcpy(p, aes_prefix.data(), aes_prefix.size());
    p += aes_prefix.size();
    std::memcpy(p, xcc_prefix.data(), xcc_prefix.size());
    return out;
}

Header Header::parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kHeaderSize) {
        throw Error(ErrorCode::Corrupted, "File too short — corrupted V7 container.");
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
        throw Error(ErrorCode::UnsupportedFormat, "Not a V7 container.");
    }
    const std::uint8_t* p = bytes.data() + 8;
    if (*p != kKdfArgon2id) {
        throw Error(ErrorCode::UnsupportedFormat, "Unsupported KDF id in V7 header.");
    }
    ++p;
    Header h;
    h.kdf.time_cost = get_be32(p);
    p += 4;
    h.kdf.memory_kib = get_be32(p);
    p += 4;
    h.kdf.parallelism = *p++;
    const auto& k = h.kdf;
    if (!(k.time_cost >= 1 && k.time_cost <= kLimitTime && k.parallelism >= 1 &&
          k.parallelism <= kLimitPar && k.memory_kib >= kMinMemKib &&
          k.memory_kib <= kLimitMemKib && k.memory_kib >= 8U * k.parallelism)) {
        throw Error(ErrorCode::Corrupted,
                    "Invalid Argon2id parameters in V7 header — file corrupted or tampered.");
    }
    std::memcpy(h.salt.data(), p, kSaltLen);
    p += kSaltLen;
    std::memcpy(h.aes_prefix.data(), p, kAesPrefixLen);
    p += kAesPrefixLen;
    std::memcpy(h.xcc_prefix.data(), p, kXccPrefixLen);
    return h;
}

std::string truncate_utf8(const std::string& s, std::size_t max_bytes) {
    if (s.size() <= max_bytes) {
        return s;
    }
    std::size_t cut = max_bytes;
    // Back off while the byte at `cut` is a continuation byte (10xxxxxx):
    // the code point it belongs to would be split.
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) {
        --cut;
    }
    return s.substr(0, cut);
}

std::array<std::uint8_t, kMetaPlain> Meta::pack() const {
    const std::string n = truncate_utf8(name, kMaxNameBytes);
    std::array<std::uint8_t, kMetaPlain> out{};
    out[0] = 1;  // meta version
    out[1] = flags;
    out[2] = static_cast<std::uint8_t>(n.size() >> 8);
    out[3] = static_cast<std::uint8_t>(n.size() & 0xFF);
    std::memcpy(out.data() + 4, n.data(), n.size());
    put_be64(out.data() + 4 + n.size(), size);
    return out;  // zero padded to a fixed size: hides the name length
}

Meta Meta::unpack(std::span<const std::uint8_t> plain) {
    if (plain.size() < kMetaPlain) {
        throw Error(ErrorCode::Corrupted, "Unsupported V7 metadata.");
    }
    const std::size_t name_len = (std::size_t{plain[2]} << 8) | plain[3];
    if (plain[0] != 1 || (plain[1] != kFlagFile && plain[1] != kFlagZip) ||
        name_len > kMaxNameBytes) {
        throw Error(ErrorCode::Corrupted, "Unsupported V7 metadata.");
    }
    Meta m;
    m.flags = plain[1];
    m.name.assign(reinterpret_cast<const char*>(plain.data() + 4), name_len);
    m.size = get_be64(plain.data() + 4 + name_len);
    return m;
}

std::array<std::uint8_t, 24> xcc_nonce(const std::array<std::uint8_t, kXccPrefixLen>& prefix,
                                       std::uint64_t index) {
    std::array<std::uint8_t, 24> n{};
    std::memcpy(n.data(), prefix.data(), prefix.size());
    put_be64(n.data() + 16, index);
    return n;
}

std::array<std::uint8_t, 16> aes_iv(const std::array<std::uint8_t, kAesPrefixLen>& prefix,
                                    std::uint32_t index) {
    std::array<std::uint8_t, 16> iv{};
    std::memcpy(iv.data(), prefix.data(), prefix.size());
    put_be32(iv.data() + 8, index);
    return iv;  // last 4 bytes: block counter = 0
}

std::array<std::uint8_t, 73> chunk_aad(const std::array<std::uint8_t, 64>& header_hash,
                                       std::uint64_t index, bool final) {
    std::array<std::uint8_t, 73> aad{};
    std::memcpy(aad.data(), header_hash.data(), 64);
    put_be64(aad.data() + 64, index);
    aad[72] = final ? 1 : 0;
    return aad;
}

std::array<std::uint8_t, 68> meta_aad(const std::array<std::uint8_t, 64>& header_hash) {
    std::array<std::uint8_t, 68> aad{};
    std::memcpy(aad.data(), header_hash.data(), 64);
    std::memcpy(aad.data() + 64, "meta", 4);
    return aad;
}

std::uint64_t chunk_count(std::uint64_t payload_size) {
    return payload_size == 0 ? 1 : (payload_size + kChunkSize - 1) / kChunkSize;
}

}  // namespace encpto::v7
