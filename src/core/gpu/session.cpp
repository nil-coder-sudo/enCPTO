#include "session.hpp"

#include "encpto/error.hpp"
#include "encpto/gpu.hpp"
#include "encpto/secure_memory.hpp"
#include "opencl_api.hpp"

#include <algorithm>
#include <cstring>
#include <map>

namespace encpto::gpu {
namespace {

// ── Kernel ───────────────────────────────────────────────────────────────
// One work-item = one 64-byte segment = 1 ChaCha20 block + 4 AES blocks.
// Lookup tables come from the host (in the same buffer as the keys) and are
// copied to local memory once per work-group.
constexpr const char* kKernelSource = R"CLC(
#define ROTL(x, n) rotate((uint)(x), (uint)(n))
#define ROTR(x, n) rotate((uint)(x), (uint)(32 - (n)))
#define BSWAP(x) as_uint(as_uchar4(x).s3210)

#define QR(a, b, c, d)                    \
    a += b; d ^= a; d = ROTL(d, 16);      \
    c += d; b ^= c; b = ROTL(b, 12);      \
    a += b; d ^= a; d = ROTL(d, 8);       \
    c += d; b ^= c; b = ROTL(b, 7);

#define AES_ROUND(T, a, b, c, d, k) \
    (T[(a) >> 24] ^ ROTR(T[((b) >> 16) & 255u], 8) ^ ROTR(T[((c) >> 8) & 255u], 16) ^ ROTR(T[(d) & 255u], 24) ^ (k))
#define AES_FINAL(S, a, b, c, d, k) \
    ((S[(a) >> 24] << 24) ^ (S[((b) >> 16) & 255u] << 16) ^ (S[((c) >> 8) & 255u] << 8) ^ S[(d) & 255u] ^ (k))

__kernel void encpto_xor(__global uint* data, const uint nseg, __constant uint* keys,
                         const uint pre0, const uint pre1, const uint chunk,
                         const uint n13, const uint n14, const uint n15)
{
    __local uint T[256];
    __local uint S[256];
    for (uint i = get_local_id(0); i < 256u; i += get_local_size(0)) {
        T[i] = keys[i];
        S[i] = keys[256u + i];
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    const uint seg = get_global_id(0);
    if (seg >= nseg) return;
    __constant uint* rk = keys + 512;   // 60 AES-256 round-key words
    __constant uint* ck = keys + 572;   // 8 ChaCha20 key words

    // ChaCha20 block: counter = 1 + segment (block 0 is the Poly1305 key)
    uint j0 = 0x61707865u, j1 = 0x3320646eu, j2 = 0x79622d32u, j3 = 0x6b206574u;
    uint j4 = ck[0], j5 = ck[1], j6 = ck[2], j7 = ck[3];
    uint j8 = ck[4], j9 = ck[5], j10 = ck[6], j11 = ck[7];
    uint j12 = 1u + seg, j13 = n13, j14 = n14, j15 = n15;
    uint x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7;
    uint x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15;
    for (int r = 0; r < 10; ++r) {
        QR(x0, x4, x8, x12) QR(x1, x5, x9, x13) QR(x2, x6, x10, x14) QR(x3, x7, x11, x15)
        QR(x0, x5, x10, x15) QR(x1, x6, x11, x12) QR(x2, x7, x8, x13) QR(x3, x4, x9, x14)
    }
    uint ks[16] = {x0 + j0, x1 + j1, x2 + j2, x3 + j3, x4 + j4, x5 + j5, x6 + j6, x7 + j7,
                   x8 + j8, x9 + j9, x10 + j10, x11 + j11, x12 + j12, x13 + j13, x14 + j14, x15 + j15};

    __global uint* p = data + (size_t)seg * 16u;
    for (uint b = 0; b < 4u; ++b) {
        // AES-256-CTR: counter block = prefix(8) ‖ chunk index(4) ‖ block number(4)
        uint s0 = pre0 ^ rk[0], s1 = pre1 ^ rk[1], s2 = chunk ^ rk[2], s3 = (seg * 4u + b) ^ rk[3];
        for (int r = 1; r < 14; ++r) {
            const uint t0 = AES_ROUND(T, s0, s1, s2, s3, rk[4 * r + 0]);
            const uint t1 = AES_ROUND(T, s1, s2, s3, s0, rk[4 * r + 1]);
            const uint t2 = AES_ROUND(T, s2, s3, s0, s1, rk[4 * r + 2]);
            const uint t3 = AES_ROUND(T, s3, s0, s1, s2, rk[4 * r + 3]);
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }
        const uint o0 = AES_FINAL(S, s0, s1, s2, s3, rk[56]);
        const uint o1 = AES_FINAL(S, s1, s2, s3, s0, rk[57]);
        const uint o2 = AES_FINAL(S, s2, s3, s0, s1, rk[58]);
        const uint o3 = AES_FINAL(S, s3, s0, s1, s2, rk[59]);
        p[4u * b + 0u] ^= ks[4u * b + 0u] ^ BSWAP(o0);
        p[4u * b + 1u] ^= ks[4u * b + 1u] ^ BSWAP(o1);
        p[4u * b + 2u] ^= ks[4u * b + 2u] ^ BSWAP(o2);
        p[4u * b + 3u] ^= ks[4u * b + 3u] ^ BSWAP(o3);
    }
}
)CLC";

constexpr std::size_t kLocalSize = 64;
constexpr std::size_t kKeyWords = 256 + 256 + 60 + 8;

// ── AES tables ──────────────────────────────────────────────────────────

struct AesTables {
    std::array<std::uint8_t, 256> sbox{};
    std::array<std::uint32_t, 256> te0{};
};

const AesTables& tables() {
    static const AesTables t = [] {
        AesTables r;
        const auto rotl8 = [](std::uint8_t x, int s) {
            return static_cast<std::uint8_t>((x << s) | (x >> (8 - s)));
        };
        // S-box from the multiplicative inverse (p·q = 1 in GF(2^8)) + affine map
        std::uint8_t p = 1, q = 1;
        do {
            p = static_cast<std::uint8_t>(p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0));
            q ^= static_cast<std::uint8_t>(q << 1);
            q ^= static_cast<std::uint8_t>(q << 2);
            q ^= static_cast<std::uint8_t>(q << 4);
            if (q & 0x80) q ^= 0x09;
            const std::uint8_t x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
            r.sbox[p] = static_cast<std::uint8_t>(x ^ 0x63);
        } while (p != 1);
        r.sbox[0] = 0x63;
        for (int i = 0; i < 256; ++i) {
            const std::uint32_t s = r.sbox[static_cast<std::size_t>(i)];
            const std::uint32_t s2 = ((s << 1) ^ ((s & 0x80) ? 0x1B : 0)) & 0xFF;
            const std::uint32_t s3 = s2 ^ s;
            r.te0[static_cast<std::size_t>(i)] = (s2 << 24) | (s << 16) | (s << 8) | s3;
        }
        return r;
    }();
    return t;
}

std::uint32_t be32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}
std::uint32_t le32(const std::uint8_t* p) {
    return std::uint32_t{p[0]} | (std::uint32_t{p[1]} << 8) | (std::uint32_t{p[2]} << 16) | (std::uint32_t{p[3]} << 24);
}

// ── Device registry ─────────────────────────────────────────────────────

struct DeviceHandle {
    cl_platform_id platform = nullptr;
    cl_device_id device = nullptr;
};

struct Registry {
    Status status;
    std::vector<DeviceHandle> handles;
};

std::string info_string(cl_device_id d, cl_device_info what) {
    std::size_t n = 0;
    if (cl::api().clGetDeviceInfo(d, what, 0, nullptr, &n) != CL_SUCCESS || n == 0) return {};
    std::string s(n, '\0');
    cl::api().clGetDeviceInfo(d, what, n, s.data(), nullptr);
    while (!s.empty() && (s.back() == '\0' || s.back() == ' ')) s.pop_back();
    return s;
}

Registry& registry() {
    static Registry reg;
    static std::once_flag once;
    std::call_once(once, [] {
        const auto& api = cl::api();
        if (!api.loaded) {
            reg.status.message = api.error;
            return;
        }
        reg.status.runtime_found = true;
        cl_uint np = 0;
        if (api.clGetPlatformIDs(0, nullptr, &np) != CL_SUCCESS || np == 0) {
            reg.status.message = "An OpenCL runtime is installed, but it reports no platforms.";
            return;
        }
        std::vector<cl_platform_id> platforms(np);
        api.clGetPlatformIDs(np, platforms.data(), nullptr);
        for (cl_platform_id pf : platforms) {
            char pname[256] = {};
            api.clGetPlatformInfo(pf, CL_PLATFORM_NAME, sizeof pname - 1, pname, nullptr);
            cl_uint nd = 0;
            if (api.clGetDeviceIDs(pf, CL_DEVICE_TYPE_ALL, 0, nullptr, &nd) != CL_SUCCESS || nd == 0) continue;
            std::vector<cl_device_id> devs(nd);
            api.clGetDeviceIDs(pf, CL_DEVICE_TYPE_ALL, nd, devs.data(), nullptr);
            for (cl_device_id d : devs) {
                cl_bool little = CL_FALSE, avail = CL_FALSE, compiler = CL_FALSE;
                api.clGetDeviceInfo(d, CL_DEVICE_ENDIAN_LITTLE, sizeof little, &little, nullptr);
                api.clGetDeviceInfo(d, CL_DEVICE_AVAILABLE, sizeof avail, &avail, nullptr);
                api.clGetDeviceInfo(d, CL_DEVICE_COMPILER_AVAILABLE, sizeof compiler, &compiler, nullptr);
                if (!little || !avail || !compiler) continue;
                Device info;
                info.index = static_cast<int>(reg.status.devices.size());
                info.name = info_string(d, CL_DEVICE_NAME);
                info.vendor = info_string(d, CL_DEVICE_VENDOR);
                info.platform = pname;
                cl_device_type type = 0;
                api.clGetDeviceInfo(d, CL_DEVICE_TYPE, sizeof type, &type, nullptr);
                info.is_gpu = (type & CL_DEVICE_TYPE_GPU) != 0;
                cl_ulong mem = 0;
                api.clGetDeviceInfo(d, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof mem, &mem, nullptr);
                info.memory = mem;
                cl_uint cu = 0;
                api.clGetDeviceInfo(d, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof cu, &cu, nullptr);
                info.compute_units = cu;
                reg.status.devices.push_back(info);
                reg.handles.push_back({pf, d});
            }
        }
        if (reg.status.devices.empty()) {
            reg.status.message = "OpenCL is installed, but no usable device was found.";
        }
    });
    return reg;
}

/// Context + compiled program per device, built on first use and kept.
struct Compiled {
    cl_context context = nullptr;
    cl_program program = nullptr;
};

Compiled& compiled(int index) {
    static std::mutex mu;
    static std::map<int, Compiled> cache;
    std::lock_guard lk(mu);
    auto it = cache.find(index);
    if (it != cache.end()) return it->second;

    const auto& api = cl::api();
    auto& reg = registry();
    if (index < 0 || index >= static_cast<int>(reg.handles.size())) {
        throw Error(ErrorCode::Gpu, reg.status.message.empty() ? "GPU device not found." : reg.status.message);
    }
    const auto& h = reg.handles[static_cast<std::size_t>(index)];
    cl_int err = CL_SUCCESS;
    const cl_context_properties props[] = {CL_CONTEXT_PLATFORM,
                                           reinterpret_cast<cl_context_properties>(h.platform), 0};
    Compiled c;
    c.context = api.clCreateContext(props, 1, &h.device, nullptr, nullptr, &err);
    cl::check(err, "creating a context");
    const char* src = kKernelSource;
    c.program = api.clCreateProgramWithSource(c.context, 1, &src, nullptr, &err);
    cl::check(err, "loading the kernel");
    err = api.clBuildProgram(c.program, 1, &h.device, "-cl-std=CL1.2", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        std::size_t n = 0;
        api.clGetProgramBuildInfo(c.program, h.device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &n);
        std::string log(n, '\0');
        api.clGetProgramBuildInfo(c.program, h.device, CL_PROGRAM_BUILD_LOG, n, log.data(), nullptr);
        api.clReleaseProgram(c.program);
        api.clReleaseContext(c.context);
        throw Error(ErrorCode::Gpu, "GPU kernel failed to compile: " + log.substr(0, 600));
    }
    return cache.emplace(index, c).first->second;
}

}  // namespace

// ── Public ──────────────────────────────────────────────────────────────

const Status& probe() { return registry().status; }

int default_device() {
    const auto& devs = probe().devices;
    for (const auto& d : devs) {
        if (d.is_gpu) return d.index;
    }
    return devs.empty() ? -1 : devs.front().index;
}

namespace detail {

std::array<std::uint32_t, 60> aes256_expand_key(crypto::Bytes key) {
    if (key.size() != 32) throw Error(ErrorCode::InvalidArgument, "AES-256 key must be 32 bytes");
    const auto& sb = tables().sbox;
    const auto sub = [&](std::uint32_t w) {
        return (std::uint32_t{sb[w >> 24]} << 24) | (std::uint32_t{sb[(w >> 16) & 255]} << 16) |
               (std::uint32_t{sb[(w >> 8) & 255]} << 8) | sb[w & 255];
    };
    std::array<std::uint32_t, 60> w{};
    for (int i = 0; i < 8; ++i) w[static_cast<std::size_t>(i)] = be32(key.data() + 4 * i);
    std::uint32_t rcon = 0x01000000;
    for (std::size_t i = 8; i < 60; ++i) {
        std::uint32_t t = w[i - 1];
        if (i % 8 == 0) {
            t = sub((t << 8) | (t >> 24)) ^ rcon;
            rcon = ((rcon << 1) ^ ((rcon & 0x80000000U) ? 0x1B000000U : 0)) & 0xFF000000U;
        } else if (i % 8 == 4) {
            t = sub(t);
        }
        w[i] = w[i - 8] ^ t;
    }
    return w;
}

struct Session::Lane {
    cl_command_queue queue = nullptr;
    cl_kernel kernel = nullptr;
    cl_mem buffer = nullptr;
};

Session::Session(int device_index, crypto::Bytes k_aes, crypto::Bytes k_xcc,
                 const std::array<std::uint8_t, v7::kAesPrefixLen>& aes_prefix,
                 const std::array<std::uint8_t, v7::kXccPrefixLen>& xcc_prefix, unsigned lanes) {
    const auto& api = cl::api();
    if (!api.loaded) throw Error(ErrorCode::Gpu, api.error);
    const int index = device_index >= 0 ? device_index : default_device();
    if (index < 0) throw Error(ErrorCode::Gpu, probe().message);
    Compiled& c = compiled(index);
    context_ = c.context;
    const cl_device_id device = registry().handles[static_cast<std::size_t>(index)].device;

    subkey_ = crypto::hchacha20(k_xcc, crypto::Bytes(xcc_prefix.data(), 16));
    aes_prefix_words_ = {be32(aes_prefix.data()), be32(aes_prefix.data() + 4)};

    // Te0 ‖ S-box ‖ round keys ‖ ChaCha key — wiped by the destructor.
    SecureBytes host(kKeyWords * sizeof(std::uint32_t));
    auto* words = reinterpret_cast<std::uint32_t*>(host.data());
    const auto& t = tables();
    for (std::size_t i = 0; i < 256; ++i) {
        words[i] = t.te0[i];
        words[256 + i] = t.sbox[i];
    }
    auto rk = aes256_expand_key(k_aes);
    std::copy(rk.begin(), rk.end(), words + 512);
    secure_zero(rk.data(), sizeof rk);
    for (int i = 0; i < 8; ++i) words[572 + i] = le32(subkey_.data() + 4 * i);

    cl_int err = CL_SUCCESS;
    try {
        keys_ = api.clCreateBuffer(c.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, host.size(),
                                   host.data(), &err);
        cl::check(err, "uploading keys");
        for (unsigned i = 0; i < std::max(1U, lanes); ++i) {
            auto lane = std::make_unique<Lane>();
            lane->queue = api.clCreateCommandQueue(c.context, device, 0, &err);
            cl::check(err, "creating a command queue");
            lane->kernel = api.clCreateKernel(c.program, "encpto_xor", &err);
            cl::check(err, "creating the kernel");
            lane->buffer = api.clCreateBuffer(c.context, CL_MEM_READ_WRITE, v7::kChunkSize, nullptr, &err);
            cl::check(err, "allocating device memory");
            cl_mem k = static_cast<cl_mem>(keys_);
            cl::check(api.clSetKernelArg(lane->kernel, 0, sizeof(cl_mem), &lane->buffer), "kernel arg");
            cl::check(api.clSetKernelArg(lane->kernel, 2, sizeof(cl_mem), &k), "kernel arg");
            free_.push_back(lane.get());
            lanes_.push_back(std::move(lane));
        }
    } catch (...) {
        cleanup();
        throw;
    }
}

Session::~Session() { cleanup(); }

void Session::cleanup() noexcept {
    const auto& api = cl::api();
    // Zero device memory: drivers do not guarantee it is cleared before
    // another process gets it (cf. CVE-2023-4969 "LeftoverLocals").
    static constexpr cl_uint zero = 0;
    for (auto& lane : lanes_) {
        if (lane->queue != nullptr) {
            if (lane->buffer != nullptr) {
                api.clEnqueueFillBuffer(lane->queue, lane->buffer, &zero, sizeof zero, 0,
                                        v7::kChunkSize, 0, nullptr, nullptr);
            }
            if (keys_ != nullptr && lane.get() == lanes_.front().get()) {
                api.clEnqueueFillBuffer(lane->queue, static_cast<cl_mem>(keys_), &zero, sizeof zero, 0,
                                        kKeyWords * sizeof(std::uint32_t), 0, nullptr, nullptr);
            }
            api.clFinish(lane->queue);
        }
        if (lane->buffer != nullptr) api.clReleaseMemObject(lane->buffer);
        if (lane->kernel != nullptr) api.clReleaseKernel(lane->kernel);
        if (lane->queue != nullptr) api.clReleaseCommandQueue(lane->queue);
    }
    lanes_.clear();
    free_.clear();
    if (keys_ != nullptr) {
        api.clReleaseMemObject(static_cast<cl_mem>(keys_));
        keys_ = nullptr;
    }
    secure_zero(subkey_.data(), subkey_.size());
}

Session::Lane* Session::acquire() {
    std::unique_lock lk(mu_);
    cv_.wait(lk, [&] { return !free_.empty(); });
    Lane* l = free_.back();
    free_.pop_back();
    return l;
}

void Session::release(Lane* lane) {
    std::lock_guard lk(mu_);
    free_.push_back(lane);
    cv_.notify_one();
}

void Session::xor_keystreams(std::uint64_t chunk_index, std::uint8_t* data, std::size_t size) {
    if (size == 0) return;
    if (size > v7::kChunkSize) throw Error(ErrorCode::InvalidArgument, "GPU chunk too large");
    const auto& api = cl::api();
    Lane* lane = acquire();
    struct Release {
        Session* s;
        Lane* l;
        ~Release() { s->release(l); }
    } guard{this, lane};

    // IETF nonce 0x00000000 ‖ be64(index) as little-endian words 13..15
    std::uint8_t n12[12] = {};
    for (int i = 0; i < 8; ++i) n12[4 + i] = static_cast<std::uint8_t>(chunk_index >> (56 - 8 * i));
    const cl_uint nseg = static_cast<cl_uint>((size + 63) / 64);
    const cl_uint pre0 = aes_prefix_words_[0], pre1 = aes_prefix_words_[1];
    const cl_uint chunk = static_cast<cl_uint>(chunk_index);
    const cl_uint n13 = le32(n12), n14 = le32(n12 + 4), n15 = le32(n12 + 8);
    cl_kernel k = lane->kernel;
    cl::check(api.clSetKernelArg(k, 1, sizeof nseg, &nseg), "kernel arg");
    cl::check(api.clSetKernelArg(k, 3, sizeof pre0, &pre0), "kernel arg");
    cl::check(api.clSetKernelArg(k, 4, sizeof pre1, &pre1), "kernel arg");
    cl::check(api.clSetKernelArg(k, 5, sizeof chunk, &chunk), "kernel arg");
    cl::check(api.clSetKernelArg(k, 6, sizeof n13, &n13), "kernel arg");
    cl::check(api.clSetKernelArg(k, 7, sizeof n14, &n14), "kernel arg");
    cl::check(api.clSetKernelArg(k, 8, sizeof n15, &n15), "kernel arg");

    // Bytes past `size` in the last segment are garbage on the device and are
    // never copied back.
    const std::size_t global = (nseg + kLocalSize - 1) / kLocalSize * kLocalSize;
    cl::check(api.clEnqueueWriteBuffer(lane->queue, lane->buffer, CL_FALSE, 0, size, data, 0, nullptr, nullptr),
              "uploading a chunk");
    cl::check(api.clEnqueueNDRangeKernel(lane->queue, k, 1, nullptr, &global, &kLocalSize, 0, nullptr, nullptr),
              "running the kernel");
    cl::check(api.clEnqueueReadBuffer(lane->queue, lane->buffer, CL_TRUE, 0, size, data, 0, nullptr, nullptr),
              "downloading a chunk");
}

}  // namespace detail
}  // namespace encpto::gpu
