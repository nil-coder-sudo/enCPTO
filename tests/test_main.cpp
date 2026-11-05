// enCPTO test-suite (dependency-free).
//
// The fixtures in tests/data were produced by the original Python tool
// (legacy/enCPTO-v7.py) and by tests/compat/v7_reference.py, so passing these
// tests proves byte-level compatibility of the C++ engine with v7.0.

#include <encpto/archive.hpp>
#include <encpto/crypto.hpp>
#include <encpto/engine.hpp>
#include <encpto/file.hpp>
#include <encpto/fsutil.hpp>
#include <encpto/password.hpp>
#include <encpto/shred.hpp>

#include <miniz.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace encpto;

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        ++g_checks;                                                                    \
        if (!(cond)) {                                                                 \
            ++g_failures;                                                              \
            std::cerr << "  FAILED: " #cond "  (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        }                                                                              \
    } while (0)

template <typename F>
ErrorCode expect_error(F&& f) {
    try {
        f();
    } catch (const Error& e) {
        return e.code();
    }
    return ErrorCode::Internal;  // sentinel: nothing was thrown
}

const std::string kPwd = "Fixture#Pass2026";
const fs::path kData = ENCPTO_TEST_DATA;

std::vector<std::uint8_t> read_all(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}

void write_all(const fs::path& p, const std::vector<std::uint8_t>& d) {
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size()));
}

std::vector<std::uint8_t> random_data(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    crypto::random_bytes(v);
    return v;
}

Options fast_opts(unsigned threads = 0) {
    Options o;
    o.threads = threads;
    o.kdf = {1, 65536, 1};  // weakest profile the parser accepts — keeps tests fast
    return o;
}

struct TempDir {
    fs::path path;
    TempDir() {
        path = fs::temp_directory_path() / fsutil::from_utf8("encpto-test-" + fsutil::random_hex(6));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

void test_known_answer() {
    // tests/data/kat_v7.dat = v7_reference.encrypt_bytes(...) with fixed salt/IVs
    const auto expected = read_all(kData / "kat_v7.dat");
    CHECK(expected.size() == 1682);
    const auto header = v7::Header::parse(std::span(expected).first(v7::kHeaderSize));
    std::vector<std::uint8_t> payload(1000);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>((i * 7 + 3) & 0xFF);
    }
    v7::Meta meta;
    meta.name = "kat.txt";
    const auto got = detail::encrypt_buffer(payload, meta, kPwd, header);
    CHECK(got == expected);
}

void test_python_fixtures() {
    TempDir t;
    {
        const auto r = decrypt(kData / "py_hello.dat", t.path, kPwd);
        CHECK(!r.is_directory);
        CHECK(r.path.filename() == "hello.txt");
        const auto d = read_all(r.path);
        const std::string s(d.begin(), d.end());
        CHECK(s == "Hello from the original enCPTO v7 Python tool!\n");
    }
    {
        const auto r = decrypt(kData / "py_empty.dat", t.path, kPwd);
        CHECK(fs::file_size(r.path) == 0);
        CHECK(r.path.filename() == "empty.bin");
    }
    {
        const auto r = decrypt(kData / "py_unicode.dat", t.path, kPwd);
        CHECK(r.original_name == "中文檔名 ✓.txt");
        CHECK(fs::exists(t.path / fsutil::from_utf8("中文檔名 ✓.txt")));
    }
    {
        const auto r = decrypt(kData / "py_folder.dat", t.path, kPwd);
        CHECK(r.is_directory);
        CHECK(r.path.filename() == "My Folder");
        CHECK(read_all(r.path / "a.txt") == std::vector<std::uint8_t>(1000, 'A'));
        CHECK(fs::file_size(r.path / "sub dir" / "b.bin") == 2560);
        CHECK(fs::exists(r.path / "sub dir" / fsutil::from_utf8("照片.txt")));
    }
    {
        // Decrypting again never overwrites: "hello (1).txt"
        const auto r = decrypt(kData / "py_hello.dat", t.path, kPwd);
        CHECK(r.path.filename() == "hello (1).txt");
    }
}

void test_roundtrip_sizes() {
    TempDir t;
    const std::size_t C = v7::kChunkSize;
    for (const std::size_t size : {std::size_t{0}, std::size_t{1}, C - 1, C, C + 1, 3 * C + 5}) {
        for (const unsigned threads : {1U, 4U}) {
            const auto data = random_data(size);
            const fs::path src = t.path / "in.bin";
            const fs::path enc = t.path / "in.dat";
            const fs::path out = t.path / ("out-" + std::to_string(size) + "-" + std::to_string(threads));
            write_all(src, data);
            encrypt_file(src, enc, kPwd, fast_opts(threads));
            CHECK(fs::file_size(enc) == v7::kHeaderSize + v7::kMetaSize + v7::kMacSize +
                                            size + v7::chunk_count(size) * v7::kTag);
            const auto r = decrypt(enc, out, kPwd, fast_opts(threads));
            CHECK(read_all(r.path) == data);
        }
    }
}

void test_wrong_password_and_tampering() {
    TempDir t;
    const auto data = random_data(v7::kChunkSize + 100);
    write_all(t.path / "x.bin", data);
    encrypt_file(t.path / "x.bin", t.path / "x.dat", kPwd, fast_opts());
    const auto good = read_all(t.path / "x.dat");

    CHECK(expect_error([&] { decrypt(t.path / "x.dat", t.path / "o1", "Wrong#Pass2026"); }) ==
          ErrorCode::WrongPassword);

    auto body = good;
    body[v7::kHeaderSize + v7::kMetaSize + 10] ^= 1;  // ciphertext bit flip
    write_all(t.path / "b.dat", body);
    CHECK(expect_error([&] { decrypt(t.path / "b.dat", t.path / "o2", kPwd); }) == ErrorCode::Tampered);

    auto hdr = good;
    hdr[20] ^= 1;  // salt → different keys → metadata fails
    write_all(t.path / "h.dat", hdr);
    CHECK(expect_error([&] { decrypt(t.path / "h.dat", t.path / "o3", kPwd); }) == ErrorCode::WrongPassword);

    auto trunc = good;
    trunc.erase(trunc.begin() + static_cast<std::ptrdiff_t>(good.size() / 2),
                trunc.begin() + static_cast<std::ptrdiff_t>(good.size() / 2 + 1000));
    write_all(t.path / "t.dat", trunc);
    const auto code = expect_error([&] { decrypt(t.path / "t.dat", t.path / "o4", kPwd); });
    CHECK(code == ErrorCode::Tampered || code == ErrorCode::Corrupted);

    auto kdf = good;
    kdf[13] = 0xFF;  // absurd memory cost
    write_all(t.path / "k.dat", kdf);
    CHECK(expect_error([&] { decrypt(t.path / "k.dat", t.path / "o5", kPwd); }) == ErrorCode::Corrupted);

    // nothing may be left behind after failures
    for (const char* d : {"o1", "o2", "o3", "o4", "o5"}) {
        CHECK(!fs::exists(t.path / d) || fs::is_empty(t.path / d));
    }
}

void test_folder_roundtrip() {
    TempDir t;
    const fs::path root = t.path / fsutil::from_utf8("資料夾 Folder");
    fs::create_directories(root / "empty");
    fs::create_directories(root / "nested" / "deeper");
    write_all(root / "big.bin", random_data(40 * 1024 * 1024));   // streamed path
    write_all(root / "text.txt", std::vector<std::uint8_t>(200000, 'z'));  // deflated
    write_all(root / "photo.jpg", random_data(5000));               // stored
    write_all(root / "nested" / "deeper" / fsutil::from_utf8("檔案.md"), random_data(77));
    for (int i = 0; i < 50; ++i) {
        write_all(root / "nested" / ("f" + std::to_string(i)), random_data(static_cast<std::size_t>(i * 100)));
    }
    encrypt_directory(root, t.path / "f.dat", kPwd, fast_opts());
    const auto r = decrypt(t.path / "f.dat", t.path / "restore", kPwd, fast_opts());
    CHECK(r.is_directory);
    CHECK(r.path.filename() == root.filename());
    CHECK(fs::is_directory(r.path / "empty"));
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        const fs::path rel = fs::relative(e.path(), root);
        CHECK(fs::exists(r.path / rel));
        if (e.is_regular_file()) {
            CHECK(read_all(e.path()) == read_all(r.path / rel));
        }
    }
}

void test_zip_slip_rejected() {
    // Build a malicious archive by hand
    mz_zip_archive zip{};
    CHECK(mz_zip_writer_init_heap(&zip, 0, 0));
    const char evil[] = "pwned";
    CHECK(mz_zip_writer_add_mem(&zip, "../evil.txt", evil, 5, 0));
    void* buf = nullptr;
    std::size_t size = 0;
    CHECK(mz_zip_writer_finalize_heap_archive(&zip, &buf, &size));
    std::vector<std::uint8_t> data(static_cast<std::uint8_t*>(buf), static_cast<std::uint8_t*>(buf) + size);
    mz_zip_writer_end(&zip);
    TempDir t;
    CHECK(expect_error([&] { archive::extract(data, t.path / "x", {}); }) == ErrorCode::Corrupted);
    CHECK(!fs::exists(t.path / "evil.txt"));
}

void test_names_and_paths() {
    CHECK(fsutil::safe_output_name("../../etc/passwd", "f") == "passwd");
    CHECK(fsutil::safe_output_name("C:\\Windows\\evil.exe", "f") == "evil.exe");
    CHECK(fsutil::safe_output_name("  ..  ", "fallback") == "fallback");
    CHECK(fsutil::safe_output_name("a<b>c:d|e?.txt", "f") == "abcde.txt");
    CHECK(v7::truncate_utf8(std::string(254, 'a') + "中", 255) == std::string(254, 'a'));
    CHECK(fsutil::human_size(1536) == "1.5 KB");

    TempDir t;
    write_all(t.path / "a.txt", {});
    CHECK(fsutil::unique_path(t.path / "a.txt").filename() == "a (1).txt");
    fs::create_directories(t.path / "dir.v2");
    CHECK(fsutil::unique_path(t.path / "dir.v2").filename() == "dir.v2 (1)");
}

void test_password_tools() {
    using password::Strength;
    CHECK(password::assess("").strength == Strength::Empty);
    CHECK(password::assess("Ab1!").strength == Strength::TooShort);
    CHECK(password::assess("abcdefgh").strength == Strength::Weak);
    CHECK(password::assess("abcdEF12").acceptable());
    CHECK(password::assess("Fixture#Pass2026").strength >= Strength::Good);

    password::GeneratorOptions o;
    o.length = 32;
    o.avoid_ambiguous = true;
    for (int i = 0; i < 200; ++i) {
        const auto p = password::generate(o);
        CHECK(p.size() == 32);
        CHECK(p.find_first_of("0O1lI") == std::string::npos);
        CHECK(password::assess(p).classes == 4);
    }
    o.upper = o.lower = o.digits = o.symbols = false;
    CHECK(expect_error([&] { password::generate(o); }) == ErrorCode::InvalidArgument);
}

void test_inspect_and_legacy() {
    TempDir t;
    std::vector<std::uint8_t> v6 = {'E', 'N', 'C', 'P', 'T', 'O', '6', 0};
    v6.resize(800);
    write_all(t.path / "old.dat", v6);
    CHECK(inspect(t.path / "old.dat").kind == ContainerInfo::Kind::LegacyV2toV6);
    CHECK(expect_error([&] { decrypt(t.path / "old.dat", t.path, kPwd); }) ==
          ErrorCode::UnsupportedFormat);
    CHECK(inspect(kData / "py_hello.dat").kind == ContainerInfo::Kind::V7);
}

void test_cancel() {
    TempDir t;
    write_all(t.path / "c.bin", random_data(20 * 1024 * 1024));
    std::atomic_bool cancel{true};
    auto o = fast_opts();
    o.cancel = &cancel;
    CHECK(expect_error([&] { encrypt_file(t.path / "c.bin", t.path / "c.dat", kPwd, o); }) ==
          ErrorCode::Cancelled);
    CHECK(!fs::exists(t.path / "c.dat"));
    std::size_t leftovers = 0;
    for ([[maybe_unused]] const auto& e : fs::directory_iterator(t.path)) ++leftovers;
    CHECK(leftovers == 1);  // only c.bin
}

void test_shred() {
    TempDir t;
    write_all(t.path / "s.bin", random_data(100000));
    shred::shred_file(t.path / "s.bin");
    CHECK(fs::is_empty(t.path));
    fs::create_directories(t.path / "d" / "e");
    write_all(t.path / "d" / "e" / "x", random_data(10));
    shred::shred_directory(t.path / "d");
    CHECK(!fs::exists(t.path / "d"));
}

void bench() {
    // Not a test: prints throughput so CI logs show the speed-up.
    TempDir t;
    const std::size_t mb = 256;
    write_all(t.path / "bench.bin", random_data(mb << 20));
    for (const unsigned threads : {1U, 0U}) {
        auto o = Options{};
        o.threads = threads;
        const auto t0 = std::chrono::steady_clock::now();
        encrypt_file(t.path / "bench.bin", t.path / "bench.dat", kPwd, o);
        const auto t1 = std::chrono::steady_clock::now();
        decrypt(t.path / "bench.dat", t.path / ("o" + std::to_string(threads)), kPwd, o);
        const auto t2 = std::chrono::steady_clock::now();
        const auto secs = [](auto a, auto b) { return std::chrono::duration<double>(b - a).count(); };
        std::cout << "  bench " << mb << " MiB, threads=" << (threads ? std::to_string(threads) : "auto")
                  << ": encrypt " << secs(t0, t1) << " s (" << mb / secs(t0, t1)
                  << " MiB/s incl. Argon2id), decrypt " << secs(t1, t2) << " s ("
                  << mb / secs(t1, t2) << " MiB/s)\n";
    }
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<std::pair<const char*, std::function<void()>>> tests = {
        {"known-answer vector (Python reference)", test_known_answer},
        {"decrypt files made by the Python tool", test_python_fixtures},
        {"round-trip at chunk boundaries", test_roundtrip_sizes},
        {"wrong password / tampering", test_wrong_password_and_tampering},
        {"folder round-trip", test_folder_roundtrip},
        {"zip-slip protection", test_zip_slip_rejected},
        {"names and paths", test_names_and_paths},
        {"password tools", test_password_tools},
        {"inspect / legacy detection", test_inspect_and_legacy},
        {"cancellation", test_cancel},
        {"shredder", test_shred},
    };
    for (const auto& [name, fn] : tests) {
        const int before = g_failures;
        std::cout << "[ RUN  ] " << name << std::endl;
        try {
            fn();
        } catch (const std::exception& e) {
            ++g_failures;
            std::cerr << "  EXCEPTION: " << e.what() << "\n";
        }
        std::cout << (g_failures == before ? "[  OK  ] " : "[ FAIL ] ") << name << std::endl;
    }
    if (argc > 1 && std::strcmp(argv[1], "--bench") == 0) {
        bench();
    }
    std::cout << "\n" << g_checks << " checks, " << g_failures << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
