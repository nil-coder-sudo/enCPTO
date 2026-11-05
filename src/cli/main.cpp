// encpto-cli — command-line front end for the enCPTO engine.

#include <encpto/engine.hpp>
#include <encpto/fsutil.hpp>
#include <encpto/password.hpp>
#include <encpto/secure_memory.hpp>
#include <encpto/shred.hpp>
#include <encpto/version.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace encpto;

namespace {

std::atomic_bool g_cancel{false};

void on_signal(int) { g_cancel = true; }

constexpr const char* kUsage = R"(enCPTO )" ENCPTO_VERSION R"( — Argon2id + AES-256-CTR ⊕ XChaCha20-Poly1305 + HMAC-SHA512

Usage:
  encpto-cli encrypt <file|folder> [-o OUT.dat] [--shred] [options]
  encpto-cli decrypt <file.dat>    [-o OUT_DIR]           [options]
  encpto-cli info    <file.dat>
  encpto-cli genpass [--length N] [--no-upper] [--no-lower] [--no-digits]
                     [--no-symbols] [--no-ambiguous]

Options:
  -o, --output PATH     output file (encrypt) or folder (decrypt)
  -t, --threads N       worker threads (default: all cores)
      --password-stdin  read the password from the first line of stdin
      --shred           securely shred the source after encrypting
  -q, --quiet           no progress output
  -h, --help            show this help
  -v, --version         show the version

The password is prompted for (hidden) unless --password-stdin is given.
)";

struct Args {
    std::string command;
    std::vector<std::string> positional;
    std::optional<std::string> output;
    unsigned threads = 0;
    bool password_stdin = false;
    bool shred = false;
    bool quiet = false;
    password::GeneratorOptions gen;
};

[[noreturn]] void usage_error(const std::string& msg) {
    std::cerr << "error: " << msg << "\n\n" << kUsage;
    std::exit(2);
}

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) usage_error("missing value for " + s);
            return argv[++i];
        };
        if (s == "-h" || s == "--help") {
            std::cout << kUsage;
            std::exit(0);
        } else if (s == "-v" || s == "--version") {
            std::cout << "enCPTO " ENCPTO_VERSION " (container format V7)\n";
            std::exit(0);
        } else if (s == "-o" || s == "--output") {
            a.output = value();
        } else if (s == "-t" || s == "--threads") {
            a.threads = static_cast<unsigned>(std::stoul(value()));
        } else if (s == "--password-stdin") {
            a.password_stdin = true;
        } else if (s == "--shred") {
            a.shred = true;
        } else if (s == "-q" || s == "--quiet") {
            a.quiet = true;
        } else if (s == "--length") {
            a.gen.length = std::stoi(value());
        } else if (s == "--no-upper") {
            a.gen.upper = false;
        } else if (s == "--no-lower") {
            a.gen.lower = false;
        } else if (s == "--no-digits") {
            a.gen.digits = false;
        } else if (s == "--no-symbols") {
            a.gen.symbols = false;
        } else if (s == "--no-ambiguous") {
            a.gen.avoid_ambiguous = true;
        } else if (!s.empty() && s[0] == '-') {
            usage_error("unknown option " + s);
        } else if (a.command.empty()) {
            a.command = s;
        } else {
            a.positional.push_back(s);
        }
    }
    if (a.command.empty()) {
        std::cout << kUsage;
        std::exit(0);
    }
    return a;
}

// ── Password input ──────────────────────────────────────────────────────

class EchoOff {
public:
    EchoOff() {
#ifdef _WIN32
        h_ = GetStdHandle(STD_INPUT_HANDLE);
        if (GetConsoleMode(h_, &mode_)) {
            SetConsoleMode(h_, mode_ & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
            active_ = true;
        }
#else
        if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_) == 0) {
            termios t = old_;
            t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
            active_ = true;
        }
#endif
    }
    ~EchoOff() {
        if (!active_) return;
#ifdef _WIN32
        SetConsoleMode(h_, mode_);
#else
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_);
#endif
        std::cerr << "\n";
    }

private:
    bool active_ = false;
#ifdef _WIN32
    HANDLE h_{};
    DWORD mode_{};
#else
    termios old_{};
#endif
};

std::string read_line_utf8() {
#ifdef _WIN32
    // Read UTF-16 from the console so non-ASCII passwords match other platforms.
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(h, &mode)) {
        std::wstring w;
        wchar_t ch;
        DWORD n;
        while (ReadConsoleW(h, &ch, 1, &n, nullptr) && n == 1 && ch != L'\n') {
            if (ch != L'\r') w.push_back(ch);
        }
        const int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                            nullptr, 0, nullptr, nullptr);
        std::string s(static_cast<std::size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), len,
                            nullptr, nullptr);
        secure_zero(w.data(), w.size() * sizeof(wchar_t));
        return s;
    }
#endif
    std::string s;
    std::getline(std::cin, s);
    if (!s.empty() && s.back() == '\r') s.pop_back();
    return s;
}

std::string get_password(const Args& a, bool confirm) {
    if (a.password_stdin) {
        return read_line_utf8();
    }
    std::string pwd;
    {
        std::cerr << "Password: " << std::flush;
        EchoOff off;
        pwd = read_line_utf8();
    }
    if (confirm) {
        std::string again;
        {
            std::cerr << "Confirm password: " << std::flush;
            EchoOff off;
            again = read_line_utf8();
        }
        const bool same = again == pwd;
        secure_zero(again.data(), again.size());
        if (!same) {
            secure_zero(pwd.data(), pwd.size());
            throw Error(ErrorCode::InvalidArgument, "Passwords do not match.");
        }
    }
    return pwd;
}

// ── Progress ────────────────────────────────────────────────────────────

const char* phase_name(Phase p) {
    switch (p) {
        case Phase::DerivingKey: return "Deriving key (Argon2id)";
        case Phase::Packing: return "Packing folder";
        case Phase::Encrypting: return "Encrypting";
        case Phase::Verifying: return "Verifying HMAC";
        case Phase::Decrypting: return "Decrypting";
        case Phase::Extracting: return "Extracting";
        case Phase::Shredding: return "Shredding";
    }
    return "";
}

ProgressCallback make_progress(bool quiet) {
    if (quiet) return {};
    struct State {
        std::mutex mu;
        Phase phase = Phase::DerivingKey;
        std::chrono::steady_clock::time_point phase_start = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point last{};
    };
    auto st = std::make_shared<State>();
    return [st](const Progress& p) {
        std::lock_guard lk(st->mu);
        const auto now = std::chrono::steady_clock::now();
        if (p.phase != st->phase) {
            std::cerr << "\n";
            st->phase = p.phase;
            st->phase_start = now;
        }
        const bool finished = p.done >= p.total;
        if (!finished && now - st->last < std::chrono::milliseconds(100)) return;
        st->last = now;
        const double pct = p.total ? 100.0 * static_cast<double>(p.done) / static_cast<double>(p.total) : 100.0;
        const double secs = std::chrono::duration<double>(now - st->phase_start).count();
        std::fprintf(stderr, "\r  %-24s %6.1f%%", phase_name(p.phase), pct);
        if (p.phase != Phase::DerivingKey && secs > 0.05 && p.total > 1) {
            std::fprintf(stderr, "  %8.1f MB/s", static_cast<double>(p.done) / secs / 1e6);
        }
        std::fflush(stderr);
    };
}

// ── Commands ────────────────────────────────────────────────────────────

int cmd_encrypt(const Args& a) {
    if (a.positional.size() != 1) usage_error("encrypt needs exactly one input");
    const fs::path in = fsutil::from_utf8(a.positional[0]);
    if (!fs::exists(in)) throw Error(ErrorCode::InvalidArgument, "Input not found: " + a.positional[0]);
    const bool is_dir = fs::is_directory(in);
    fs::path out = a.output ? fsutil::from_utf8(*a.output) : fs::path();
    if (out.empty()) {
        fs::path base = in;
        if (!base.has_filename()) base = base.parent_path();
        out = base;
        out += ".dat";
    }

    std::string pwd = get_password(a, !a.password_stdin);
    const auto strength = password::assess(pwd);
    if (!strength.acceptable()) {
        secure_zero(pwd.data(), pwd.size());
        throw Error(ErrorCode::InvalidArgument,
                    "Weak password rejected: use ≥ 8 characters and at least 3 of "
                    "{upper, lower, digits, symbols}.");
    }

    Options opts;
    opts.threads = a.threads;
    opts.cancel = &g_cancel;
    opts.on_progress = make_progress(a.quiet);
    const auto t0 = std::chrono::steady_clock::now();
    try {
        if (is_dir) encrypt_directory(in, out, pwd, opts);
        else encrypt_file(in, out, pwd, opts);
    } catch (...) {
        secure_zero(pwd.data(), pwd.size());
        throw;
    }
    secure_zero(pwd.data(), pwd.size());
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (!a.quiet) std::cerr << "\n";
    std::cout << "Encrypted → " << fsutil::to_utf8(out) << "  (" << secs << " s)\n";

    if (a.shred) {
        if (is_dir) shred::shred_directory(in, opts);
        else shred::shred_file(in, opts);
        if (!a.quiet) std::cerr << "\n";
        std::cout << "Source shredded.\n";
    }
    return 0;
}

int cmd_decrypt(const Args& a) {
    if (a.positional.size() != 1) usage_error("decrypt needs exactly one input");
    const fs::path in = fsutil::from_utf8(a.positional[0]);
    const fs::path out_dir = a.output ? fsutil::from_utf8(*a.output)
                                      : (in.has_parent_path() ? in.parent_path() : fs::path("."));
    std::string pwd = get_password(a, false);
    Options opts;
    opts.threads = a.threads;
    opts.cancel = &g_cancel;
    opts.on_progress = make_progress(a.quiet);
    DecryptResult r;
    try {
        r = decrypt(in, out_dir, pwd, opts);
    } catch (...) {
        secure_zero(pwd.data(), pwd.size());
        throw;
    }
    secure_zero(pwd.data(), pwd.size());
    if (!a.quiet) std::cerr << "\n";
    std::cout << (r.is_directory ? "Folder" : "File") << " restored → " << fsutil::to_utf8(r.path)
              << "\n";
    return 0;
}

int cmd_info(const Args& a) {
    if (a.positional.size() != 1) usage_error("info needs exactly one input");
    const fs::path in = fsutil::from_utf8(a.positional[0]);
    const auto info = inspect(in);
    const auto size = fs::file_size(in);
    switch (info.kind) {
        case ContainerInfo::Kind::V7:
            std::cout << "enCPTO V7 container, " << fsutil::human_size(size)
                      << "\nThe original name and type are encrypted.\n";
            return 0;
        case ContainerInfo::Kind::LegacyV2toV6:
            std::cout << "Legacy enCPTO V" << info.version
                      << " container — decrypt it with legacy/enCPTO-v7.py.\n";
            return 0;
        case ContainerInfo::Kind::Unknown:
            std::cout << "Not a recognised enCPTO container.\n";
            return 1;
    }
    return 1;
}

int cmd_genpass(const Args& a) {
    std::cout << password::generate(a.gen) << "\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::signal(SIGINT, on_signal);
    const Args a = parse(argc, argv);
    try {
        if (a.command == "encrypt") return cmd_encrypt(a);
        if (a.command == "decrypt") return cmd_decrypt(a);
        if (a.command == "info") return cmd_info(a);
        if (a.command == "genpass") return cmd_genpass(a);
        usage_error("unknown command '" + a.command + "'");
    } catch (const Error& e) {
        std::cerr << "\nerror: " << e.what() << "\n";
        switch (e.code()) {
            case ErrorCode::WrongPassword: return 3;
            case ErrorCode::Tampered:
            case ErrorCode::Corrupted: return 4;
            case ErrorCode::Cancelled: return 130;
            default: return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "\nerror: " << e.what() << "\n";
        return 1;
    }
}
