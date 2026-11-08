#include "opencl_api.hpp"

#include "encpto/error.hpp"

#include <mutex>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace encpto::gpu::cl {
namespace {

void* open_library() {
#if defined(_WIN32)
    return reinterpret_cast<void*>(LoadLibraryW(L"OpenCL.dll"));
#elif defined(__APPLE__)
    return dlopen("/System/Library/Frameworks/OpenCL.framework/OpenCL", RTLD_NOW | RTLD_LOCAL);
#else
    for (const char* name : {"libOpenCL.so.1", "libOpenCL.so"}) {
        if (void* h = dlopen(name, RTLD_NOW | RTLD_LOCAL)) return h;
    }
    return nullptr;
#endif
}

void* symbol(void* lib, const char* name) {
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(lib), name));
#else
    return dlsym(lib, name);
#endif
}

}  // namespace

const Api& api() {
    static Api a;
    static std::once_flag once;
    std::call_once(once, [] {
        void* lib = open_library();
        if (lib == nullptr) {
            a.error = "No OpenCL runtime found (install your GPU driver).";
            return;
        }
#define X(name)                                                                 \
    a.name = reinterpret_cast<decltype(a.name)>(symbol(lib, #name));             \
    if (a.name == nullptr) {                                                     \
        a.error = "The OpenCL runtime lacks " #name " (OpenCL 1.2 is required)."; \
        return;                                                                  \
    }
        ENCPTO_CL_FUNCTIONS(X)
#undef X
        a.loaded = true;  // the library stays loaded for the process lifetime
    });
    return a;
}

void fail(const char* what, cl_int code) {
    throw Error(ErrorCode::Gpu, std::string("GPU error: ") + what + " (OpenCL " + std::to_string(code) + ")");
}

}  // namespace encpto::gpu::cl
