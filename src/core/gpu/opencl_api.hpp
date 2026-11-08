#pragma once

// Run-time loaded OpenCL 1.2 entry points. Nothing links against OpenCL, so
// the binaries run on systems without an OpenCL driver.

#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 120
#endif
#include <CL/cl.h>

#include <string>

namespace encpto::gpu::cl {

#define ENCPTO_CL_FUNCTIONS(X)        \
    X(clGetPlatformIDs)               \
    X(clGetPlatformInfo)              \
    X(clGetDeviceIDs)                 \
    X(clGetDeviceInfo)                \
    X(clCreateContext)                \
    X(clReleaseContext)               \
    X(clCreateCommandQueue)           \
    X(clReleaseCommandQueue)          \
    X(clCreateProgramWithSource)      \
    X(clBuildProgram)                 \
    X(clGetProgramBuildInfo)          \
    X(clReleaseProgram)               \
    X(clCreateKernel)                 \
    X(clReleaseKernel)                \
    X(clSetKernelArg)                 \
    X(clCreateBuffer)                 \
    X(clReleaseMemObject)             \
    X(clEnqueueWriteBuffer)           \
    X(clEnqueueReadBuffer)            \
    X(clEnqueueFillBuffer)            \
    X(clEnqueueNDRangeKernel)         \
    X(clFinish)

struct Api {
#define X(name) decltype(&::name) name = nullptr;
    ENCPTO_CL_FUNCTIONS(X)
#undef X
    bool loaded = false;
    std::string error;
};

/// Loads the system OpenCL library once; check `loaded` / `error`.
const Api& api();

/// Throws Error(ErrorCode::Gpu) describing `what` and the OpenCL error code.
[[noreturn]] void fail(const char* what, cl_int code);

inline void check(cl_int code, const char* what) {
    if (code != CL_SUCCESS) fail(what, code);
}

}  // namespace encpto::gpu::cl
