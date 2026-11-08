#pragma once

// Experimental OpenCL acceleration.
//
// The OpenCL runtime is loaded at run time, so enCPTO starts and works
// normally on machines without a GPU driver; GPU support simply reports
// "unavailable" there.

#include <cstdint>
#include <string>
#include <vector>

namespace encpto::gpu {

struct Device {
    int index = -1;           // stable index for Options::gpu_device
    std::string name;
    std::string vendor;
    std::string platform;
    bool is_gpu = false;      // false: CPU / accelerator OpenCL device
    std::uint64_t memory = 0; // global memory, bytes
    unsigned compute_units = 0;
};

struct Status {
    bool runtime_found = false;
    std::string message;       // human-readable reason when no device is usable
    std::vector<Device> devices;
};

/// Discovers OpenCL devices (cached after the first call; thread-safe).
const Status& probe();

/// First real GPU, else the first device of any type, else -1.
int default_device();

}  // namespace encpto::gpu
