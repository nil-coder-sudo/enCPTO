# Third-party dependencies
#
#   System / package manager : OpenSSL 3 (AES-256-CTR, SHA-512, HMAC, HKDF)
#                              libsodium  (XChaCha20-Poly1305, secure memory)
#                              Qt 6       (GUI only)
#   Fetched at configure time: Argon2 reference implementation (supports p > 1,
#                              which libsodium does not), libdeflate (fast SIMD
#                              DEFLATE + CRC-32), miniz (ZIP container I/O),
#                              Khronos OpenCL headers (the runtime itself is
#                              loaded with dlopen/LoadLibrary at run time)
include(FetchContent)
set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ── OpenSSL ──────────────────────────────────────────────────────────────
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# ── libsodium ────────────────────────────────────────────────────────────
add_library(encpto_sodium INTERFACE)
find_package(unofficial-sodium CONFIG QUIET)            # vcpkg
if(TARGET unofficial-sodium::sodium)
    target_link_libraries(encpto_sodium INTERFACE unofficial-sodium::sodium)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
    endif()
    if(TARGET PkgConfig::SODIUM)
        target_link_libraries(encpto_sodium INTERFACE PkgConfig::SODIUM)
    else()
        find_path(SODIUM_INCLUDE_DIR sodium.h REQUIRED)
        find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
        target_include_directories(encpto_sodium INTERFACE ${SODIUM_INCLUDE_DIR})
        target_link_libraries(encpto_sodium INTERFACE ${SODIUM_LIBRARY})
    endif()
endif()

# ── Argon2 (P-H-C reference implementation) ─────────────────────────────
FetchContent_Declare(argon2
    GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
    GIT_TAG        62358ba2123abd17fccf2a108a301d4b52c01a7c)   # tag 20190702
FetchContent_MakeAvailable(argon2)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|x64|i[3-6]86)$")
    set(ARGON2_IMPL ${argon2_SOURCE_DIR}/src/opt.c)    # SSE2/SSSE3 optimised
else()
    set(ARGON2_IMPL ${argon2_SOURCE_DIR}/src/ref.c)    # portable (ARM etc.)
endif()

add_library(argon2_static STATIC
    ${argon2_SOURCE_DIR}/src/argon2.c
    ${argon2_SOURCE_DIR}/src/core.c
    ${argon2_SOURCE_DIR}/src/encoding.c
    ${argon2_SOURCE_DIR}/src/thread.c
    ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
    ${ARGON2_IMPL})
target_include_directories(argon2_static
    PUBLIC  ${argon2_SOURCE_DIR}/include
    PRIVATE ${argon2_SOURCE_DIR}/src)
target_link_libraries(argon2_static PRIVATE Threads::Threads)
set_target_properties(argon2_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
# A static libsodium (vcpkg on Windows) exports its own argon2_* and, in some
# versions, unprefixed blake2b_* symbols with a *different* state layout.
# Prefix every external symbol of the bundled Argon2 so the linker can never
# mix the two implementations (which silently produced wrong hashes on MSVC).
foreach(sym argon2_ctx argon2_hash argon2_verify argon2_verify_ctx argon2_error_message
            argon2_encodedlen argon2_type2string
            argon2i_ctx argon2i_hash_encoded argon2i_hash_raw argon2i_verify argon2i_verify_ctx
            argon2d_ctx argon2d_hash_encoded argon2d_hash_raw argon2d_verify argon2d_verify_ctx
            argon2id_ctx argon2id_hash_encoded argon2id_hash_raw argon2id_verify argon2id_verify_ctx)
    target_compile_definitions(argon2_static PUBLIC ${sym}=encpto_${sym})
endforeach()
foreach(sym blake2b blake2b_init blake2b_init_key blake2b_init_param blake2b_update
            blake2b_final blake2b_long
            initialize finalize validate_inputs fill_memory_blocks fill_segment index_alpha
            allocate_memory free_memory secure_wipe_memory clear_internal_memory
            fill_first_blocks initial_hash init_block_value copy_block xor_block
            encode_string decode_string b64len numlen
            argon2_thread_create argon2_thread_join argon2_thread_exit
            FLAG_clear_internal_memory)
    target_compile_definitions(argon2_static PRIVATE ${sym}=encpto_argon2_${sym})
endforeach()
if(MSVC)
    target_compile_options(argon2_static PRIVATE /W0)
else()
    target_compile_options(argon2_static PRIVATE -w)
endif()

# ── miniz (ZIP) ──────────────────────────────────────────────────────────
FetchContent_Declare(miniz
    URL      https://github.com/richgel999/miniz/releases/download/3.1.2/miniz-3.1.2.zip
    URL_HASH SHA256=f0446d863f9c19926ad9483c523fdc42e42b8d4a6a431d27e09d49c79a140d9a
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(miniz)

add_library(miniz_static STATIC ${miniz_SOURCE_DIR}/miniz.c)
target_include_directories(miniz_static PUBLIC ${miniz_SOURCE_DIR})
target_compile_definitions(miniz_static PUBLIC
    MINIZ_NO_ZLIB_COMPATIBLE_NAMES _LARGEFILE64_SOURCE)
set_target_properties(miniz_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(MSVC)
    target_compile_options(miniz_static PRIVATE /W0)
else()
    target_compile_options(miniz_static PRIVATE -w)
endif()

# ── libdeflate (fast DEFLATE / CRC-32 for folder archives) ──────────────
set(LIBDEFLATE_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(LIBDEFLATE_BUILD_GZIP OFF CACHE BOOL "" FORCE)
set(LIBDEFLATE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBDEFLATE_ZLIB_SUPPORT OFF CACHE BOOL "" FORCE)
set(LIBDEFLATE_GZIP_SUPPORT ON CACHE BOOL "" FORCE)   # provides libdeflate_crc32()
FetchContent_Declare(libdeflate
    GIT_REPOSITORY https://github.com/ebiggers/libdeflate.git
    GIT_TAG        c8c56a20f8f621e6a966b716b31f1dedab6a41e3)   # v1.25
FetchContent_MakeAvailable(libdeflate)

# ── OpenCL headers (experimental GPU path; header-only) ─────────────────
FetchContent_Declare(opencl_headers
    GIT_REPOSITORY https://github.com/KhronosGroup/OpenCL-Headers.git
    GIT_TAG        8a97ebc88daa3495d6f57ec10bb515224400186f)   # v2025.07.22
FetchContent_MakeAvailable(opencl_headers)
