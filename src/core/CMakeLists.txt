configure_file(version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/encpto/version.hpp @ONLY)

add_library(encpto_core STATIC
    archive.cpp
    crypto.cpp
    engine.cpp
    file.cpp
    format.cpp
    fsutil.cpp
    password.cpp
    secure_memory.cpp
    shred.cpp
)
add_library(encpto::core ALIAS encpto_core)

target_include_directories(encpto_core
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(encpto_core
    PUBLIC  Threads::Threads
    PRIVATE OpenSSL::Crypto encpto_sodium argon2_static miniz_static
            libdeflate::libdeflate_static)
target_compile_definitions(encpto_core PRIVATE _FILE_OFFSET_BITS=64)
if(WIN32)
    target_link_libraries(encpto_core PRIVATE crypt32 ws2_32 advapi32 user32 bcrypt)
endif()
encpto_set_warnings(encpto_core)
