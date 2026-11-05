cmake_minimum_required(VERSION 3.21)

project(enCPTO
    VERSION 8.0.0
    DESCRIPTION "Dual-layer file & folder encryption (Argon2id + AES-256-CTR ⊕ XChaCha20-Poly1305 + HMAC-SHA512)"
    HOMEPAGE_URL "https://github.com/nil-coder-sudo/enCPTO"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(ENCPTO_BUILD_GUI   "Build the Qt 6 desktop application" ON)
option(ENCPTO_BUILD_CLI   "Build the encpto-cli command-line tool" ON)
option(ENCPTO_BUILD_TESTS "Build the test suite" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Dependencies)

add_subdirectory(src/core)

if(ENCPTO_BUILD_CLI)
    add_subdirectory(src/cli)
endif()

if(ENCPTO_BUILD_GUI)
    add_subdirectory(src/app)
endif()

if(ENCPTO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
