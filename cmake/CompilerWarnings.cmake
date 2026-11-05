# Warning / hardening flags applied to enCPTO's own targets (not third-party code).
function(encpto_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
        if(NOT APPLE)
            target_compile_options(${target} PRIVATE -fstack-protector-strong)
        endif()
    endif()
endfunction()
