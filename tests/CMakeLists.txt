add_executable(encpto-tests test_main.cpp)
target_link_libraries(encpto-tests PRIVATE encpto::core miniz_static)
target_include_directories(encpto-tests PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
target_compile_definitions(encpto-tests PRIVATE
    ENCPTO_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/data")
encpto_set_warnings(encpto-tests)
add_test(NAME encpto-tests COMMAND encpto-tests)
set_tests_properties(encpto-tests PROPERTIES TIMEOUT 600)
