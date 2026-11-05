add_executable(encpto-cli main.cpp)
target_link_libraries(encpto-cli PRIVATE encpto::core)
encpto_set_warnings(encpto-cli)
install(TARGETS encpto-cli RUNTIME DESTINATION bin)
