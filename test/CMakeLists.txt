set(TEST_SRCS test-main.cpp test_pw_crypto.cpp test_typtop.cpp)
add_executable(tests ${TEST_SRCS})
target_link_libraries(tests pw_crypto typtopdb)
add_test(test tests)