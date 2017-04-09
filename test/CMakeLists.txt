set(TEST_SRCS test-main.cpp test_pw_crypto.cpp test_typtop.cpp test_install.cpp)
add_executable(tests ${TEST_SRCS})
if(APPLE)
    set(PAM_LIBS "pam")
else()
    set(PAM_LIBS "pam;pam_misc")
endif()


target_link_libraries(tests pw_crypto typtopdb ${PAM_LIBS})
add_test(test tests)
add_dependencies(tests ${CRYPTOPP_PREFIX})
add_dependencies(tests ${PLOG_PREFIX})
add_dependencies(tests ${ZXCVBN_PREFIX})
