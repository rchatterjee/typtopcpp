add_library(pw_crypto STATIC pw_crypto.cpp pw_crypto.h)
target_include_directories (pw_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pw_crypto cryptopp-static)

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS src/db.proto)
set(TYPTOP_SRCS typtop.cpp typtop.h ${PROTO_SRCS} ${PROTO_HDRS})

add_library(typtopdb STATIC ${TYPTOP_SRCS})
target_include_directories(typtopdb PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(typtopdb ${PROTOBUF_LIBRARIES} pw_crypto)


add_executable(typtop typtop-main.cpp)
target_link_libraries(typtop pw_crypto typtopdb)

### --- INSTALL --- ###
# Install three things,
#   1> pam_typtop.so -> /usr/local/lib/security,
#   2> typtop -> /sbin/
#   3> typtop.conf -> /etc/pam.d
#   4> POST_INSTALL_SCRIPT := to update the pam_config files,
INSTALL(TARGETS typtop ${PAM_LIB}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib/security
        PERMISSIONS )
