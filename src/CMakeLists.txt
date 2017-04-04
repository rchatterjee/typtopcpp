# find_library(CRYPTOPP cryptopp ${CMAKE_BINARY_DIR})
# find_package(EASYLOGGING easylogging ${CMAKE_BINARY_DIR})

if (CRYPTOPP_INCLUDE_DIRS)
    message(STATUS "ADDING CRYPTOPP: ${CRYPTOPP_INCLUDE_DIRS} ${CRYPTOPP_LIBRARY_DIRS}")
    include_directories(${CRYPTOPP_INCLUDE_DIRS})
    link_directories(${CRYPTOPP_LIBRARY_DIRS})
else ()
    message(SEND_ERROR "Cryptopp not found: ${CRYPTOPP_INCLUDE_DIRS} is empty or incorrect")
endif ()

if (EASYLOGGING_INCLUDE_DIRS)
    message(STATUS "ADDING EASYLOGGING: ${EASYLOGGING_INCLUDE_DIRS} ${EASYLOGGING_FILES}")
endif()

add_library(pw_crypto STATIC pw_crypto.cpp pw_crypto.h)
target_include_directories (pw_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(pw_crypto ${CRYPTOPP_LIBRARY_DIRS}/libcryptopp.a)

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS db.proto)
set(TYPTOP_SRCS typtop.cpp typtop.h ${PROTO_SRCS} ${PROTO_HDRS} ${EASYLOGGING_FILES})

add_library(typtopdb STATIC ${TYPTOP_SRCS})
target_include_directories(typtopdb PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${EASYLOGGING_INCLUDE_DIRS})
#target_include_directories(typtopdb PUBLIC )
#target_include_directories(typtopdb PUBLIC )

message(STATUS "PROTO_SRCS: ${PROTO_SRCS} ${PROTO_HDRS} ${CMAKE_CURRENT_BINARY_DIR}")
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
