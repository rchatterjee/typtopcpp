### Protobuf is a strict dependency here
find_package(Protobuf REQUIRED)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS db.proto)
include_directories(${PROTOBUF_INCLUDE_DIRS})
find_library(PROTOBUF_STATIC_LIB libprotobuf.a PROTOBUF_LIBRARIES)
find_library(PROTOBUF_SHARED_LIB libprotobuf.so PROTOBUF_LIBRARIES)

if(NOT PROTOBUF_STATIC_LIB AND NOT PROTOBUF_SHARED_LIB)
  message( FATAL_ERROR "Cannot find any suitable protobuf library." )
endif()

### Curl is also required
find_package(CURL REQUIRED)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET(DEBUG 1)
endif()

### Set the sources for typtop
file(GLOB TYPTOP_SRCS "*.cpp")
file(GLOB TYPTOP_HDRS "*.h")
set(TYPTOP_SRCS ${TYPTOP_SRCS} ${TYPTOP_HDRS} ${PROTO_SRCS} ${PROTO_HDRS} typtopconfig.h)

### Build the main typtop functionality (in particular, the db) as library
add_library(typtopdb ${TYPTOP_SRCS})
### Build typtop as an executable (why for win32?)
add_executable(typtop typtop-main.cpp)  # Not sure why we have win32


### Ad an executable for decoding base64 encoded lines, python base64 is not compatible with CryptoPP one.
### Hence, a C++ binary to deal with it.
add_executable(b64 b64.cpp)

### Include various header files from external libraries
target_include_directories(typtopdb PRIVATE ${CRYPTOPP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
target_include_directories(typtop PUBLIC ${CRYPTOPP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})
target_include_directories(b64 PUBLIC ${CRYPTOPP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${ZXCVBN_INCLUDE_DIRS} ${PLOG_INCLUDE_DIRS})

### Link libraries. These are configured through 3rdparty/${lib_name}
target_link_libraries(typtopdb cryptopp)
target_link_libraries(typtop typtopdb cryptopp zxcvbn typtopdb curl)
target_link_libraries(b64 typtopdb ${PROTOBUF_STATIC_LIB})

### Make sure cryptopp and zxcvbn are built when necessary.
add_dependencies(typtopdb cryptopp zxcvbn)


### Attempt to follow preference for protobuf library.
if(CMAKE_PREFER_SHARED_LIBRARIES)
    if(PROTOBUF_SHARED_LIB)
        target_link_libraries(typtop ${PROTOBUF_SHARED_LIB})
    else(PROTOBUF_STATIC_LIB)
        target_link_libraries(typtop ${PROTOBUF_STATIC_LIB})
    endif()
else()
    if(PROTOBUF_SHARED_LIB)
        target_link_libraries(typtop ${PROTOBUF_SHARED_LIB})
    else(PROTOBUF_STATIC_LIB)
        target_link_libraries(typtop ${PROTOBUF_STATIC_LIB})
    endif()
endif()
# ### --- INSTALL --- ###
# # Install three things,
# #   1> pam_typtop.so -> /usr/local/lib/security,
# #   2> typtop -> /sbin/
# #   3> typtop.conf -> /etc/pam.d
# #   4> POST_INSTALL_SCRIPT := to update the pam_config files,

INSTALL(TARGETS typtop
        RUNTIME DESTINATION ${INSTALL_BIN_DIR}
        PERMISSIONS SETUID WORLD_EXECUTE OWNER_EXECUTE GROUP_EXECUTE
        OWNER_WRITE GROUP_READ WORLD_READ
        OWNER_READ GROUP_READ
        )
INSTALL(DIRECTORY typtop.d DESTINATION ${INSTALL_DATA_DIR})
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION ${INSTALL_DATA_DIR}/typtop.d/)
