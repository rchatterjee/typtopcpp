cmake_minimum_required(VERSION 3.6)

project(typtop_c)
# The version number.
set (typtop_VERSION_MAJOR 1)
set (typtop_VERSION_MINOR 0)
add_definitions(-DDEBUG)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_C_COMPILER ${CC})
SET(CMAKE_CXX_COMPILER ${CC})
set(CMAKE_CXX_FLAGS "-Wall -std=c++11")
IF(UNIX)
    IF(APPLE)
        SET(GUI "Cocoa")
    ELSE(APPLE)
        SET(GUI "X11")
    ENDIF(APPLE)
ELSE(UNIX)
    IF(WIN32)
        SET(GUI "Win32")
    ELSE(WIN32)
        SET(GUI "Unknown")
    ENDIF(WIN32)
ENDIF(UNIX)
MESSAGE("GUI system is ${GUI}")

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
        "${PROJECT_SOURCE_DIR}/typtopconfig.h.in"
        "${PROJECT_BINARY_DIR}/typtopconfig.h"
)

find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS src/db.proto)

include_directories("${PROJECT_BINARY_DIR}")

# Set up cryptopp
include_directories("${PROJECT_SOURCE_DIR}/cryptopp")
add_subdirectory (cryptopp)
# add_library(cryptopp STATIC cryptopp)


add_library(pw_crypto STATIC src/pw_crypto.cpp)
target_include_directories (pw_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pw_crypto cryptopp-static)

set(TYPTOP_SRCS src/typtop.cpp src/typtop.h ${PROTO_SRCS} ${PROTO_HDRS})
add_library(typtop STATIC ${TYPTOP_SRCS})
target_include_directories(typtop PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(typtop ${PROTOBUF_LIBRARIES})

include_directories(test)
set(TEST_SRCS "${PROJECT_SOURCE_DIR}/test/test-main.cpp" "${PROJECT_SOURCE_DIR}/test/test_pw_crypto.cpp" test/test_typtop.cpp)
add_executable(tests ${TEST_SRCS})
target_link_libraries(tests pw_crypto typtop)

add_executable(typtop_c src/main.cpp  ${TYPTOP_SRCS})
target_link_libraries(typtop_c pw_crypto ${PROTOBUF_LIBRARIES})
