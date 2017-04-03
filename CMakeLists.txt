cmake_minimum_required(VERSION 2.8)

## So it generates one executable and one shared library
## 1> pam_typtop.so : a pam module that to engage typtop via PAM
## 2> typtop : a binary that manages the typtop database, and called by pam_typtop.so
##             this one also runs with elevated privileges SETGID bit  similar to unix_chkpwd

project(typtop)
# The version number.
set (typtop_VERSION_MAJOR 1)
set (typtop_VERSION_MINOR 0)
add_definitions(-DDEBUG)


SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_C_COMPILER ${CC})
SET(CMAKE_CXX_COMPILER ${CC})
set(CMAKE_CXX_FLAGS "-Wall -std=c++11")

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
        "${PROJECT_SOURCE_DIR}/typtopconfig.h.in"
        "${PROJECT_BINARY_DIR}/typtopconfig.h"
)

find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS src/db.proto)

# include_directories("${PROJECT_BINARY_DIR}")
add_subdirectory(3rdparty)
add_subdirectory(test)
add_subdirectory(src)

# Set up cryptopp
# include(CMakeLists-External.txt)
# find_package(CryptoPP REQUIRED)
# include_directories("${CryptoPP_INCLUDE_DIRS}")
# add_subdirectory (cryptopp)
# add_library(cryptopp STATIC cryptopp)


# required modules for our task
include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckIncludeFiles)
include(ExternalProject)


# TO BE CREATED
# include(3rdparty/CMakeLists.txt)
include(3rdparty/cryptopp.cmake)

# testing
include(CTest)
ENABLE_TESTING()
