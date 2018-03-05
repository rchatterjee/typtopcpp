cmake_minimum_required(VERSION 2.8)

## Basic project information
project(typtop)
# The version number.
set (typtop_VERSION_MAJOR 1)
set (typtop_VERSION_MINOR 0)
set (typtop_VERSION_PATCH 6)

## Set compiler flags
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DDEBUG)
    set(CMAKE_VERBOSE_MAKEFILE true)
endif()

set(CMAKE_PREFER_SHARED_LIBRARIES $ENV{CMAKE_PREFER_SHARED_LIBRARIES})
message(STATUS "Building with shared libraries preferred: ${CMAKE_PREFER_SHARED_LIBRARIES}")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER ${CC})
set(CMAKE_CXX_COMPILER ${CC})
set(CMAKE_CXX_FLAGS "-Wall -std=c++11")

## Load any cmake modules from 3rdparty/
## Allows us to do find_package(CryptoPP)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/3rdparty/")

#### Set up sources for external dependencies

## CryptoPP fallback
set(CRYPTOPP_URL https://github.com/weidai11/cryptopp.git)
set(CRYPTOPP_TAG CRYPTOPP_5_6_5)
set(CRYPTOPP_PREFIX cryptopp565)
set(CRYPTOPP_TARGET_VERSION 5.6.5)
message(STATUS "Configuring dependencies: cryptopp, zxcvbn and plog")
include(cryptopp)
if(${CRYPTOPP_SHARED})
    message(STATUS "Crypto++ setup to be shared.")
else()
    message(STATUS "Crypto++ setup to be compiled.")
endif()

## Zxcvbn source (always used)
set(ZXCVBN_URL https://github.com/tsyrogit/zxcvbn-c.git)
set(ZXCVBN_TAG v2.1)
set(ZXCVBN_PREFIX zxcvbn21)
message(STATUS "Setup zxcvbn from github")
include(zxcvbn)

## Plog source(always used)
set(PLOG_URL https://github.com/SergiusTheBest/plog.git)
set(PLOG_TAG 1.1.0)
set(PLOG_PREFIX plog110)
message(STATUS "Setup plog from github")
include(plog)

set(INSTALL_DATA_DIR etc)
set(INSTALL_BIN_DIR bin)
set(INSTALL_LIB_DIR lib/security)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
        "${PROJECT_SOURCE_DIR}/typtopconfig.h.in"
        "${PROJECT_BINARY_DIR}/src/typtopconfig.h"
)

## So it generates one executable and one shared library
## 1> pam_typtop.so : a pam module that to engage typtop via PAM
## 2> typtop : a binary that manages the typtop database, and called by pam_typtop.so
##             this one also runs with elevated privileges SETGID bit  similar to unix_chkpwd

### Build each component
# build main source code
add_subdirectory(src)

# build pam module
add_subdirectory(src/pam_modules)

# testing
include(CTest)
ENABLE_TESTING()
add_subdirectory(test)

if(APPLE)
    SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif()

# For creating install packages
# add_subdirectory(install)

INCLUDE(install/CMakeLists.txt)
INCLUDE(CPack)
