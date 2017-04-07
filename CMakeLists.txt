cmake_minimum_required(VERSION 2.8)

## So it generates one executable and one shared library
## 1> pam_typtop.so : a pam module that to engage typtop via PAM
## 2> typtop : a binary that manages the typtop database, and called by pam_typtop.so
##             this one also runs with elevated privileges SETGID bit  similar to unix_chkpwd

project(typtop)
# The version number.
set (typtop_VERSION_MAJOR 1)
set (typtop_VERSION_MINOR 0)

if(CMAKE_BUILD_TYPE EQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_C_COMPILER ${CC})
SET(CMAKE_CXX_COMPILER ${CC})
set(CMAKE_CXX_FLAGS "-Wall -std=c++11")

SET(INSTALL_DATA_DIR etc)
SET(INSTALL_BIN_DIR bin)
SET(INSTALL_LIB_DIR lib/security)

if(APPLE)
    SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif()

# External libraries
set(CRYPTOPP_PREFIX cryptopp565) # cryptopp
set(PLOG_PREFIX plog110) # Plog
set(ZXCVBN_PREFIX zxcvbn21) # Zxcvbn

include(3rdparty/DownloadProject.cmake)
set(CRYPTOPP_URL https://github.com/weidai11/cryptopp/archive/CRYPTOPP_5_6_5.tar.gz)
set(ZXCVBN_URL https://github.com/tsyrogit/zxcvbn-c/archive/v2.1.tar.gz)
download_project(PROJ                ${CRYPTOPP_PREFIX}
        URL      ${CRYPTOPP_URL}
        ${UPDATE_DISCONNECTED_IF_AVAILABLE}
        )
# add_subdirectory(${${CRYPTOPP_PREFIX}_SOURCE_DIR} ${${CRYPTOPP_PREFIX}_BINARY_DIR})

download_project(PROJ  ${ZXCVBN_PREFIX}
        URL      ${ZXCVBN_URL}
        # BUILD_COMMAND COMMAND make libzxcvbn.a USE_DICT_FILE=1 -C ${SOURCE_DIR}
        )

# add_dependencies(${ZXCVBN_PREFIX} libzxcvbn.a)

# include(CMakeLists-External.txt)

# Set up cryptopp
# include(CMakeLists-External.txt)
# find_package(CryptoPP REQUIRED)
# include_directories("${CryptoPP_INCLUDE_DIRS}")
# add_subdirectory (cryptopp)
# add_library(cryptopp STATIC cryptopp)




# required modules for our task
# include(CheckIncludeFile)

include(3rdparty/CMakeLists.txt)


add_subdirectory(src)
add_subdirectory(test)

# TO BE CREATED
# include(3rdparty/cryptopp.cmake)


# testing
include(CTest)
ENABLE_TESTING()

# For creating install packages
# add_subdirectory(install)

INCLUDE(install/CMakeLists.txt)
INCLUDE(CPack)
