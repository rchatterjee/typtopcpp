
set(CRYPTOPP_PREFIX cryptopp565)

# Cryptopp url from where it should download
set(CRYPTOPP_URL https://github.com/weidai11/cryptopp/archive/CRYPTOPP_5_6_5.tar.gz)

set(NCPU 6)   # Number of CPUs to use

ExternalProject_Add(
        ${CRYPTOPP_PREFIX}
        PREFIX ${CRYPTOPP_PREFIX}
        URL ${CRYPTOPP_URL}
        TLS_VERIFY 1

        # SOURCE_DIR ${CMAKE_SOURCE_DIR}/3rdparty/cryptopp-5.6.5

        INSTALL_DIR ${CMAKE_BINARY_DIR}/${CRYPTOPP_PREFIX}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR> -j${NCPU}
        # BUILD_IN_SOURCE 1
        LOG_DOWNLOAD 1
        LOG_BUILD 1
        # STEP_TARGETS ${CRYPTOPP_PREFIX}_info
)


# get the unpacked source directory path
ExternalProject_Get_Property(${CRYPTOPP_PREFIX} SOURCE_DIR INSTALL_DIR)
message(STATUS "Source directory of ${CRYPTOPP_PREFIX} ${SOURCE_DIR}, ${INSTALL_DIR}")

# build another dependency
#ExternalProject_Add_Step(${CRYPTOPP_PREFIX} ${CRYPTOPP_PREFIX}_info
#  COMMAND cmake ${CMAKE_ARGS}
#  DEPENDEES build
#  WORKING_DIRECTORY ${SOURCE_DIR}
#  LOG 1
#)


# set the include directory variable and include it
set(CRYPTOPP_INCLUDE_DIRS ${INSTALL_DIR}/include)
include_directories(${CRYPTOPP_INCLUDE_DIRS})
set(CRYPTOPP_LIBRARY_DIRS ${INSTALL_DIR}/lib)
set(CRYPTOPP_LIBS cryptopp)

# verify that the CRYPTOPP header files can be included
set(CMAKE_REQUIRED_INCLUDES_SAVE ${CMAKE_REQUIRED_INCLUDES})
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${CRYPTOPP_INCLUDE_DIRS})
message(STATUS "CMAKE_REQUIRED_INCLUDES: ${CMAKE_REQUIRED_INCLUDES}")

check_include_file_cxx("cryptopp/cryptlib.h" HAVE_CRYPTOPP)
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVE})
 if (NOT HAVE_CRYPTOPP)
   message(STATUS "Did not build CRYPTOPP correctly as cannot find cryptopp.h. Will build it.")
   set(HAVE_CRYPTOPP 1)
endif (NOT HAVE_CRYPTOPP)

add_dependencies(tests ${CRYPTOPP_PREFIX})
add_dependencies(pw_crypto ${CRYPTOPP_PREFIX})

