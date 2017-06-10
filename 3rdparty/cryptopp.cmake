### Produces a `cryptopp` library which either points to a static or shared version.

include(ExternalProject)

set(NCPU 6)   # Number of CPUs to use


find_package(CryptoPP)
message(STATUS "CryptoPP installation: ${CRYPTOPP_FOUND} Version: ${CRYPTOPP_VERSION}")
if(CRYPTOPP_FOUND AND CMAKE_PREFER_SHARED_LIBRARIES AND (NOT CRYPTOPP_VERSION VERSION_LESS CRYPTOPP_TARGET_VERSION))
    ## If we insist on using shared version of cryptopp, set the library to the
    ## shared one
    set(CRYPTOPP_SHARED true)
    message(STATUS "Using CryptoPP system libraries")
    set(CRYPTOPP_INCLUDE_DIRS ${CRYPTOPP_INCLUDE_DIRS}/cryptopp)
    add_library(cryptopp SHARED IMPORTED)
    set_target_properties(cryptopp PROPERTIES IMPORTED_LOCATION ${CRYPTOPP_LIBRARY})
else()
    ### Add external projet for adding CryptoPP in case we need to build package
    ExternalProject_Add(
      ${CRYPTOPP_PREFIX}

      GIT_REPOSITORY ${CRYPTOPP_URL}
      GIT_TAG "CRYPTOPP_5_6_5 "
      
      UPDATE_COMMAND ""
      PATCH_COMMAND ""
      
      SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rdparty/${CRYPTOPP_PREFIX}"
      CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR> -j${NCPU} -DCMAKE_BUILD_TYPE=Release -DDISABLE_NATIVE_ARCH=ON
      
      TEST_COMMAND ""
    )

    ## Otherwise, use the static library which will be compiled using the above
    ## directories
    set(CRYPTOPP_SHARED false)
    message(STATUS "Install cryptopp from sources with prefix: ${CRYPTOPP_PREFIX}")
    set(CRYPTOPP_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rdparty/${CRYPTOPP_PREFIX}/")
    message(STATUS "CRYPTOPP_INCLUDE_DIRS: " ${CRYPTOPP_INCLUDE_DIRS})
    add_library(cryptopp STATIC IMPORTED)
    add_dependencies(cryptopp ${CRYPTOPP_PREFIX})
    ExternalProject_Get_Property(${CRYPTOPP_PREFIX} BINARY_DIR)
    set_target_properties(cryptopp PROPERTIES IMPORTED_LOCATION ${BINARY_DIR}/libcryptopp.a)
endif()
