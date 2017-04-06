set(NCPU 6)   # Number of CPUs to use

ExternalProject_Add(
        ${CRYPTOPP_PREFIX}
        PREFIX ${${CRYPTOPP_PREFIX}_SOURCE_DIR}
        TLS_VERIFY 1
        SOURCE_DIR ${${CRYPTOPP_PREFIX}_SOURCE_DIR}
        INSTALL_DIR ${${CRYPTOPP_PREFIX}_BINARY_DIR}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR> -j${NCPU}
        # BUILD_IN_SOURCE 1
        LOG_DOWNLOAD 1
        LOG_BUILD 1
        # STEP_TARGETS ${CRYPTOPP_PREFIX}_info
)

# include(src/${CRYPTOPP_PREFIX}-stamp/down)

## get the unpacked source directory path
#ExternalProject_Get_Property(${CRYPTOPP_PREFIX} SOURCE_DIR INSTALL_DIR)
#message(STATUS "Source directory of ${CRYPTOPP_PREFIX} ${SOURCE_DIR}, ${INSTALL_DIR}")
#
## build another dependency
##ExternalProject_Add_Step(${CRYPTOPP_PREFIX} ${CRYPTOPP_PREFIX}_info
##  COMMAND cmake ${CMAKE_ARGS}
##  DEPENDEES build
##  WORKING_DIRECTORY ${SOURCE_DIR}
##  LOG 1
##)
#
#
## set the include directory variable and include it
#set(CRYPTOPP_INCLUDE_DIRS ${INSTALL_DIR}/include CACHE INTERNL "Cryptopp include dirs")
#message(STATUS ">> ${LIBRARY_DIR}")
#set(CRYPTOPP_LIBRARY_DIRS ${INSTALL_DIR}/lib CACHE INTERNAL "Cryptopp libs")
#set(CRYPTOPP_LIBS cryptopp-static)
## SET_PROPERTY(GLOBAL PROPERTY CRYPTOPP_INCLUDE_DIRS "${INSTALL_DIR}/include")
## SET_PROPERTY(GLOBAL PROPERTY CRYPTOPP_LIBS "${INSTALL_DIR}/lib")
#
#
## verify that the CRYPTOPP header files can be included
#set(CMAKE_REQUIRED_INCLUDES_SAVE ${CMAKE_REQUIRED_INCLUDES})
#set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${CRYPTOPP_INCLUDE_DIRS})
## message(STATUS "CMAKE_REQUIRED_INCLUDES: ${CMAKE_REQUIRED_INCLUDES}")
#
#check_include_file_cxx("cryptopp/cryptlib.h" HAVE_CRYPTOPP)
#set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVE})
# if (NOT HAVE_CRYPTOPP)
#   message(STATUS "Did not build CRYPTOPP correctly as cannot find cryptopp.h. Will build it.")
#   set(HAVE_CRYPTOPP 1)
#endif (NOT HAVE_CRYPTOPP)
