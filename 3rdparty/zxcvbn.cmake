# Zxcvbn url from where it should download
set(ZXCVBN_URL https://github.com/tsyrogit/zxcvbn-c/archive/v2.1.tar.gz)

ExternalProject_Add(
        ${ZXCVBN_PREFIX}
        PREFIX ${ZXCVBN_PREFIX}
        URL ${ZXCVBN_URL}
        TLS_VERIFY 1

        INSTALL_DIR ${CMAKE_BINARY_DIR}/${ZXCVBN_PREFIX}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        # BUILD_IN_SOURCE 1
        LOG_DOWNLOAD 1
        LOG_BUILD 1
)

#ExternalProject_Add_Step(
#        ${ZXCVBN_PREFIX} CopyToBin
#        COMMAND make libzxcvbn.a USE_DICT_FILE=1
#        # COMMAND ${CMAKE_COMMAND} -E copy_directory ${GLOBAL_OUTPUT_PATH}/humblelogging/lib ${GLOBAL_OUTPUT_PATH}
#        # DEPENDEES install
#)


ExternalProject_Get_Property(${ZXCVBN_PREFIX} SOURCE_DIR INSTALL_DIR)
message(STATUS "ZXCVBN: Source directory of ${ZXCVBN_PREFIX} ${SOURCE_DIR}, ${INSTALL_DIR}")

# set the include directory variable and include it
set(ZXCVBN_INCLUDE_DIRS ${SOURCE_DIR} CACHE INTERNAL "zxcvbn inlcude dirs")
# FILE(GLOB ZXCVBN_FILES_T ${SOURCE_DIR}/*.h ${SOURCE_DIR}/*.cc)
set(ZXCVBN_LIBRARY_DIRS ${ZXCVBN_INCLUDE_DIRS} CACHE INTERNAL "zxcvbn files")
message(STATUS ">>> ZXCVBN_INCLUDE_DIRS = ${ZXCVBN_INCLUDE_DIRS}  ${ZXCVBN_FILES}")

add_custom_command(
        OUTPUT libzxcvbn.a
        COMMAND make libzxcvbn.a USE_DICT_FILE=1 -C ${ZXCVBN_INCLUDE_DIRS}
)
add_custom_target(libzxcvbn ALL DEPENDS libzxcvbn.a)
add_dependencies(${ZXCVBN_PREFIX} libzxcvbn)