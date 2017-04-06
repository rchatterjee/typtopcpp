# Zxcvbn url from where it should download
set(ZXCVBN_URL https://github.com/tsyrogit/zxcvbn-c/archive/v2.1.tar.gz)

ExternalProject_Add(
        ${ZXCVBN_PREFIX}
        PREFIX ${ZXCVBN_PREFIX}-src
        # URL ${ZXCVBN_URL}
        SOURCE_DIR ${${ZXCVBN_PREFIX}_SOURCE_DIR}
        TLS_VERIFY 1

        INSTALL_DIR ${${ZXCVBN_PREFIX}_BINARY_DIR}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        CONFIGURE_COMMAND ""
        BUILD_COMMAND  make  -C ${${ZXCVBN_PREFIX}_SOURCE_DIR} libzxcvbn.a USE_DICT_FILE=1
        INSTALL_COMMAND cp ${${ZXCVBN_PREFIX}_SOURCE_DIR}/libzxcvbn.a ${${ZXCVBN_PREFIX}_BINARY_DIR}/
        # BUILD_IN_SOURCE 1
        LOG_DOWNLOAD 1
        LOG_BUILD 1
)

ExternalProject_Get_Property(${ZXCVBN_PREFIX} SOURCE_DIR INSTALL_DIR)
message("ZXCVBN: Source directory of ${ZXCVBN_PREFIX} ${SOURCE_DIR}, ${INSTALL_DIR}")

#ExternalProject_Add_Step(
#        ${ZXCVBN_PREFIX} BUILD_COMMAND
#        COMMAND "make -f libzxcvbn.a USE_DICT_FILE=1 -C ${SOURCE_DIR}"
#        # COMMAND ${CMAKE_COMMAND} -E copy_directory ${GLOBAL_OUTPUT_PATH}/humblelogging/lib ${GLOBAL_OUTPUT_PATH}
#        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/${${ZXCVBN_PREFIX}_BINARY_DIR}
#        DEPENDEES all
#)



# set the include directory variable and include it
set(ZXCVBN_INCLUDE_DIRS ${SOURCE_DIR} CACHE INTERNAL "zxcvbn inlcude dirs")
# FILE(GLOB ZXCVBN_FILES_T ${SOURCE_DIR}/*.h ${SOURCE_DIR}/*.cc)
set(ZXCVBN_LIBRARY_DIRS ${ZXCVBN_INCLUDE_DIRS} CACHE INTERNAL "zxcvbn files")
message(STATUS ">>> ZXCVBN_INCLUDE_DIRS = ${ZXCVBN_INCLUDE_DIRS}  ${ZXCVBN_FILES}")

#add_custom_command(
#        OUTPUT libzxcvbn.a
#        COMMAND make libzxcvbn.a USE_DICT_FILE=1 -C ${ZXCVBN_INCLUDE_DIRS} -j4
#)
#add_custom_target(libzxcvbn ALL DEPENDS libzxcvbn.a)
