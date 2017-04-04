# Easylogging
set(EASYLOGGING_PREFIX easylogging)
# Easylogging url from where it should download
set(EASYLOGGING_URL https://github.com/muflihun/easyloggingpp/releases/download/v9.94.1/easyloggingpp_v9.94.1.tar.gz)

ExternalProject_Add(
        ${EASYLOGGING_PREFIX}
        PREFIX ${EASYLOGGING_PREFIX}
        URL ${EASYLOGGING_URL}
        TLS_VERIFY 1

        INSTALL_DIR ${CMAKE_BINARY_DIR}/${EASYLOGGING_PREFIX}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        CONFIGURE_COMMAND ""
        INSTALL_COMMAND ""
        BUILD_COMMAND ""
        # BUILD_IN_SOURCE 1
        LOG_DOWNLOAD 1
        LOG_BUILD 1
)


ExternalProject_Get_Property(${EASYLOGGING_PREFIX} SOURCE_DIR INSTALL_DIR)
message(STATUS "Source directory of ${EASYLOGGING_PREFIX} ${SOURCE_DIR}, ${INSTALL_DIR}")

# set the include directory variable and include it
set(EASYLOGGING_INCLUDE_DIRS ${SOURCE_DIR} CACHE INTERNAL "easylogging inlcude dirs")
FILE(GLOB EASYLOGGING_FILES_T ${SOURCE_DIR}/*.h ${SOURCE_DIR}/*.cc)
set(EASYLOGGING_FILES ${EASYLOGGING_FILES_T} CACHE INTERNAL "easylogging files")
message(STATUS ">>> EASYLOGGING_INCLUDE_DIRS = ${EASYLOGGING_INCLUDE_DIRS}  ${EASYLOGGING_FILES}")
include_directories(${EASYLOGGING_INCLUDE_DIRS})

add_dependencies(typtop ${EASYLOGGING_PREFIX})
add_dependencies(typtopdb ${EASYLOGGING_PREFIX})