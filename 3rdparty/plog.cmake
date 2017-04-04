# Plog

# Plog url from where it should download
set(PLOG_URL https://github.com/SergiusTheBest/plog/archive/1.1.0.tar.gz)

ExternalProject_Add(
        ${PLOG_PREFIX}
        PREFIX ${PLOG_PREFIX}
        URL ${PLOG_URL}
        TLS_VERIFY 1

        INSTALL_DIR ${CMAKE_BINARY_DIR}/${PLOG_PREFIX}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        CONFIGURE_COMMAND ""
        INSTALL_COMMAND ""
        BUILD_COMMAND ""
        # BUILD_IN_SOURCE 1
        LOG_DOWNLOAD 1
        LOG_BUILD 1
)


ExternalProject_Get_Property(${PLOG_PREFIX} SOURCE_DIR INSTALL_DIR)
message(STATUS "Source directory of ${PLOG_PREFIX} ${SOURCE_DIR}, ${INSTALL_DIR}")

# set the include directory variable and include it
set(PLOG_INCLUDE_DIRS ${SOURCE_DIR}/include CACHE INTERNAL "plog inlcude dirs")
FILE(GLOB PLOG_FILES_T ${SOURCE_DIR}/*.h ${SOURCE_DIR}/*.cc)
set(PLOG_FILES ${PLOG_FILES_T} CACHE INTERNAL "plog files")
message(STATUS ">>> PLOG_INCLUDE_DIRS = ${PLOG_INCLUDE_DIRS}  ${PLOG_FILES}")
include_directories(${PLOG_INCLUDE_DIRS})
