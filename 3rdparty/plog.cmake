ExternalProject_Add(
  ${PLOG_PREFIX}

  GIT_REPOSITORY ${PLOG_URL}
  GIT_TAG ${PLOG_TAG}
  
  UPDATE_COMMAND ""
  PATCH_COMMAND ""

  INSTALL_DIR "${CMAKE_BINARY_DIR}/${PLOG_PREFIX}"
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND ""
  BUILD_COMMAND ""
  # BUILD_IN_SOURCE 1
  LOG_DOWNLOAD 1
  LOG_BUILD 1

  SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rdparty/${PLOG_PREFIX}"
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)

set(PLOG_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rdparty/${PLOG_PREFIX}/include")
