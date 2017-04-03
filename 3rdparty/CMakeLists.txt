include(ExternalProject)
include(CheckIncludeFileCXX)

# Builds external third party projects.
# The parent script needs to define the "GLOBAL_OUTPUT_PATH" variable,
# which will be used as output directory for all *.lib, *.dll, *.a, *.so, *.pdb files.

##############################################################################
# Crypto++
##############################################################################
# include(cryptopp.cmake)

#ExternalProject_Add(cryptopp_proj
#        URL https://github.com/weidai11/cryptopp/archive/CRYPTOPP_5_6_5.tar.gz
#        TLS_VERIFY 1
#        UPDATE_COMMAND ""
#        PATCH_COMMAND ""
#
#        # SOURCE_DIR ${CMAKE_SOURCE_DIR}/3rdparty/cryptopp-5.6.5
#
#        PREFIX ${CMAKE_CURRENT_BINARY_DIR}/cryptopp-5.6.5
#        DOWNLOAD_COMMAND ""
#        # INSTALL_DIR ${PROJECT_BINARY_DIR}
#        CMAKE_ARGS -DBuildShared=OFF -DBuildExamples=OFF -DCMAKE_INSTALL_PREFIX=${GLOBAL_OUTPUT_PATH}/cryptopp
#        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
#)
#ExternalProject_Get_Property(cryptopp_proj install_dir)
#add_library(cryptopp STATIC IMPORTED)
#ExternalProject_Add_StepDependencies(cryptopp_proj cryptopp)


# install(TARGETS cryptopp EXPORT cryptopp)
# export(TARGETS cryptopp FILE ${CMAKE_CURRENT_BINARY_DIR}/cryptopp-config.cmake)
# set_property(TARGET cryptopp PROPERTY IMPORTED_LOCATION ${install_dir}/lib/)

###############################################################################
# HumbleLogging
###############################################################################

# ExternalProject_Add(
#   HumbleLogging
#
#   GIT_REPOSITORY "https://github.com/mfreiholz/humble-logging-library.git"
#   GIT_TAG "master"
#
#   UPDATE_COMMAND ""
#   PATCH_COMMAND ""
#
#   SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rdparty/humblelogging"
#   CMAKE_ARGS -DBuildShared=ON -DBuildExamples=OFF -DCMAKE_INSTALL_PREFIX=${GLOBAL_OUTPUT_PATH}/humblelogging
#
#   TEST_COMMAND ""
# )

# ExternalProject_Add_Step(
#   HumbleLogging CopyToBin
#   COMMAND ${CMAKE_COMMAND} -E copy_directory ${GLOBAL_OUTPUT_PATH}/humblelogging/bin ${GLOBAL_OUTPUT_PATH}
#   COMMAND ${CMAKE_COMMAND} -E copy_directory ${GLOBAL_OUTPUT_PATH}/humblelogging/lib ${GLOBAL_OUTPUT_PATH}
#   DEPENDEES install
# )

# set(HumbleLogging_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rdparty/humblelogging/include")
# set(HumbleLogging_LIBRARIES "${CMAKE_SHARED_LIBRARY_PREFIX}humblelogging${CMAKE_SHARED_LIBRARY_SUFFIX}")
# include_directories(${HumbleLogging_INCLUDE_DIRS})


###############################################################################
# Google Prototype Buffers (protobuf)
# VS2008 Issue: Doesn't support OutDir/OutputPath
###############################################################################

#if (WIN32)
#    ExternalProject_Add(
#            protobuf
#
#            URL https://github.com/google/protobuf/releases/download/v3.1.0/protobuf-cpp-3.1.0.tar.gz
#            UPDATE_COMMAND ""
#            PATCH_COMMAND ""
#
#            SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rdparty/protobuf"
#            CONFIGURE_COMMAND ""
#
#            BUILD_COMMAND devenv /upgrade ${CMAKE_SOURCE_DIR}/3rdparty/protobuf/vsprojects/protobuf.sln
#            COMMAND msbuild /p:OutputPath=${GLOBAL_OUTPUT_PATH}/protobuf/ /p:OutDir=${GLOBAL_OUTPUT_PATH}/protobuf/ ${CMAKE_SOURCE_DIR}/3rdparty/protobuf/vsprojects/protobuf.sln
#
#            INSTALL_COMMAND ""
#
#            TEST_COMMAND ""
#    )
#
#    ExternalProject_Add_Step(
#            protobuf CopyToBin
#            COMMAND ${CMAKE_COMMAND} -E copy_directory ${GLOBAL_OUTPUT_PATH}/protobuf ${GLOBAL_OUTPUT_PATH}
#            DEPENDEES install
#    )
#
#    set(protobuf_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/3rdparty/protobuf/src/google/protobuf)
#    set(protobuf_LIBRARIES ${CMAKE_SHARED_LIBRARY_PREFIX}protobuf${CMAKE_SHARED_LIBRARY_SUFFIX})
#    include_directories(${protobuf_INCLUDE_DIRS})
#
#else (WIN32)
#
#    ExternalProject_Add(
#            protobuf
#
#            URL https://github.com/google/protobuf/releases/download/v3.1.0/protobuf-cpp-3.1.0.tar.gz
#
#            UPDATE_COMMAND ""
#            PATCH_COMMAND ""
#
#            SOURCE_DIR "${CMAKE_SOURCE_DIR}/3rdparty/protobuf"
#            CONFIGURE_COMMAND "${CMAKE_SOURCE_DIR}/3rdparty/protobuf/configure" --prefix=${GLOBAL_OUTPUT_PATH}/protobuf
#
#            BUILD_COMMAND make
#
#            INSTALL_COMMAND make install
#
#            TEST_COMMAND ""
#    )
#
#    ExternalProject_Add_Step(
#            protobuf CopyToBin
#            COMMAND ${CMAKE_COMMAND} -E copy_directory ${GLOBAL_OUTPUT_PATH}/protobuf ${GLOBAL_OUTPUT_PATH}
#            DEPENDEES install
#    )
#
#    set(protobuf_INCLUDE_DIRS ${GLOBAL_OUTPUT_PATH}/protobuf/include)
#    set(protobuf_LIBRARIES ${GLOBAL_OUTPUT_PATH}/protobuff/lib/)
#    include_directories(${protobuf_INCLUDE_DIRS})
#
#endif (WIN32)
