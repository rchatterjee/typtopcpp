# find_path(PLOG_INCLUDE_DIRS include PATHS ${CMAKE_BINARY_DIR})
# GET_PROPERTY(CRYPTOPP_INCLUDE_DIRS GLOBAL PROPERTY CRYPTOPP_INCLUDE_DIRS)
# set(cryptopp_DIR ${CMAKE_BINARY_DIR}/cryptopp565/lib/cmake/cryptopp/)
find_package(cryptopp REQUIRED PATHS ${CMAKE_BINARY_DIR}/${CRYPTOPP_PREFIX}/lib/cmake/cryptopp NO_DEFAULT_PATH)
function (getListOfVarsStartingWith _prefix _varResult)
    get_cmake_property(_vars VARIABLES)
    string (REGEX MATCHALL "(^|;)${_prefix}[A-Za-z0-9_]*" _matchedVars "${_vars}")
    set (${_varResult} ${_matchedVars} PARENT_SCOPE)
endfunction()
#getListOfVarsStartingWith("cryptopp_" matchedVars)
#foreach (_var IN LISTS matchedVars)
#    message("${_var}=${${_var}}")
#endforeach()

if (PLOG_INCLUDE_DIRS)
    message(STATUS "ADDING PLOG: ${PLOG_INCLUDE_DIRS} ${PLOG_FILES}")
    include_directories(${PLOG_INCLUDE_DIRS})
endif()

if (ZXCVBN_INCLUDE_DIRS)
    message(STATUS "ADDING ZXCVBN: ${ZXCVBN_INCLUDE_DIRS}")
    find_library(zxcvbn_lib zxcvbn ${ZXCVBN_INCLUDE_DIRS})
    include_directories(${ZXCVBN_INCLUDE_DIRS})
else(ZXCVBN_INCLUDE_DIRS)
    message(SEND_ERROR "Zxcvbn not found")
endif()

add_library(pw_crypto STATIC pw_crypto.cpp pw_crypto.h)
target_include_directories (pw_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(pw_crypto cryptopp-static)

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS db.proto)
set(TYPTOP_SRCS typtop.cpp typtop.h ${PROTO_SRCS} ${PROTO_HDRS} ${PLOG_FILES})

add_library(typtopdb STATIC ${TYPTOP_SRCS})
target_include_directories(typtopdb PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
        ${PLOG_INCLUDE_DIRS} ${ZXCVBN_INCLUDE_DIRS})
#target_include_directories(typtopdb PUBLIC )
#target_include_directories(typtopdb PUBLIC )

message(STATUS "PROTO_SRCS: ${PROTO_SRCS} ${PROTO_HDRS} ${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(typtopdb ${PROTOBUF_LIBRARIES} pw_crypto ${zxcvbn_lib})


add_executable(typtop typtop-main.cpp)
target_link_libraries(typtop pw_crypto typtopdb)

add_executable(testmain main.cpp)
target_link_libraries(testmain pw_crypto typtopdb ${zxcvbn_lib})

add_subdirectory(pam_modules)
### --- INSTALL --- ###
# Install three things,
#   1> pam_typtop.so -> /usr/local/lib/security,
#   2> typtop -> /sbin/
#   3> typtop.conf -> /etc/pam.d
#   4> POST_INSTALL_SCRIPT := to update the pam_config files,

INSTALL(TARGETS typtop
        RUNTIME DESTINATION bin
        PERMISSIONS SETUID WORLD_EXECUTE OWNER_EXECUTE GROUP_EXECUTE
        OWNER_WRITE GROUP_READ WORLD_READ
        OWNER_READ GROUP_READ
        )
