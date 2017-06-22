
# set(PAM_SOURCES pam_typtop.cpp)
# add_library(pam_typtop SHARED ${PAM_SOURCES})
# set_target_properties(pam_typtop PROPERTIES PREFIX "")



set(CMAKE_MACOSX_RPATH 1)
set(PAM_LIB pam_typtop)
set(PAM_LIB_SRCS pam_typtop.cpp)
set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")

IF(UNIX)
    IF(APPLE)
#        set(PAM_LIB pam_opendirectory_typtop)
#        set(PAM_LIB_SRCS pam_opendirectory_typtop.c)
        # set(EXTRA_PAM_LIB "-framework CoreFoundation -framework OpenDirectory")
        find_library(OpenDirectory OpenDirectory)
        find_library(CoreFoundation CoreFoundation)
        find_path(EXTRA_INCLUDE_PATH NAMES OpenDirectory/OpenDirectory.h)
        set(EXTRA_LIBS ${OpenDirectory} ${CoreFoundation})
        SET(EXTRA_OPTIONS "-flat_namespace")
        SET(GUI "Cocoa")
    ELSE(APPLE)  # Some unix platform, create pam_typtop
        SET(EXTRA_OPTIONS "-fPIC")
        SET(GUI "X11")
    ENDIF(APPLE)
ELSE(UNIX)
    IF(WIN32)
        SET(GUI "Win32")
    ELSE(WIN32)
        SET(GUI "Unknown")
    ENDIF(WIN32)
ENDIF(UNIX)

MESSAGE("GUI system is ${GUI}")
# Search for PAM, required to build the pam_modules
find_path(PAM_INCLUDE_DIR NAMES security/pam_appl.h pam/pam_appl.h)
find_library(PAM_LIBRARY pam)

if(NOT PAM_INCLUDE_DIR)
    MESSAGE(FATAL_ERROR "PAM not found. Please install libpamdev or equivalent")
else(NOT PAM_INCLUDE_DIR)
    add_library(${PAM_LIB} SHARED ${PAM_LIB_SRCS} ${PAM_INCLUDE_DIR})
    target_link_libraries(${PAM_LIB} ${PAM_LIBRARY} ${EXTRA_LIBS})
    set_target_properties(${PAM_LIB} PROPERTIES LINK_FLAGS ${EXTRA_OPTIONS})
endif(NOT PAM_INCLUDE_DIR)

install(TARGETS ${PAM_LIB}
        DESTINATION lib/security)

if(APPLE)
    SET(PRIMARY_PAM_MODULE pam_opendirectory.so)
    SET(OSX_COMMENT "# ")
else(NOT WIN32)
    SET(PRIMARY_PAM_MODULE pam_unix.so)
    SET(OSX_COMMENT "")
endif()
configure_file(${CMAKE_CURRENT_LIST_DIR}/typtop-auth.in ${CMAKE_BINARY_DIR}/typtop-auth)
install(FILES  ${CMAKE_BINARY_DIR}/typtop-auth DESTINATION /etc/pam.d)
install(FILES  ${CMAKE_BINARY_DIR}/typtop-auth DESTINATION ${INSTALL_DATA_DIR}/typtop.d/)
