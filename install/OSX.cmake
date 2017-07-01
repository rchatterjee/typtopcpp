
#-------------------------------------------------------------------------------
# This macro will set all the variables necessary to have a "good" OS X Application
# bundle. The variables are as follows:
#  PROJECT_NAME - which can be taken from the ${PROJECT_NAME} variable is needed
#  DEBUG_EXTENSION - The extension used to denote a debug built Application. Typically
#   this is '_debug'
#  ICON_FILE_PATH - The complete path to the bundle icon file
#  VERSION_STRING - The version string that you wish to use for the bundle. For OS X
#   this string is usually XXXX.YY.ZZ in type. Look at the Apple docs for more info
#-------------------------------------------------------------------------------
macro(ConfigureMacOSXBundlePlist PROJECT_NAME DEBUG_EXTENSION ICON_FILE_PATH VERSION_STRING)
    # message(STATUS "ConfigureMacOSXBundlePlist for ${PROJECT_NAME} ")
    IF(CMAKE_BUILD_TYPE MATCHES "Release")
        SET(DBG_EXTENSION "")
    else()
        set(DBG_EXTENSION ${DEBUG_EXTENSION})
    endif()
    get_filename_component(ICON_FILE_NAME "${ICON_FILE_PATH}" NAME)

    #CFBundleGetInfoString
    SET(MACOSX_BUNDLE_INFO_STRING "${PROJECT_NAME}${DBG_EXTENSION} Version ${VERSION_STRING} - a smart password checker for laptop login")
    SET(MACOSX_BUNDLE_ICON_FILE ${ICON_FILE_NAME})
    SET(MACOSX_BUNDLE_GUI_IDENTIFIER "${PROJECT_NAME}${DBG_EXTENSION}")
    #CFBundleLongVersionString
    SET(MACOSX_BUNDLE_LONG_VERSION_STRING "${PROJECT_NAME}${DBG_EXTENSION} Version ${VERSION_STRING}")
    SET(MACOSX_BUNDLE_BUNDLE_NAME ${PROJECT_NAME}${DBG_EXTENSION})
    SET(MACOSX_BUNDLE_SHORT_VERSION_STRING ${VERSION_STRING})
    SET(MACOSX_BUNDLE_BUNDLE_VERSION ${VERSION_STRING})
    SET(MACOSX_BUNDLE_COPYRIGHT "Copyright 2017, Cornell Tech, All Rights Reserved.")

    SET(${PROJECT_NAME}_PROJECT_SRCS ${${PROJECT_NAME}_PROJECT_SRCS} ${ICON_FILE_PATH})
    SET_SOURCE_FILES_PROPERTIES(${ICON_FILE_PATH} PROPERTIES
            MACOSX_PACKAGE_LOCATION Resources)

endmacro()


SET(CPACK_GENERATOR "TGZ")
SET(CPACK_BINARY_PACKAGEMAKER "pkgbuild")
set(CPACK_POSTFLIGHT_SCRIPT  "${CMAKE_SOURCE_DIR}/install/postinst")
set(CPACK_POSTUPGRADE_SCRIPT  "${CMAKE_SOURCE_DIR}/install/postinst")
set(CPACK_OSX_PACKAGE_VERSION, 11.0)
SET(CPACK_STRIP_FILES "ON")
SET(CPACK_SOURCE_STRIP_FILES "ON")
ConfigureMacOSXBundlePlist(${PROJECT_NAME} "-debug" icon_typtop.icns "${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
SET(CPACK_BUNDLE_STARTUP_COMMAND "${CMAKE_SOURCE_DIR}/install/postinst")
SET(CPACK_BUNDLE_ICON ${CMAKE_SOURCE_DIR}/install/icon_typtop.icns)
message(">>     ${CMAKE_MODULE_PATH}")
# set_target_properties(typtop PROPERTIES
#        MACOSX_BUNDLE "on")
set(pam_module "pam_opendirectory.so")
set(typtop_identifier "com.typtop.cornell.edu")

configure_file(${CMAKE_SOURCE_DIR}/install/prerm_osx.in
        ${CMAKE_BINARY_DIR}/scripts/prerm @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/install/postinstall_osx.in
        ${CMAKE_BINARY_DIR}/scripts/postinstall @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/install/preinstall
        ${CMAKE_BINARY_DIR}/scripts/preinstall COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/install/distribution.plist.in
        ${CMAKE_BINARY_DIR}/distribution.plist @ONLY)

# SET(CPACK_INSTALL_SCRIPT ${CMAKE_SOURCE_DIR}/install/osx_packaging.sh)
#        set_target_properties(${PROJECT_NAME} PROPERTIES
#                MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/CMake/Info.plist.in)
SET(CPACK_BUNDLE_PLIST "${CMAKE_BINARY_DIR}/Info.plist")

add_custom_target(bundle DEPENDS typtop)
add_custom_command(TARGET bundle POST_BUILD
        COMMAND bash ${CMAKE_SOURCE_DIR}/install/osx_packaging.sh ${CPACK_PACKAGE_FILE_NAME}.tar.gz scripts
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${PROJECT_NAME})

INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/prerm DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.prerm)
INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/postinstall DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.postinst)
