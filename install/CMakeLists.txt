
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

# INCLUDE(InstallRequiredSystemLibraries)
SET(CPACK_GENERATOR "DEB")
SET(CPACK_BUNDLE_NAME ${PROJECT_NAME})

SET(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 1)
SET(CPACK_PACKAGE_CONTACT "Rahul Chatterjee <rahul@cs.cornell.edu>")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TypTop - A smart typo-tolerant password checking system.")
SET(CPACK_PACKAGE_VENDOR "Rahul Chatterjee")

SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
SET(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_WELCOME "${CMAKE_CURRENT_LIST_DIR}/welcome.txt")
set(CPACK_SOURCE_IGNORE_FILES "/cmake-*/;/.svn/;/.git*/;.swp$;.#;/#;.*~;cscope.*")



set(CPACK_PACKAGE_VERSION_MAJOR ${typtop_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${typtop_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${typtop_VERSION_PATCH})
SET(CPACK_PACKAGE_VERSION "${typtop_VERSION_MAJOR}.${typtop_VERSION_MINOR}.${typtop_VERSION_PATCH}")

SET(CPACK_SET_DESTDIR "on")
SET(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local/")
# SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
# SET(CPACK_OUTPUT_CONFIG_FILE ${PROJECT_SOURCE_DIR}/install/CPackConfig.cmake)
SET(CPACK_OUTPUT_CONFIG_FILE CPackConfig.cmake)

SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

IF(WIN32)
    # There is a bug in NSI that does not handle full unix paths properly. Make
    # sure there is at least one set of four (4) backlasshes.
#    SET(CPACK_PACKAGE_ICON "${CMake_SOURCE_DIR}/Utilities/Release\\\\InstallIcon.bmp")
#    SET(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\typtop.exe")
#    SET(CPACK_NSIS_DISPLAY_NAME "${CPACK_PACKAGE_INSTALL_DIRECTORY} My Famous Project")
#    SET(CPACK_NSIS_HELP_LINK "http:\\\\\\\\www.my-project-home-page.org")
#    SET(CPACK_NSIS_URL_INFO_ABOUT "http:\\\\\\\\www.my-personal-home-page.com")
#    SET(CPACK_NSIS_CONTACT "me@my-personal-home-page.com")
#    SET(CPACK_NSIS_MODIFY_PATH ON)
ELSEIF(UNIX)
    IF(APPLE)
        SET(CPACK_GENERATOR "TGZ")
        SET(CPACK_BINARY_PACKAGEMAKER "pkgbuild")
        set( CPACK_POSTFLIGHT_SCRIPT  "${CMAKE_SOURCE_DIR}/install/postinst")
        set( CPACK_POSTUPGRADE_SCRIPT  "${CMAKE_SOURCE_DIR}/install/postinst")
        set( CPACK_OSX_PACKAGE_VERSION, 11.0)
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

        # SET(CPACK_INSTALL_SCRIPT ${CMAKE_SOURCE_DIR}/install/osx_packaging.sh)
#        set_target_properties(${PROJECT_NAME} PROPERTIES
#                MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/CMake/Info.plist.in)
        SET(CPACK_BUNDLE_PLIST "${CMAKE_BINARY_DIR}/Info.plist")

        add_custom_target(bundle DEPENDS typtop)
        add_custom_command(TARGET bundle POST_BUILD
                COMMAND bash ${CMAKE_SOURCE_DIR}/install/osx_packaging.sh ${CPACK_PACKAGE_FILE_NAME}.tar.gz scripts
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                DEPENDS ${PROJECT_NAME})

    ELSE(APPLE)
        MESSAGE(STATUS "CPack for non-osx unix systems")
        # Debian details
        configure_file(${CMAKE_SOURCE_DIR}/install/postinst
                ${CMAKE_BINARY_DIR}/scripts/postinst @ONLY)
        configure_file(${CMAKE_SOURCE_DIR}/install/prerm
                ${CMAKE_BINARY_DIR}/scripts/prerm @ONLY)
        configure_file(${CMAKE_SOURCE_DIR}/install/preinstall
                ${CMAKE_BINARY_DIR}/scripts/preinst COPYONLY)

        set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
                "${CMAKE_BINARY_DIR}/scripts/postinst"
                "${CMAKE_BINARY_DIR}/scripts/prerm"
                "${CMAKE_BINARY_DIR}/scripts/preinst")
            message("${CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA}")
        SET(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
    ENDIF(APPLE)
ENDIF(WIN32)

SET(CPACK_PACKAGE_EXECUTABLES typtop "TypTop")

INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/prerm DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.prerm)
INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/postinstall DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.postinstall)
INSTALL(FILES ${CMAKE_BINARY_DIR}/install_manifest.txt DESTINATION ${INSTALL_DATA_DIR}/typtop.d/)
