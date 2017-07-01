set(CPACK_BUNDLE_NAME ${PROJECT_NAME})
set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 1)
set(CPACK_PACKAGE_CONTACT "Rahul Chatterjee <rahul@cs.cornell.edu>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TypTop - A smart typo-tolerant password checking system.")
set(CPACK_PACKAGE_VENDOR "Rahul Chatterjee")

set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/install/welcome.txt")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.html")
set(CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/install/welcome.txt")
set(CPACK_SOURCE_IGNORE_FILES "/cmake-*/;/.svn/;/.git*/;.swp$;.#;/#;.*~;cscope.*")



set(CPACK_PACKAGE_VERSION_MAJOR ${typtop_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${typtop_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${typtop_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION "${typtop_VERSION_MAJOR}.${typtop_VERSION_MINOR}.${typtop_VERSION_PATCH}")

SET(CPACK_SET_DESTDIR "on")
SET(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local/")
# SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
# SET(CPACK_OUTPUT_CONFIG_FILE ${PROJECT_SOURCE_DIR}/install/CPackConfig.cmake)
SET(CPACK_OUTPUT_CONFIG_FILE CPackConfig.cmake)


SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
string(TIMESTAMP TIME_NOW %Y%m%d_%H%M)
SET(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}.${TIME_NOW}")

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
        include(${CMAKE_CURRENT_LIST_DIR}/OSX.cmake)
    ELSE(APPLE)  # Not apple
        MESSAGE(STATUS "CPack for non-osx unix systems")
        # INCLUDE(InstallRequiredSystemLibraries)
        SET(CPACK_GENERATOR "DEB;RPM")
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
        set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
        add_custom_target(bundle DEPENDS typtop)
        add_custom_command(TARGET bundle POST_BUILD
                COMMAND debsigs --sign=origin -k 445E6411 ${CPACK_PACKAGE_FILE_NAME}.deb # No idea what exactly it is doing
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                DEPENDS ${PROJECT_NAME})
        # set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcurl4-openssl-dev")
        # RPM
        # set(CPACK_RPM_PACKAGE_REQUIRES "libcurl4-openssl-devevl")
        set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/preinst")
        set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/postinst")
        set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/prerm")
        set(CPACK_RPM_PACKAGE_LICENSE "${CPACK_RESOURCE_FILE_LICENSE}")
        set(CPACK_RPM_PACKAGE_RELOCATABLE "OFF")

        INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/prerm DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.prerm)
        INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/postinst DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.postinst)
        INSTALL(FILES ${CMAKE_BINARY_DIR}/scripts/preinst DESTINATION ${INSTALL_BIN_DIR}/ RENAME typtop.preinst)
    ENDIF(APPLE)
ENDIF(WIN32)

set(CPACK_PACKAGE_EXECUTABLES typtop "TypTop")

if (EXISTS "${CMAKE_BINARY_DIR}/install_manifest.txt")
    INSTALL(FILES ${CMAKE_BINARY_DIR}/install_manifest.txt DESTINATION ${INSTALL_DATA_DIR}/typtop.d/)
    message(STATUS "INSTALL MAIFEST FOUND @ ${CMAKE_BINARY_DIR}/install_manifest.txt")
endif ()
INSTALL(FILES ${CPACK_RESOURCE_FILE_WELCOME} DESTINATION ${INSTALL_DATA_DIR}/typtop.d/)
