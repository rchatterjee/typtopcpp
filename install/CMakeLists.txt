# INCLUDE(InstallRequiredSystemLibraries)

SET(CPACK_GENERATOR "DEB;RPM")
SET(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY 0)
SET(CPACK_PACKAGE_CONTACT "Rahul Chatterjee <rahul@cs.cornell.edu>")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TypTop - A smart typo-tolerant password checking system.")
SET(CPACK_PACKAGE_VENDOR "Rahul Chatterjee")

SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
SET(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_WELCOME "${CMAKE_CURRENT_LIST_DIR}/welcome.txt")
# set(CPACK_SOURCE_IGNORE_FILES "/CVS/;/\\.svn/;/\\.git*/;\\.swp$;\\.#;/#;.*~;cscope.*")

SET(CPACK_PACKAGE_VERSION_MAJOR "1")
SET(CPACK_PACKAGE_VERSION_MINOR "0")
SET(CPACK_PACKAGE_VERSION_PATCH "0")

SET(CPACK_SET_DESTDIR "on")
SET(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local/")
# SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
# SET(CPACK_OUTPUT_CONFIG_FILE ${PROJECT_SOURCE_DIR}/install/CPackConfig.cmake)
SET(CPACK_OUTPUT_CONFIG_FILE CPackConfig.cmake)

# Debian details
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
        "${CMAKE_SOURCE_DIR}/install/postinst;${CMAKE_SOURCE_DIR}/install/prerm;")
SET(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)


IF(WIN32)
    # There is a bug in NSI that does not handle full unix paths properly. Make
    # sure there is at least one set of four (4) backlasshes.
    SET(CPACK_PACKAGE_ICON "${CMake_SOURCE_DIR}/Utilities/Release\\\\InstallIcon.bmp")
    SET(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\typtop.exe")
    SET(CPACK_NSIS_DISPLAY_NAME "${CPACK_PACKAGE_INSTALL_DIRECTORY} My Famous Project")
    SET(CPACK_NSIS_HELP_LINK "http:\\\\\\\\www.my-project-home-page.org")
    SET(CPACK_NSIS_URL_INFO_ABOUT "http:\\\\\\\\www.my-personal-home-page.com")
    SET(CPACK_NSIS_CONTACT "me@my-personal-home-page.com")
    SET(CPACK_NSIS_MODIFY_PATH ON)
ELSEIF(UNIX)
    IF(APPLE)
        SET(CPACK_STRIP_FILES "bin/typtop")
        SET(CPACK_SOURCE_STRIP_FILES "")
    ELSE(APPLE)
        MESSAGE(STATUS "CPack for non-osx unix systems")
    ENDIF(APPLE)
ENDIF(WIN32)

SET(CPACK_PACKAGE_EXECUTABLES typtop "TypTop")
