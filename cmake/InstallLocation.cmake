# Some default installation locations. These should be global, with any project
# specific locations added to the end. These paths are all relative to the
# install prefix.
#
# These paths attempt to adhere to the FHS, and are similar to those provided
# by autotools and used in many Linux distributions.
#
# Use GNU install directories
include(GNUInstallDirs)
if(NOT INSTALL_RUNTIME_DIR)
  set(INSTALL_RUNTIME_DIR "${CMAKE_INSTALL_BINDIR}")
endif()
if(NOT INSTALL_LIBRARY_DIR)
  set(INSTALL_LIBRARY_DIR "${CMAKE_INSTALL_LIBDIR}")
endif()
if(NOT INSTALL_ARCHIVE_DIR)
  set(INSTALL_ARCHIVE_DIR "${CMAKE_INSTALL_LIBDIR}")
endif()
if(NOT INSTALL_INCLUDE_DIR)
  set(INSTALL_INCLUDE_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
endif()
if(NOT INSTALL_DATA_DIR)
  set(INSTALL_DATA_DIR "${CMAKE_INSTALL_DATAROOTDIR}")
endif()
if(NOT INSTALL_DOC_DIR)
  set(INSTALL_DOC_DIR "${CMAKE_INSTALL_DOCDIR}")
endif()
if(NOT INSTALL_MAN_DIR)
  set(INSTALL_DOC_DIR "${CMAKE_INSTALL_MANDIR}")
endif()

# Set up RPATH for the project too.
option(ENABLE_RPATH "Enable rpath support on Linux and Mac" ON)
if(NOT CMAKE_INSTALL_RPATH)
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${INSTALL_LIBRARY_DIR}")
endif()
if(UNIX AND ENABLE_RPATH)
  set(CMAKE_SKIP_BUILD_RPATH FALSE)
  set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()
