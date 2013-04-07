# Some default installation locations. These should be global, with any project
# specific locations added to the end. These paths are all relative to the
# install prefix.
#
# These paths attempt to adhere to the FHS, and are similar to those provided
# by autotools and used in many Linux distributions.
if(NOT INSTALL_RUNTIME_DIR)
  set(INSTALL_RUNTIME_DIR "bin")
endif()
if(NOT INSTALL_LIBRARY_DIR)
  set(INSTALL_LIBRARY_DIR "lib")
endif()
if(NOT INSTALL_ARCHIVE_DIR)
  set(INSTALL_ARCHIVE_DIR "lib")
endif()
if(NOT INSTALL_INCLUDE_DIR)
  set(INSTALL_INCLUDE_DIR "include")
endif()
if(NOT INSTALL_DATA_DIR)
  set(INSTALL_DATA_DIR "share")
endif()
if(NOT INSTALL_DOC_DIR)
  set(INSTALL_DOC_DIR "${INSTALL_DATA_DIR}/doc")
endif()

# Set up RPATH for the project too.
option(ENABLE_RPATH "Enable rpath support on Linux and Mac" ON)
if(UNIX AND ENABLE_RPATH)
  set(CMAKE_SKIP_BUILD_RPATH FALSE)
  set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()
