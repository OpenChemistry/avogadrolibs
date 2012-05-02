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
  set(INSTALL_DOC_DIR "doc")
endif()
