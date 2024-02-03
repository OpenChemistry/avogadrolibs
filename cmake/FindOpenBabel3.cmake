# Find the OpenBabel3 library
#
# Defines:
#
#  OpenBabel3_FOUND        - system has OpenBabel
#  OpenBabel3_INCLUDE_DIRS - the OpenBabel include directories
#  OpenBabel3_LIBRARY      - The OpenBabel library
#
find_path(OpenBabel3_INCLUDE_DIR openbabel3/openbabel/babelconfig.h)
if(OPENBABEL3_INCLUDE_DIR)
  set(OPENBABEL3_INCLUDE_DIR ${OPENBABEL3_INCLUDE_DIR}/openbabel3)
endif()
find_library(OpenBabel3_LIBRARY NAMES openbabel openbabel3 openbabel-3)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenBabel3 DEFAULT_MSG OpenBabel3_INCLUDE_DIR
                                 OpenBabel3_LIBRARY)

mark_as_advanced(OpenBabel3_INCLUDE_DIR OpenBabel3_LIBRARY)

if(OpenBabel3_FOUND)
  set(OpenBabel3_INCLUDE_DIRS "${OpenBabel3_INCLUDE_DIR}")

  if(NOT TARGET OpenBabel3)
    add_library(OpenBabel3 SHARED IMPORTED GLOBAL)
    set_target_properties(OpenBabel3 PROPERTIES
      IMPORTED_LOCATION "${OpenBabel3_LIBRARY}"
      IMPORTED_IMPLIB "${OpenBabel3_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${OpenBabel3_INCLUDE_DIR}")
  endif()
endif()
