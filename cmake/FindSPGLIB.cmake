# Find the Spglib library
#
# Defines:
#
#  SPGLIB_FOUND        - system has Spglib
#  SPGLIB_INCLUDE_DIRS - the Spglib include directories
#  SPGLIB_LIBRARY      - The Spglib library
#
find_path(SPGLIB_INCLUDE_DIR spglib.h)
find_library(SPGLIB_LIBRARY NAMES spglib symspg)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SPGLIB DEFAULT_MSG SPGLIB_INCLUDE_DIR
                                  SPGLIB_LIBRARY)

mark_as_advanced(SPGLIB_INCLUDE_DIR SPGLIB_LIBRARY)

if(SPGLIB_FOUND)
  set(SPGLIB_INCLUDE_DIRS "${SPGLIB_INCLUDE_DIR}")

  if(NOT TARGET spglib::spglib)
    add_library(spglib::spglib SHARED IMPORTED GLOBAL)
    set_target_properties(spglib::spglib PROPERTIES
      IMPORTED_LOCATION "${SPGLIB_LIBRARY}"
      IMPORTED_IMPLIB "${SPGLIB_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${SPGLIB_INCLUDE_DIR}")
  endif()
endif()
