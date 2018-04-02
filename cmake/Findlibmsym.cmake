# Find the libmsym library
#
# Defines:
#
#  LIBMSYM_FOUND        - system has LIBMSYM
#  LIBMSYM_INCLUDE_DIRS - the LIBMSYM include directories
#  LIBMSYM_LIBRARIES    - The LIBMSYM library
#
find_path(LIBMSYM_INCLUDE_DIR libmsym/msym.h)
find_library(LIBMSYM_LIBRARY NAMES libmsym)

set(LIBMSYM_INCLUDE_DIRS "${LIBMSYM_INCLUDE_DIR}")
set(LIBMSYM_LIBRARIES "${LIBMSYM_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBMSYM DEFAULT_MSG LIBMSYM_INCLUDE_DIR
                                  LIBMSYM_LIBRARY)

mark_as_advanced(LIBMSYM_INCLUDE_DIR LIBMSYM_LIBRARY)
