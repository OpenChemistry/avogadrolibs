# Find the LIBARCHIVE library
#
# Defines:
#
#  LIBARCHIVE_FOUND        - system has LIBARCHIVE
#  LIBARCHIVE_INCLUDE_DIRS - the LIBARCHIVE include directories
#  LIBARCHIVE_LIBRARIES    - The LIBARCHIVE library
#
find_path(LIBARCHIVE_INCLUDE_DIR archive.h)
# libarchive/archive_entry.h)
find_library(LIBARCHIVE_LIBRARY NAMES archive)

set(LIBARCHIVE_INCLUDE_DIRS "${LIBARCHIVE_INCLUDE_DIR}")
set(LIBARCHIVE_LIBRARIES "${LIBARCHIVE_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBARCHIVE DEFAULT_MSG LIBARCHIVE_INCLUDE_DIR
                                  LIBARCHIVE_LIBRARY)

mark_as_advanced(LIBARCHIVE_INCLUDE_DIR LIBARCHIVE_LIBRARY)
