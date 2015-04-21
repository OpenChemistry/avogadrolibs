# Find the SymSPG library
#
# Defines:
#
#  SymSGP_FOUND        - system has SymSPG
#  SymSPG_INCLUDE_DIRS - the SymSPG include directories
#  SymSPG_LIBRARY      - The SymSPG library
#
find_path(SymSPG_INCLUDE_DIR spglib/spglib.h)
find_library(SymSPG_LIBRARY NAMES SymSPG symspg)

set(SymSPG_INCLUDE_DIRS "${GLEW_INCLUDE_DIR}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SymSPG DEFAULT_MSG SymSPG_INCLUDE_DIR SymSPG_LIBRARY)

mark_as_advanced(SymSPG_INCLUDE_DIR SymSPG_LIBRARY)
