# Find the MMTF library
#
# Defines:
#
#  MMTF_FOUND        - system has MMTF
#  MMTF_INCLUDE_DIRS - the MMTF include directories
#
find_path(MMTF_INCLUDE_DIR mmtf.hpp)

set(MMTF_INCLUDE_DIRS "${MMTF_INCLUDE_DIR}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MMTF DEFAULT_MSG MMTF_INCLUDE_DIR)

mark_as_advanced(MMTF_INCLUDE_DIR)
