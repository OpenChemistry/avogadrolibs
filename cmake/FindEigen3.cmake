find_path(EIGEN3_INCLUDE_DIR
  NAMES signature_of_eigen3_matrix_library
  PATH_SUFFIXES eigen3 eigen
  DOC "Eigen include directory")
mark_as_advanced(EIGEN3_INCLUDE_DIR)

if (EIGEN3_INCLUDE_DIR)
  file(STRINGS "${EIGEN3_INCLUDE_DIR}/Eigen/src/Core/util/Macros.h" _Eigen3_version_lines
    REGEX "#define[ \t]+EIGEN_(WORLD|MAJOR|MINOR)_VERSION")
  string(REGEX REPLACE ".*EIGEN_WORLD_VERSION *\([0-9]*\).*" "\\1" _Eigen3_version_world "${_Eigen3_version_lines}")
  string(REGEX REPLACE ".*EIGEN_MAJOR_VERSION *\([0-9]*\).*" "\\1" _Eigen3_version_major "${_Eigen3_version_lines}")
  string(REGEX REPLACE ".*EIGEN_MINOR_VERSION *\([0-9]*\).*" "\\1" _Eigen3_version_minor "${_Eigen3_version_lines}")
  set(Eigen3_VERSION "${_Eigen3_version_world}.${_Eigen3_version_major}.${_Eigen3_version_minor}")
  unset(_Eigen3_version_world)
  unset(_Eigen3_version_major)
  unset(_Eigen3_version_minor)
  unset(_Eigen3_version_lines)
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Eigen3
  REQUIRED_VARS EIGEN3_INCLUDE_DIR
  VERSION_VAR EIGEN3_VERSION)

if (Eigen3_FOUND)
  set(Eigen3_INCLUDE_DIRS "${EIGEN3_INCLUDE_DIR}")

  if (NOT TARGET Eigen3::Eigen)
    add_library(Eigen3::Eigen INTERFACE IMPORTED)
    set_target_properties(Eigen3::Eigen PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${EIGEN3_INCLUDE_DIR}")
  endif ()
endif ()
