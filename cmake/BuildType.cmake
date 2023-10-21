# Set a default build type if none was specified
set(_build_type "Release")
if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
  set(_build_type "Debug")
endif()
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE ${_build_type}
      CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo" "ASAN" "TSAN" "MSAN" "LSAN" "UBSAN")
endif()
