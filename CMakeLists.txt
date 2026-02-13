cmake_minimum_required(VERSION 3.24 FATAL_ERROR)

project(AvogadroLibs)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Use C++17 when possible
option(PYTHON_WHEEL_BUILD "Is this a Python wheel build?" OFF)
mark_as_advanced(PYTHON_WHEEL_BUILD)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS False)
# Set symbol visibility defaults for all targets.
set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
set(CMAKE_VISIBILITY_INLINES_HIDDEN True)

include(BuildType)
include(BuildLocation)
include(CompilerFlags)
include(InstallLocation)
include(DetermineVersion)

# Set up our version.
set(AvogadroLibs_VERSION_MAJOR   "1")
set(AvogadroLibs_VERSION_MINOR   "103")
set(AvogadroLibs_VERSION_PATCH   "0")
set(AvogadroLibs_VERSION
  "${AvogadroLibs_VERSION_MAJOR}.${AvogadroLibs_VERSION_MINOR}.${AvogadroLibs_VERSION_PATCH}")
find_package(Git)
determine_version(${AvogadroLibs_SOURCE_DIR} ${GIT_EXECUTABLE} "AvogadroLibs")

# path for data / fragment files which could be overriden by package maintainers
# by default we assume we're using the openchemistry superbuild layout
# .. this is used by the fragment library, molecules, crystals, etc.
set(AvogadroLibs_SOURCEDATA_DIR "${AvogadroLibs_SOURCE_DIR}/..")

option(BUILD_SHARED_LIBS "Build with shared libraries" ON)

# Before any plugins are defined, and before any add_subdirectory calls:
set_property(GLOBAL PROPERTY AvogadroLibs_PLUGINS)
set_property(GLOBAL PROPERTY AvogadroLibs_STATIC_PLUGINS)

if(MSVC)
  add_definitions("-D_CRT_SECURE_NO_WARNINGS" "-DNOMINMAX -D_USE_MATH_DEFINES")
  # Ensure __cplusplus is correct, otherwise it defaults to 199711L which isn't true
  # https://docs.microsoft.com/en-us/cpp/build/reference/zc-cplusplus?view=msvc-160
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zc:__cplusplus")

  message(STATUS "Setting MSVC debug information format to 'Embedded'")
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>")

  set(CMAKE_VS_GLOBALS
    "UseMultiToolTask=true"
    "DebugInformationFormat=OldStyle"
  )
endif()

option(ENABLE_TESTING "Enable testing and building the tests." OFF)
option(TEST_QTGL "Build the Qt OpenGL test application" OFF)
option(USE_OPENGL "Enable libraries that use OpenGL" ON)
option(USE_HDF5 "Enable optional HDF5 features" OFF)
option(USE_QT "Enable libraries that use Qt 6" ON)
option(USE_VTK "Enable libraries that use VTK" OFF)
option(USE_LIBARCHIVE "Enable optional Libarchive features" ON)
option(USE_LIBMSYM "Enable optional features using libmsym" ON)
option(USE_SPGLIB "Enable optional features using spglib" ON)
option(USE_PLOTTER "Enable JKQTPlotter for charts and spectra" ON)
option(USE_MMTF "Enable optional features using mmtf" OFF) # MMTF is no longer maintained
option(USE_PYTHON "Use Python to wrap some of our API" OFF)
option(USE_EXTERNAL_NLOHMANN "Use an externally-provided version of the nlohmann JSON library" OFF)
option(USE_EXTERNAL_PUGIXML "Use an externally-provided version of pugixml" OFF)
option(USE_EXTERNAL_STRUCT "Use an externally-provided version of the struct binary data formatting library" OFF)
option(USE_EXTERNAL_TOMLPLUSPLUS "Use an externally-provided version of tomlplusplus" OFF)
set(QT_VERSION "6" CACHE STRING "What major version of Qt")
set(QT_VERSIONS_SUPPORTED 6)
set_property(CACHE QT_VERSION PROPERTY STRINGS 6)
if(NOT QT_VERSION IN_LIST QT_VERSIONS_SUPPORTED)
  message(FATAL_ERROR "Qt version must be one of ${QT_VERSIONS_SUPPORTED}")
endif()

add_subdirectory(thirdparty)
add_subdirectory(utilities)
add_subdirectory(avogadro)

if(ENABLE_TESTING)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

option(BUILD_DOCUMENTATION "Build project documentation" OFF)

if(BUILD_DOCUMENTATION)
  add_subdirectory(docs)
endif()

if(USE_PYTHON)
  add_subdirectory(python)
endif()

# SKBUILD is set for binary wheel
if (NOT SKBUILD)
  install(
    FILES
      README.md
      CONTRIBUTING.md
      LICENSE
    DESTINATION "${INSTALL_DOC_DIR}/avogadrolibs")
endif()

# After all add_subdirectory calls, so the list of plugins is complete:
get_property(AvogadroLibs_PLUGINS GLOBAL PROPERTY AvogadroLibs_PLUGINS)
get_property(AvogadroLibs_STATIC_PLUGINS GLOBAL
  PROPERTY AvogadroLibs_STATIC_PLUGINS)

configure_file(${AvogadroLibs_SOURCE_DIR}/cmake/CTestCustom.cmake.in
  ${AvogadroLibs_BINARY_DIR}/CTestCustom.cmake)

configure_file("${AvogadroLibs_SOURCE_DIR}/cmake/AvogadroLibsConfig.cmake.in"
  "${AvogadroLibs_BINARY_DIR}/AvogadroLibsConfig.cmake" @ONLY)
configure_file("${AvogadroLibs_SOURCE_DIR}/cmake/AvogadroLibsConfigVersion.cmake.in"
  "${AvogadroLibs_BINARY_DIR}/AvogadroLibsConfigVersion.cmake" @ONLY)

# SKBUILD is set for binary wheel
if (NOT SKBUILD)
  install(FILES
    "${AvogadroLibs_BINARY_DIR}/AvogadroLibsConfig.cmake"
    "${AvogadroLibs_BINARY_DIR}/AvogadroLibsConfigVersion.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Findlibmsym.cmake"
    DESTINATION "${INSTALL_LIBRARY_DIR}/cmake/avogadrolibs")
  install(EXPORT "AvogadroLibsTargets"
    NAMESPACE Avogadro::
    DESTINATION "${INSTALL_LIBRARY_DIR}/cmake/avogadrolibs")
endif()
