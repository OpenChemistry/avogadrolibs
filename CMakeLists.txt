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
set(AvogadroLibs_VERSION_MAJOR   "2")
set(AvogadroLibs_VERSION_MINOR   "0")
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
option(USE_OPENGL "Enable libraries that use OpenGL" ON)
option(USE_HDF5 "Enable optional HDF5 features" OFF)
option(USE_QT "Enable libraries that use Qt 6" ON)
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
option(ENABLE_CALC_BENCHMARKS "Build optional calc benchmark executables" OFF)

# Declared here, not only in tests/, because the libraries are configured
# before tests/ is and they need the definition below. The tests/*/CMakeLists
# files repeat the option() for standalone test builds; whichever runs first
# wins and the value is the same either way.
if(DEFINED ENV{LIB_FUZZING_ENGINE})
  option(ENABLE_FUZZ "Enable fuzz testing." ON)
else()
  option(ENABLE_FUZZ "Enable fuzz testing." OFF)
endif()

# Fuzz builds compile out the exception guard in Io::FileFormat so that an
# exception escaping a parser still reaches libFuzzer as a crash. The name is
# the OSS-Fuzz convention, which OSS-Fuzz itself adds to CXXFLAGS; this is for
# our own ENABLE_FUZZ builds. Must precede add_subdirectory(avogadro).
if(ENABLE_FUZZ OR DEFINED ENV{LIB_FUZZING_ENGINE})
  add_compile_definitions(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)

  # The libraries themselves need SanitizerCoverage, or the fuzz targets run
  # blind: tests/*/CMakeLists.txt puts -fsanitize=fuzzer on the fuzz
  # executable only, which instruments the harness translation unit and
  # nothing else. Every file-format target in the 2026-09-17 nightly showed
  # the symptom -- "Loaded 1 modules (34 inline 8-bit counters)", cov: 10,
  # and a corpus frozen at 3 files after 24 million executions, because no
  # input ever reached instrumented code and so none ever looked new.
  #
  # -no-link because these are libraries: it adds the coverage callbacks
  # without pulling in libFuzzer's main(). OSS-Fuzz already puts this in
  # CFLAGS/CXXFLAGS for the whole build, so only our own builds need it.
  if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      add_compile_options(-fsanitize=fuzzer-no-link)
      # The coverage callbacks the flag inserts are defined by libFuzzer's
      # runtime, which only the fuzz executables link. ELF shared libraries
      # leave such symbols undefined and bind them at load time; Mach-O
      # resolves everything at link time and would fail, so ask for the ELF
      # behaviour. Only needed for local fuzzing on macOS -- CI fuzzes on
      # Linux -- but without it the build simply does not link there.
      if(APPLE AND BUILD_SHARED_LIBS)
        add_link_options(-Wl,-undefined,dynamic_lookup)
      endif()
    else()
      message(FATAL_ERROR
        "ENABLE_FUZZ requires Clang; ${CMAKE_CXX_COMPILER_ID} has no libFuzzer.")
    endif()
  endif()
endif()

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
  # > This command should be invoked in the top-level source directory because
  # > ctest(1) expects to find a test file in the top-level build directory.
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
