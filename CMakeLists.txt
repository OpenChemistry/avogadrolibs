cmake_minimum_required(VERSION 2.8.4 FATAL_ERROR)

project(MolCore)

set(CMAKE_MODULE_PATH ${MolCore_SOURCE_DIR}/cmake)

include(BuildType)
include(BuildLocation)
include(CompilerFlags)

add_subdirectory(src)

option(ENABLE_TESTING "Enable testing and building the tests." OFF)

if(ENABLE_TESTING)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

configure_file(${MolCore_SOURCE_DIR}/cmake/CTestCustom.cmake.in
  ${MolCore_BINARY_DIR}/CTestCustom.cmake)
