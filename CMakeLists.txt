cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)

project(LibAvogadro)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(BuildType)
include(BuildLocation)
include(CompilerFlags)

option(BUILD_SHARED_LIBS "Build with shared libraries" ON)

add_subdirectory(avogadro)

option(ENABLE_TESTING "Enable testing and building the tests." OFF)

if(ENABLE_TESTING)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

configure_file(${LibAvogadro_SOURCE_DIR}/cmake/CTestCustom.cmake.in
  ${LibAvogadro_BINARY_DIR}/CTestCustom.cmake)
