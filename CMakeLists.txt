cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)

project(AvogadroLibs)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(BuildType)
include(BuildLocation)
include(CompilerFlags)
include(InstallLocation)

option(BUILD_SHARED_LIBS "Build with shared libraries" ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_subdirectory(utilities)
add_subdirectory(avogadro)

option(ENABLE_TESTING "Enable testing and building the tests." OFF)

if(ENABLE_TESTING)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

option(BUILD_DOCUMENTATION "Build project documentation" OFF)

if(BUILD_DOCUMENTATION)
  add_subdirectory(docs)
endif()

configure_file(${AvogadroLibs_SOURCE_DIR}/cmake/CTestCustom.cmake.in
	${AvogadroLibs_BINARY_DIR}/CTestCustom.cmake)
