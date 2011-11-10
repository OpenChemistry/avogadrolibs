cmake_minimum_required(VERSION 2.8)

project(MolCore)

add_subdirectory(src)

option(ENABLE_TESTING "Enable testing and building the tests." OFF)

if(ENABLE_TESTING)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()
