cmake_minimum_required(VERSION 3.24)
project(AvogadroWebGLTests LANGUAGES CXX)

if(NOT EMSCRIPTEN)
  message(FATAL_ERROR "Configure these tests with the Emscripten toolchain")
endif()
find_package(AvogadroLibs REQUIRED)
find_package(Eigen3 REQUIRED)

add_executable(WebGLInputTest inputtest.cpp)
target_compile_features(WebGLInputTest PRIVATE cxx_std_17)
target_compile_options(WebGLInputTest PRIVATE -pthread)
target_link_options(WebGLInputTest PRIVATE -pthread "-sNODERAWFS=1" "-sENVIRONMENT=node" "-sMAX_WEBGL_VERSION=2")
target_link_libraries(WebGLInputTest PRIVATE Avogadro::Rendering Eigen3::Eigen)

enable_testing()
add_test(NAME WebGL-InputRejection COMMAND WebGLInputTest)
