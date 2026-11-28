# Downstream smoke test for the headless WebAssembly build. This is a
# standalone project: configure it with emcmake against an installed
# AvogadroLibs (-DCMAKE_PREFIX_PATH=<prefix>) and run the result under node.
cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(AvogadroWasmSmoke LANGUAGES CXX)

find_package(AvogadroLibs REQUIRED)

add_executable(smoke smoke.cpp)
target_compile_features(smoke PRIVATE cxx_std_17)
target_link_libraries(smoke PRIVATE Avogadro::Calc Avogadro::IO Avogadro::Core)
# node can run the generated module directly
set_target_properties(smoke PROPERTIES SUFFIX ".js")
