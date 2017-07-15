find_package(PythonInterp 3 REQUIRED)
find_package(PythonLibs 3 REQUIRED)
set(PYBIND11_PYTHON_VERSION "3" CACHE STRING "")
set(PYBIND11_CPP_STANDARD "-std=c++11" CACHE STRING "")
find_package(pybind11 REQUIRED)

find_package(Eigen3 REQUIRED)

include_directories(SYSTEM
  ${AvogadroLibs_SOURCE_DIR}
  ${AvogadroLibs_BINARY_DIR}/avogadro/core
  ${AvogadroLibs_BINARY_DIR}/avogadro/io
  ${AvogadroLibs_BINARY_DIR}/avogadro/quantumio
  ${PYTHON_INCLUDE_PATH}
  ${EIGEN3_INCLUDE_DIR}
  )

set(wrapper_SRCS
  main.cpp
  core.cpp
  io.cpp
  )

add_library(avogadropython MODULE ${wrapper_SRCS})
set_target_properties(avogadropython
  PROPERTIES
    OUTPUT_NAME avogadro2
    PREFIX "")
target_link_libraries(avogadropython
  PRIVATE
    AvogadroIO
    AvogadroQuantumIO
    pybind11::module
    ${PYTHON_LIBRARIES}
  )
