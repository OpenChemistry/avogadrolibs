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
  ${pybind11_INCLUDE_DIRS}
  )

set(wrapper_SRCS
  main.cpp
  core.cpp
  io.cpp
  )


set(_python_module_install_dir "avogadro")
# SKBUILD is set for binary wheel
if (NOT SKBUILD)
  set(_python_module_install_dir "${INSTALL_LIBRARY_DIR}/avogadro")
endif()

set(CMAKE_MODULE_LINKER_FLAGS "")
# Core
pybind11_add_module(avogadrocorepython core.cpp)
set_target_properties(avogadrocorepython
  PROPERTIES
    OUTPUT_NAME core)
target_link_libraries(avogadrocorepython
  PRIVATE
    AvogadroCore
    pybind11::module
)

install(TARGETS avogadrocorepython LIBRARY COMPONENT python DESTINATION "${_python_module_install_dir}")

# IO
pybind11_add_module(avogadroiopython io.cpp)
set_target_properties(avogadroiopython
  PROPERTIES
    OUTPUT_NAME io)
target_link_libraries(avogadroiopython
  PRIVATE
    AvogadroIO
    AvogadroQuantumIO
    pybind11::module
)
install(TARGETS avogadroiopython LIBRARY COMPONENT python DESTINATION "${_python_module_install_dir}")

# Set the RPATH so the dependent libraries can be found in the wheel.
if(APPLE)
  set(_rpath_value "@loader_path")
elseif(UNIX)
  set(_rpath_value "$ORIGIN")
endif()

if (NOT WIN32)
  set_target_properties(avogadrocorepython avogadroiopython PROPERTIES
                        INSTALL_RPATH ${_rpath_value})
endif()

install(FILES avogadro/__init__.py  COMPONENT python DESTINATION "${_python_module_install_dir}")

# Set the output directory so the python modules can be used from the build
# tree.
set_target_properties(avogadrocorepython avogadroiopython
  PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/avogadro"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/avogadro"
)
