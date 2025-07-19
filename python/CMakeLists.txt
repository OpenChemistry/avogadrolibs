cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

if (NOT TARGET Avogadro::Core)
  find_package(AvogadroLibs REQUIRED)
endif()
find_package(Python COMPONENTS Interpreter Development)
set(PYBIND11_PYTHON_VERSION "3" CACHE STRING "")
set(PYBIND11_CPP_STANDARD "-std=c++17" CACHE STRING "")
find_package(pybind11 REQUIRED)

set(wrapper_SRCS
  main.cpp
  core.cpp
  io.cpp
  )

set(_python_module_install_dir "avogadro")
# SKBUILD is set for binary wheel
if (NOT SKBUILD)
  set(_python_module_install_dir "${Python_SITEARCH}/avogadro")
endif()

set(CMAKE_MODULE_LINKER_FLAGS "")
# Core
pybind11_add_module(avogadrocorepython core.cpp)
set_target_properties(avogadrocorepython
  PROPERTIES
    OUTPUT_NAME core)
target_link_libraries(avogadrocorepython
  PRIVATE
    Avogadro::Core
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
    Avogadro::IO
    Avogadro::QuantumIO
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

# Install the python files.
FILE(GLOB PY_SRCS "avogadro/*.py")
install(FILES ${PY_SRCS} COMPONENT python DESTINATION "${_python_module_install_dir}")

# Set the output directory so the python modules can be used from the build
# tree.
set_target_properties(avogadrocorepython avogadroiopython
  PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/avogadro"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/avogadro"
)
