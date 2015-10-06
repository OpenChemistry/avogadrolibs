find_package(PythonInterp 3 REQUIRED)
find_package(PythonLibs 3 REQUIRED)

# The Linux distros have not made this easy, there seem to be a number of
# decorations used to select Python 3.x. We would prefer the latest Python 3
# available, default to python3, but offer the option to supply your distros
# special suffix if they use one, i.e. Ubuntu uses -py34 for Python 3.4...
if (NOT DEFINED boost_python_suffix)
  set(boost_python_suffix "3")
endif()
find_package(Boost COMPONENTS python${boost_python_suffix})

find_package(Eigen3 REQUIRED)

include_directories(SYSTEM
  ${AvogadroLibs_SOURCE_DIR}
  ${AvogadroLibs_BINARY_DIR}/avogadro/core
  ${AvogadroLibs_BINARY_DIR}/avogadro/io
  ${BOOST_PYTHON_INCLUDES}
  ${PYTHON_INCLUDE_PATH}
  ${EIGEN3_INCLUDE_DIR}
  )

set(wrapper_SRCS
  main.cpp
  core.cpp
  io.cpp
  )

add_library(avogadro-python MODULE ${wrapper_SRCS})
set_target_properties(avogadro-python
  PROPERTIES
    OUTPUT_NAME avogadro2
    PREFIX "")
target_link_libraries(avogadro-python
  AvogadroIO
  ${PYTHON_LIBRARIES}
  ${Boost_LIBRARIES}
  )
