find_package(PythonInterp 3 REQUIRED)
find_package(PythonLibs 3 REQUIRED)
find_package(Boost COMPONENTS python3)

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
