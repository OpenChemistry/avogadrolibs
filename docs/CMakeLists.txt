find_package(Doxygen REQUIRED)

set(doxygen_source_dirs
  "${AvogadroLibs_SOURCE_DIR}/avogadro ${AvogadroLibs_SOURCE_DIR}/docs")
set(doxygen_output_dir "${CMAKE_CURRENT_BINARY_DIR}")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/doxyfile.in"
  "${CMAKE_CURRENT_BINARY_DIR}/doxyfile")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/conf.py.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/conf.py")

add_custom_target(documentation
  COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_BINARY_DIR}/html
  COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/doxyfile)
