# Needed to find avogadroioexport.h:
include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/io/")

# Extension
set(quantuminput_srcs
  quantuminput.cpp
)

avogadro_plugin(QuantumInput
  "Quantum input file generation"
  ExtensionPlugin
  quantuminput.h
  QuantumInput
  "${quantuminput_srcs}"
)

target_link_libraries(QuantumInput PRIVATE AvogadroIO AvogadroMoleQueue)

set(_prefix "${AvogadroLibs_SOURCE_DIR}/../avogadrogenerators")
# Look in parallel directory for the avogadrogenerators repository.
if(EXISTS "${_prefix}/generators.cmake")
  # Bundled generator scripts,
  include("${_prefix}/generators.cmake")
  message("We have ${input_generators}")
  unset(_generators)
  foreach(gen ${input_generators})
    list(APPEND _generators "${_prefix}/${gen}")
  endforeach()
  message("We have ${_generators}")

  option(INSTALL_TEST_INPUT_GENERATOR
    "Install a dummy input generator that is used to test generator scripts."
    OFF)

  if(INSTALL_TEST_INPUT_GENERATOR)
    list(APPEND _generators "${_prefix}/${test_generator}")
  endif()

  install(PROGRAMS ${_generators}
    DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/inputGenerators/")
else()
  message("Avogadro Generators not found at ${_prefix}!")
endif()
