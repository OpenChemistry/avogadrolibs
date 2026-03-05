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

target_link_libraries(QuantumInput PRIVATE Avogadro::IO Avogadro::MoleQueue)

set(_prefix "${AvogadroLibs_SOURCE_DIR}/../avogenerators")
if(EXISTS "${_prefix}")
  install(DIRECTORY "${_prefix}"
    DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/plugins/"
    PATTERN ".git" EXCLUDE
    PATTERN ".pixi" EXCLUDE
    PATTERN "__pycache__" EXCLUDE)
else()
  message("Avogadro Generators not found at ${_prefix}!")
endif()
