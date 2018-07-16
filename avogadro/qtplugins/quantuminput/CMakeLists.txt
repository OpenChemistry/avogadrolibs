# Pull in MoleQueue
find_package(MoleQueue REQUIRED NO_MODULE)
include_directories(${MoleQueue_INCLUDE_DIRS})

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

target_link_libraries(QuantumInput LINK_PRIVATE AvogadroIO AvogadroMoleQueue)

set(_prefix "${AvogadroLibs_SOURCE_DIR}/../avogadrogenerators")
# Look in parallel directory for the avogadrogenerators repository.
if(EXISTS "${_prefix}/.avogadrogenerators")
  # Bundled generator scripts,
  set(input_generators
    ${_prefix}/apbs.py
    ${_prefix}/dalton.py
    ${_prefix}/gamessuk.py
    ${_prefix}/gaussian.py
    ${_prefix}/molpro.py
    ${_prefix}/mopac.py
    ${_prefix}/nwchem.py
    ${_prefix}/orca.py
    ${_prefix}/qchem.py
    ${_prefix}/terachem.py
  )

  option(INSTALL_TEST_INPUT_GENERATOR
    "Install a dummy input generator that is used to test generator scripts."
    OFF)

  if(INSTALL_TEST_INPUT_GENERATOR)
    list(APPEND input_generators ${_prefix}/inputgeneratortest.py)
  endif()

  install(PROGRAMS ${input_generators}
    DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/inputGenerators/")
else()
  message("Avogadro Generators not found at ${_prefix}!")
endif()
