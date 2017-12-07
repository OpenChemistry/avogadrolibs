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

# Bundled generator scripts
set(input_generators
  inputGenerators/apbs.py
  inputGenerators/dalton.py
  inputGenerators/gamessuk.py
  inputGenerators/gaussian.py
  inputGenerators/molpro.py
  inputGenerators/mopac.py
  inputGenerators/nwchem.py
  inputGenerators/qchem.py
  inputGenerators/terachem.py
)

option(INSTALL_TEST_INPUT_GENERATOR
  "Install a dummy input generator that is used to test generator scripts."
  OFF
)

if(INSTALL_TEST_INPUT_GENERATOR)
  list(APPEND input_generators inputGenerators/inputgeneratortest.py)
endif()

install(PROGRAMS ${input_generators}
  DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/inputGenerators/")
