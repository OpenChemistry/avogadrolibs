# Pull in MoleQueue
find_package(MoleQueue)
include_directories("${MoleQueue_INCLUDE_DIRS}")

# Needed to find avogadroioexport.h:
include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/io/")

# Installed location of the input generators:
set(QUANTUMINPUT_GENERATOR_DIR
  "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/inputGenerators/")
# Same, but for running from the build directory:
set(QUANTUMINPUT_GENERATOR_SOURCE_DIR
  "${AvogadroLibs_SOURCE_DIR}/avogadro/qtplugins/quantuminput/inputGenerators/")

# Make the above variables accessible from the extension:
configure_file(quantuminputconfig.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/quantuminputconfig.h")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Extension
set(quantuminput_srcs
  inputgenerator.cpp
  quantuminputdialog.cpp
  quantuminput.cpp
)

avogadro_plugin(QuantumInput
  "Quantum input file generation"
  ExtensionPlugin
  quantuminput.h
  QuantumInput
  "${quantuminput_srcs}"
  quantuminputdialog.ui
)

target_link_libraries(QuantumInput LINK_PRIVATE AvogadroIO MoleQueueClient)

# Bundled generator scripts
set(inputGenerators
  inputGenerators/nwchem.py
)

install(PROGRAMS ${inputGenerators} DESTINATION "${QUANTUMINPUT_GENERATOR_DIR}")
