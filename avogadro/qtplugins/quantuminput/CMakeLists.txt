# Pull in MoleQueue
find_package(MoleQueue REQUIRED NO_MODULE)
include_directories(${MoleQueue_INCLUDE_DIRS})

# Needed to find avogadroioexport.h:
include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/io/")

# Extension
set(quantuminput_srcs
  generichighlighter.cpp
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
set(input_generators
  inputGenerators/gamessuk.py
  inputGenerators/gaussian.py
  inputGenerators/molpro.py
  inputGenerators/mopac.py
  inputGenerators/nwchem.py
  inputGenerators/qchem.py
  inputGenerators/terachem.py
  inputGenerators/apbs.py
)

# Default shebang lines for interpreted scripts:
# Python 2.x. Default "#!/usr/bin/env python" or python 2.x interpretor in PATH.
set(PYTHON2_EXECUTABLE "/usr/bin/env python")
find_package(PythonInterp 2)
if(PYTHON_EXECUTABLE)
  set(PYTHON2_EXECUTABLE "${PYTHON_EXECUTABLE}")
endif()
set(QUANTUMINPUT_PYTHON2_SHEBANG "#!${PYTHON2_EXECUTABLE}"
  CACHE STRING "Shebang line (e.g. \"#!/usr/bin/...\") for python 2.x scripts.")
mark_as_advanced(QUANTUMINPUT_PYTHON2_SHEBANG)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/quantumpython.h.in"
"namespace Avogadro {
static const char *pythonInterpreterPath = \"${PYTHON2_EXECUTABLE}\";
}
")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/quantumpython.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/quantumpython.h")

# Place input scripts in the same relative path to the build-tree executable
set(configured_script_dir
  "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../lib/avogadro2/scripts/inputGenerators/")
message("Writing configured scripts to ${configured_script_dir}")
# Configure files to set shebangs
set(configured_input_generators)
foreach(script ${input_generators})
  get_filename_component(fname "${script}" NAME)
  set(configured_script
    "${configured_script_dir}/${fname}")
  configure_file("${script}" "${configured_script}" @ONLY)
  list(APPEND configured_input_generators "${configured_script}")
endforeach()

# Installed location of the input generators:
set(QUANTUMINPUT_GENERATOR_DIR
  "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/inputGenerators/")

install(PROGRAMS ${configured_input_generators}
  DESTINATION "${QUANTUMINPUT_GENERATOR_DIR}")
