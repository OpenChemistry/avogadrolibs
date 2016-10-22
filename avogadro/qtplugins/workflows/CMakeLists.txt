# Needed to find avogadroioexport.h:
include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/io/")

# Extension
set(workflow_srcs
  workflow.cpp
)

avogadro_plugin(Workflows
  "Script workflows"
  ExtensionPlugin
  workflow.h
  Workflow
  "${workflow_srcs}"
)

target_link_libraries(Workflows LINK_PRIVATE AvogadroIO)

# Bundled workflow scripts
set(workflows
  scripts/scale.py
)

option(INSTALL_TEST_WORKFLOWS
  "Install a dummy workflow that is to test scripts."
  OFF
)

if(INSTALL_TEST_WORKFLOWS)
  list(APPEND workflows scripts/test.py)
endif()

install(PROGRAMS ${input_generators}
  DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/workflows/")
