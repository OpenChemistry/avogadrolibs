include(ExternalProject)

avogadro_plugin(InsertPeptide
  "Insert oligopeptide chains"
  ExtensionPlugin
  insertpeptide.h
  InsertPeptide
  insertpeptide.cpp
  insertpeptidedialog.ui
)

# Install the fragments
set(_fragments "${AvogadroLibs_SOURCE_DIR}/../fragments")

# Look in parallel directory for the molecule fragment repository
if(NOT EXISTS "${_fragments}")
# download molecules...
ExternalProject_Add(fragments
    GIT_REPOSITORY https://github.com/openchemistry/fragments 
    GIT_TAG main
    # or https://github.com/OpenChemistry/molecules/archive/refs/heads/master.zip
    SOURCE_DIR "${AvogadroLibs_SOURCE_DIR}/../fragments"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
endif()

install(DIRECTORY "${AvogadroLibs_SOURCE_DIR}/../fragments"
  DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
  PATTERN ".git" EXCLUDE
)
