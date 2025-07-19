include(ExternalProject)

avogadro_plugin(InsertFragment
  "Insert molecular fragments and crystals."
  ExtensionPlugin
  insertfragment.h
  InsertFragment
  insertfragment.cpp
)

# Install the fragments & crystals
# TODO - make this a for loop
set(_molecules "${AvogadroLibs_SOURCEDATA_DIR}/molecules")
set(_crystals "${AvogadroLibs_SOURCEDATA_DIR}/crystals")

# Look in parallel directory for the molecule fragment repository
if(NOT EXISTS "${_molecules}")
# download molecules...
ExternalProject_Add(molecules
    GIT_REPOSITORY https://github.com/openchemistry/molecules
    # or https://github.com/OpenChemistry/molecules/archive/refs/heads/master.zip
    SOURCE_DIR "${AvogadroLibs_SOURCEDATA_DIR}/molecules"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
endif()

install(DIRECTORY "${AvogadroLibs_SOURCEDATA_DIR}/molecules"
  DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
  PATTERN ".git" EXCLUDE
)

# crystals
if(NOT EXISTS "${_crystals}")
# download molecules...
ExternalProject_Add(crystals
    GIT_REPOSITORY https://github.com/openchemistry/crystals
    # or https://github.com/OpenChemistry/crystals/archive/refs/heads/master.zip
    SOURCE_DIR "${AvogadroLibs_SOURCEDATA_DIR}/crystals"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
endif()

install(DIRECTORY "${AvogadroLibs_SOURCEDATA_DIR}/crystals"
DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
PATTERN ".git" EXCLUDE
)
