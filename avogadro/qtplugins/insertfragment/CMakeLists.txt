include(ExternalProject)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(InsertFragment
  "Insert molecular fragments and crystals."
  ExtensionPlugin
  insertfragment.h
  InsertFragment
  "insertfragment.cpp;insertfragmentdialog.cpp;sortfiltertreeproxymodel.cpp"
  "insertfragmentdialog.ui"
)

# Install the fragments & crystals
# TODO - make this a for loop
set(_molecules "${AvogadroLibs_SOURCE_DIR}/../molecules")
set(_crystals "${AvogadroLibs_SOURCE_DIR}/../crystals")

# Look in parallel directory for the molecule fragment repository
if(NOT EXISTS "${_molecules}")
# download molecules...
ExternalProject_Add(molecules
    GIT_REPOSITORY https://github.com/openchemistry/molecules
    # or https://github.com/OpenChemistry/molecules/archive/refs/heads/master.zip
    SOURCE_DIR "${AvogadroLibs_SOURCE_DIR}/../molecules"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
endif()

install(DIRECTORY "${AvogadroLibs_SOURCE_DIR}/../molecules"
  DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
  PATTERN ".git" EXCLUDE
)

# crystals
if(NOT EXISTS "${_crystals}")
# download molecules... 
ExternalProject_Add(crystals
    GIT_REPOSITORY https://github.com/openchemistry/crystals
    # or https://github.com/OpenChemistry/crystals/archive/refs/heads/master.zip
    SOURCE_DIR "${AvogadroLibs_SOURCE_DIR}/../crystals"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
endif()

install(DIRECTORY "${AvogadroLibs_SOURCE_DIR}/../crystals"
DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
PATTERN ".git" EXCLUDE
)
