# Needed to find avogadroioexport.h:
include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/io/")

# Extension
set(forcefield_srcs
  forcefield.cpp
  lennardjones.cpp
)

avogadro_plugin(Forcefield
  "Force field optimization and dynamics"
  ExtensionPlugin
  forcefield.h
  Forcefield
  "${forcefield_srcs}"
)

target_link_libraries(Forcefield LINK_PRIVATE AvogadroIO)

# Bundled forcefield scripts (open babel)
set(forcefields
  scripts/uff.py
  scripts/gaff.py
  scripts/mmff.py
)

install(PROGRAMS ${forcefields}
DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/forcefields/")
