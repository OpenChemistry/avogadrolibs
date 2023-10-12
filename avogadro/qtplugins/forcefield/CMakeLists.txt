set(forcefield_srcs
  forcefield.cpp
)

avogadro_plugin(Forcefield
  "Force field optimization and dynamics"
  ExtensionPlugin
  forcefield.h
  Forcefield
  "${forcefield_srcs}"
)

target_link_libraries(Forcefield PRIVATE Avogadro::Calc)

# Bundled forcefield scripts (open babel)
set(forcefields
  scripts/uff.py
  scripts/gaff.py
  scripts/mmff.py
)

#install(PROGRAMS ${forcefields}
#DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/forcefields/")
