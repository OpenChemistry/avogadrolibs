set(forcefield_srcs
  forcefield.cpp
  obmmenergy.cpp
  scriptenergy.cpp
)

avogadro_plugin(Forcefield
  "Force field optimization and dynamics"
  ExtensionPlugin
  forcefield.h
  Forcefield
  "${forcefield_srcs}"
)

target_link_libraries(Forcefield PRIVATE Avogadro::Calc)

# Bundled forcefield scripts
set(forcefields
  scripts/gfn1.py
  scripts/gfn2.py
  scripts/gfnff.py
)

install(PROGRAMS ${forcefields}
DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/energy/")
