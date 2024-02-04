set(forcefield_srcs
  forcefield.cpp
  forcefielddialog.cpp
  obmmenergy.cpp
  scriptenergy.cpp
)

if (BUILD_GPL_PLUGINS)
  find_package(OpenBabel3)
  if (OpenBabel3_LIBRARY)
    list(APPEND forcefield_srcs
      obenergy.cpp
    )
    add_definitions(-DBUILD_GPL_PLUGINS)
    include_directories(${OpenBabel3_INCLUDE_DIRS} ${OpenBabel3_INCLUDE_DIR}
    ${AvogadroLibs_BINARY_DIR}/../prefix/include/openbabel3)
  endif()
endif()

avogadro_plugin(Forcefield
  "Force field optimization and dynamics"
  ExtensionPlugin
  forcefield.h
  Forcefield
  "${forcefield_srcs}"
  forcefielddialog.ui
)

target_link_libraries(Forcefield PRIVATE Avogadro::Calc)

if (BUILD_GPL_PLUGINS AND OpenBabel3_LIBRARY)
  target_link_libraries(Forcefield PRIVATE OpenBabel3)
endif()

# Bundled forcefield scripts
set(forcefields
  scripts/ani2x.py
  scripts/gfn1.py
  scripts/gfn2.py
  scripts/gfnff.py
)

if (NOT BUILD_GPL_PLUGINS)
  # install the OB / Pybel forcefield scripts
  list(APPEND forcefields
    scripts/gaff.py
    scripts/mmff94.py
    scripts/uff.py
  )
endif()

install(PROGRAMS ${forcefields}
DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/energy/")
