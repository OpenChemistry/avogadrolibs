if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS Gui REQUIRED)
else()
  find_package(Qt5 COMPONENTS Widgets REQUIRED)
endif()

set(forcefield_srcs
  forcefield.cpp
  forcefielddialog.cpp
  obmmenergy.cpp
  scriptenergy.cpp
)

if (BUILD_GPL_PLUGINS)
  find_package(OpenBabel3)
  if (OpenBabel3_LIBRARIES)
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

if(QT_VERSION EQUAL 6)
  target_link_libraries(Forcefield PRIVATE Qt6::Gui)
else()
  target_link_libraries(Forcefield PRIVATE Qt5::Widgets)
endif()

if (BUILD_GPL_PLUGINS AND OpenBabel3_LIBRARIES)
  target_link_libraries(Forcefield PRIVATE OpenBabel3)
endif()

if (NOT BUILD_GPL_PLUGINS)
  # install the OB / Pybel forcefield scripts
  list(APPEND forcefields
    scripts/gaff.py
    scripts/mmff94.py
    scripts/uff.py
  )
endif()

# Don't install any scripts - we'll use these as plugins
