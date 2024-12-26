if(QT_VERSION EQUAL 6)
  find_package(Qt6 REQUIRED COMPONENTS OpenGL)
endif()

set(surfaces_srcs
  surfacedialog.cpp
  surfaces.cpp
)

avogadro_plugin(Surfaces
  "Surfaces"
  ExtensionPlugin
  surfaces.h
  Surfaces
  "${surfaces_srcs}"
  "surfacedialog.ui"
)

target_link_libraries(Surfaces
  PRIVATE
    Avogadro::Calc
    Avogadro::QuantumIO
    Avogadro::QtOpenGL
    Qt::Concurrent
    gif-h
    gwavi
    tinycolormap)

set(orbitals_srcs
  orbitaltablemodel.cpp
  orbitalwidget.cpp
  orbitals.cpp
)

avogadro_plugin(Orbitals
  "Render Molecular Orbitals"
  ExtensionPlugin
  orbitals.h
  Orbitals
  "${orbitals_srcs}"
  "orbitalwidget.ui"
)

target_link_libraries(Orbitals
  PRIVATE
    Avogadro::QtOpenGL
    Qt::Concurrent)

if(QT_VERSION EQUAL 6)
  target_link_libraries(Surfaces
    PRIVATE
      Qt6::OpenGL)
  target_link_libraries(Orbitals
    PRIVATE
      Qt6::OpenGL)
endif()
