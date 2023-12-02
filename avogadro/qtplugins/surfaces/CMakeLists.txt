set(surfaces_srcs
  gaussiansetconcurrent.cpp
  slatersetconcurrent.cpp
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
