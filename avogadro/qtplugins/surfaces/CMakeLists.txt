if(QT_VERSION EQUAL 6)
  find_package(Qt6 REQUIRED COMPONENTS OpenGL)
endif()

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

if(QT_VERSION EQUAL 6)
  target_link_libraries(Surfaces
    PRIVATE
      Qt6::OpenGL)
endif()
