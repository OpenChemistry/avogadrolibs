include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty/libgwavi"
  "${AvogadroLibs_SOURCE_DIR}/thirdparty/gif-h")

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
    AvogadroQuantumIO
    AvogadroQtOpenGL
    Qt5::Concurrent
    gwavi)
