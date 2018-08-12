set(surfaces_srcs
  bitvector.cpp
  edtsurface.cpp
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
  LINK_PRIVATE AvogadroQuantumIO ${Qt5Concurrent_LIBRARIES})
