avogadro_plugin(CrystalLattice
  "Render unit cell lattice."
  ScenePlugin
  crystallattice.h
  CrystalLattice
  crystallattice.cpp)

target_link_libraries(CrystalLattice AvogadroRendering)
