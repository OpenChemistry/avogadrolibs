avogadro_plugin(Dipole
  "Dipole rendering scheme"
  ScenePlugin
  dipole.h
  Dipole
  dipole.cpp
  "")

target_link_libraries(Dipole PRIVATE Avogadro::Calc Avogadro::Rendering)
