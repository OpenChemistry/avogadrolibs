avogadro_plugin(Meshes
  "Surface and mesh rendering"
  ScenePlugin
  meshes.h
  Meshes
  meshes.cpp
  "")

target_link_libraries(Meshes PRIVATE Avogadro::Rendering)
