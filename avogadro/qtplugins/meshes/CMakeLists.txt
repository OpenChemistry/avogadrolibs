avogadro_plugin(Meshes
  "Mesh rendering"
  ScenePlugin
  meshes.h
  Meshes
  meshes.cpp
  "")

target_link_libraries(Meshes PRIVATE AvogadroRendering)
