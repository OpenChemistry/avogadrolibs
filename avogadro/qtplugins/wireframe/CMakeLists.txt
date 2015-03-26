avogadro_plugin(Wireframe
  "Wireframe rendering scheme"
  ScenePlugin
  wireframe.h
  Wireframe
  wireframe.cpp
  "")

target_link_libraries(Wireframe LINK_PRIVATE AvogadroRendering)
