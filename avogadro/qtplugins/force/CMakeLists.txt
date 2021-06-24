avogadro_plugin(Force
  "Force rendering scheme"
  ScenePlugin
  force.h
  Force
  force.cpp
  "")

target_link_libraries(Force PRIVATE AvogadroRendering)
