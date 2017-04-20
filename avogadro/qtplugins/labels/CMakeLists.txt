avogadro_plugin(Labels
  "Labels rendering scheme"
  ScenePlugin
  labels.h
  Labels
  labels.cpp
  "")

target_link_libraries(Labels LINK_PRIVATE AvogadroRendering)
