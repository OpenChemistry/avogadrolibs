
avogadro_plugin(Label
  "Labels rendering scheme"
  ScenePlugin
  label.h
  Label
  label.cpp
  "")


target_link_libraries(Label LINK_PRIVATE AvogadroRendering)
