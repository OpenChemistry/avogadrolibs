avogadro_plugin(AtomLabels
  "Simple extension to test text rendering."
  ScenePlugin
  atomlabels.h
  AtomLabels
  atomlabels.cpp
  "")

target_link_libraries(AtomLabels AvogadroRendering)
