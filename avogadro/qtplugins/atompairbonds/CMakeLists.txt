avogadro_plugin(AtomPairBonds
  "Atom-pair bond rendering, including hydrogen bonds"
  ScenePlugin
  atompairbonds.h
  AtomPairBonds
  atompairbonds.cpp
  "")

target_link_libraries(AtomPairBonds PRIVATE AvogadroRendering)
