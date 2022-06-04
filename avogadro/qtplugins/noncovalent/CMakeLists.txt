avogadro_plugin(NonCovalent
  "Non-covalent interaction rendering, including hydrogen bonds"
  ScenePlugin
  noncovalent.h
  NonCovalent
  noncovalent.cpp
  "")

target_link_libraries(NonCovalent PRIVATE AvogadroRendering)
