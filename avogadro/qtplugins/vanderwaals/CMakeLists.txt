avogadro_plugin(VanDerWaals
  "Van der Waals rendering scheme"
  ScenePlugin
  vanderwaals.h
  VanDerWaals
  vanderwaals.cpp
  "")

target_link_libraries(VanDerWaals PRIVATE AvogadroRendering)
