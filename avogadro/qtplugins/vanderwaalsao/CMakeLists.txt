avogadro_plugin(VanDerWaalsAO
  "Van der Waals rendering scheme with ambient occlusion"
  ScenePlugin
  vanderwaalsao.h
  VanDerWaalsAO
  vanderwaalsao.cpp
  "")

target_link_libraries(VanDerWaalsAO PRIVATE AvogadroRendering)
