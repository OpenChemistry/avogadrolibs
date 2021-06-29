avogadro_plugin(Licorice
  "Licorice rendering scheme"
  ScenePlugin
  licorice.h
  Licorice
  licorice.cpp
  "")

target_link_libraries(Licorice PRIVATE AvogadroRendering)
