avogadro_plugin(Cartoons
  "Cartoon family rendering scheme"
  ScenePlugin
  cartoons.h
  Cartoons
  cartoons.cpp
  "")

target_link_libraries(Cartoons LINK_PRIVATE AvogadroRendering)
