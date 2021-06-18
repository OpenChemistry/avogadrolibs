avogadro_plugin(BallStick
  "Ball and stick rendering scheme"
  ScenePlugin
  ballandstick.h
  BallAndStick
  ballandstick.cpp
  "")

target_link_libraries(BallStick PRIVATE AvogadroRendering)
