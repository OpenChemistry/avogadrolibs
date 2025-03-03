avogadro_plugin(Volumes
  "Volume rendering"
  ScenePlugin
  volumes.h
  Volumes
  volumes.cpp
  "")

target_link_libraries(Volumes PRIVATE Avogadro::Rendering)
