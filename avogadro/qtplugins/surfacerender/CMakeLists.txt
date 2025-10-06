avogadro_plugin(SurfaceRender
  "Surface and mesh rendering"
  ScenePlugin
  surfacerender.h
  SurfaceRender
  surfacerender.cpp
  "")

target_link_libraries(SurfaceRender PRIVATE Avogadro::Rendering)
