find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)

avogadro_plugin(OverlayAxes
  "Reference Axes"
  ScenePlugin
  overlayaxes.h
  OverlayAxes
  overlayaxes.cpp
  "")

target_link_libraries(OverlayAxes
  PRIVATE Avogadro::Rendering Avogadro::QtOpenGL OpenGL::GL GLEW::GLEW)
