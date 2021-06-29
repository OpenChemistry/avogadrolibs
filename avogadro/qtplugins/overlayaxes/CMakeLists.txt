# Temporarily copied from Avogadro::Rendering until we can fully encapsulate
# OpenGL/GLEW calls:
find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

avogadro_plugin(OverlayAxes
  "Reference Axes Overlay"
  ExtensionPlugin
  overlayaxes.h
  OverlayAxes
  overlayaxes.cpp
  "")

target_link_libraries(OverlayAxes PRIVATE AvogadroRendering)
