avogadro_plugin(OverlayAxes
  "Reference Axes Overlay"
  ScenePlugin
  overlayaxes.h
  OverlayAxes
  overlayaxes.cpp
  "")

target_link_libraries(OverlayAxes AvogadroRendering)
