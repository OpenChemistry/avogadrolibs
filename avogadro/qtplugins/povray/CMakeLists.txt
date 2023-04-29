avogadro_plugin(POVRay
  "Render the scene using POV-Ray."
  ExtensionPlugin
  povray.h
  POVRay
  "povray.cpp"
  ""
)

target_link_libraries(POVRay PRIVATE Avogadro::Rendering)
