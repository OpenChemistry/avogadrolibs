include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(POVRay
  "Render the scene using POV-Ray."
  ExtensionPlugin
  povray.h
  POVRay
  "povray.cpp"
  ""
)

target_link_libraries(POVRay PRIVATE AvogadroRendering)
