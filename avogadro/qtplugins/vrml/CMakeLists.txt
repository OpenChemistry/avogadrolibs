include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(VRML
  "Render the scene using VRML."
  ExtensionPlugin
  vrml.h
  VRML
  "vrml.cpp"
  ""
)

target_link_libraries(VRML PRIVATE AvogadroRendering)
