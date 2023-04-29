avogadro_plugin(PLY
  "Render the scene using PLY."
  ExtensionPlugin
  ply.h
  PLY
  "ply.cpp"
  ""
)

target_link_libraries(PLY PRIVATE Avogadro::Rendering)
