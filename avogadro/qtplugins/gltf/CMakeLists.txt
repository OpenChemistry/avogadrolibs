avogadro_plugin(GLTF
  "Export the scene as a glTF binary (.glb) file."
  ExtensionPlugin
  gltf.h
  GLTF
  "gltf.cpp"
  ""
)

target_link_libraries(GLTF PRIVATE Avogadro::Rendering)
