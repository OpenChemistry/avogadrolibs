include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(CopyPaste
  "Interact with the clipboard."
  ExtensionPlugin
  copypaste.h
  CopyPaste
  "copypaste.cpp"
  ""
)

target_link_libraries(CopyPaste PRIVATE AvogadroIO)
