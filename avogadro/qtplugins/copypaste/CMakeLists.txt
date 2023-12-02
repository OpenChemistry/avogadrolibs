avogadro_plugin(CopyPaste
  "Interact with the clipboard."
  ExtensionPlugin
  copypaste.h
  CopyPaste
  "copypaste.cpp"
  ""
)

target_link_libraries(CopyPaste PRIVATE Avogadro::IO)
