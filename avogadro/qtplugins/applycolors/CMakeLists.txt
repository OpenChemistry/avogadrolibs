include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(ApplyColors
  "Extension to apply color schemes to atoms and residues."
  ExtensionPlugin
  applycolors.h
  ApplyColors
  "applycolors.cpp"
  ""
)
