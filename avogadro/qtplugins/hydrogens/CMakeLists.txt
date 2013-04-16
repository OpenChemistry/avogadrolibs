include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(Hydrogens
  "Extension that adds/removes hydrogens on a molecule."
  ExtensionPlugin
  hydrogens.h
  Hydrogens
  "hydrogens.cpp"
  ""
)
