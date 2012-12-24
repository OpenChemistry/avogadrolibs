include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(MolecularProperties
  "Show a window with basic molecular properties."
  ExtensionPlugin
  molecularproperties.h
  MolecularProperties
  "molecularproperties.cpp;molecularpropertiesdialog.cpp"
  "molecularpropertiesdialog.ui"
)
