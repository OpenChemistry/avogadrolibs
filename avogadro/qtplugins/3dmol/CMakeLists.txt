include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(ThreeDMol
  "The 3DMol HTML Block Generator"
  ExtensionPlugin
  3dmol.h
  ThreeDMol
  "3dmol.cpp;3dmoldialog.cpp"
  "3dmoldialog.ui"
)
