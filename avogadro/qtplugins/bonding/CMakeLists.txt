include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(Bonding
  "Perform bonding operations."
  ExtensionPlugin
  bonding.h
  Bonding
  "bonding.cpp"
  "bondingdialog.ui"
)
