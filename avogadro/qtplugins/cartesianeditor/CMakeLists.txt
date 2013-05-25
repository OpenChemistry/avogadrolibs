include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(CartesianEditor
  "Show a window with a free-text cartesian coordinate editor."
  ExtensionPlugin
  cartesianeditor.h
  CartesianEditor
  "cartesianeditor.cpp;cartesianeditordialog.cpp;cartesiantextedit.cpp"
  "cartesianeditordialog.ui"
)
