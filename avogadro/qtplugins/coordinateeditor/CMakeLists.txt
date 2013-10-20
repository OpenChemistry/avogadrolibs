include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(CoordinateEditor
  "Show a window with a free-text coordinate editor."
  ExtensionPlugin
  coordinateeditor.h
  CoordinateEditor
  "coordinateeditor.cpp;coordinateeditordialog.cpp;coordinatetextedit.cpp"
  "coordinateeditordialog.ui"
)
