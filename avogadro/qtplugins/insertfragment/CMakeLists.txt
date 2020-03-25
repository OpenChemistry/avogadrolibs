include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(InsertFragment
  "Insert molecular fragments and crystals."
  ExtensionPlugin
  insertfragment.h
  InsertFragment
  "insertfragment.cpp;insertfragmentdialog.cpp;sortfiltertreeproxymodel.cpp"
  "insertfragmentdialog.ui"
)
