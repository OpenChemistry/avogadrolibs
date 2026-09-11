avogadro_plugin(ZMatrixEditor
  "Edit internal (z-matrix) coordinates in a table."
  ExtensionPlugin
  zmatrixeditor.h
  ZMatrixEditor
  "zmatrixeditor.cpp;zmatrixmodel.cpp;zmatrixview.cpp"
)

target_link_libraries(ZMatrixEditor PRIVATE Avogadro::QtGui)
