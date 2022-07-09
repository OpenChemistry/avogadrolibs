include_directories(${CMAKE_CURRENT_BINARY_DIR} "${AvogadroLibs_SOURCE_DIR}/thirdparty")

avogadro_plugin(NucleicInput
  "Insert DNA/RNA sequences."
  ExtensionPlugin
  insertdna.h
  InsertDna
  "insertdna.cpp"
  "insertdnadialog.ui"
)
