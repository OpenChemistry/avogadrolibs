include_directories("${AvogadroLibs_SOURCE_DIR}/thirdparty")

avogadro_plugin(NucleicInput
  "Insert DNA/RNA sequences."
  ExtensionPlugin
  insertdna.h
  InsertDna
  "insertdna.cpp"
  "insertdnadialog.ui"
)
