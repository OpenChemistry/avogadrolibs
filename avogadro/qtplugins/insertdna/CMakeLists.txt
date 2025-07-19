avogadro_plugin(NucleicInput
  "Insert DNA/RNA sequences."
  ExtensionPlugin
  insertdna.h
  InsertDna
  "insertdna.cpp"
  "insertdnadialog.ui"
)

target_link_libraries(NucleicInput PRIVATE nlohmann_json::nlohmann_json)
