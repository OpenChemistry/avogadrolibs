include_directories("${AvogadroLibs_SOURCE_DIR}/thirdparty/tinycolormap/include")

avogadro_plugin(ApplyColors
  "Extension to apply color schemes to atoms and residues."
  ExtensionPlugin
  applycolors.h
  ApplyColors
  "applycolors.cpp"
  chargedialog.ui
)

target_link_libraries(ApplyColors PRIVATE Avogadro::Calc)
