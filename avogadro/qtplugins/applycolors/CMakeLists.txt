include_directories(${CMAKE_CURRENT_BINARY_DIR}
"${AvogadroLibs_SOURCE_DIR}/thirdparty/tinycolormap/include")

avogadro_plugin(ApplyColors
  "Extension to apply color schemes to atoms and residues."
  ExtensionPlugin
  applycolors.h
  ApplyColors
  "applycolors.cpp"
  chargedialog.ui
)

target_link_libraries(ApplyColors PRIVATE AvogadroCalc)
