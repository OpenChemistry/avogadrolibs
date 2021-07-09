set(scriptfileformats_srcs
  scriptfileformats.cpp
  fileformatscript.cpp
)

avogadro_plugin(ScriptFileFormats
  "Scriptable file formats"
  ExtensionPlugin
  scriptfileformats.h
  ScriptFileFormats
  "${scriptfileformats_srcs}"
  ""
)

target_link_libraries(ScriptFileFormats PRIVATE AvogadroQuantumIO)

# Bundled format scripts:
set(format_scripts
  formatScripts/zyx.py
)

install(PROGRAMS ${format_scripts}
  DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/formatScripts/")
