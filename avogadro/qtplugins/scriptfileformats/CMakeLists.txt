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

target_link_libraries(ScriptFileFormats PRIVATE Avogadro::QuantumIO)
