# Pull in MoleQueue -- just for QtJson right now...
find_package(MoleQueue REQUIRED NO_MODULE)
include_directories(${MoleQueue_INCLUDE_DIRS})

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

target_link_libraries(ScriptFileFormats LINK_PRIVATE AvogadroQuantumIO)

# Bundled format scripts:
set(format_scripts
  formatScripts/zyx.py
  formatScripts/cclibScript.py
)

install(PROGRAMS ${format_scripts}
  DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/formatScripts/")
