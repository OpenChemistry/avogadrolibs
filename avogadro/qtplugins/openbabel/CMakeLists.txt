include_directories("${AvogadroLibs_SOURCE_DIR}/thirdparty")

set(openbabel_srcs
  obfileformat.cpp
  obforcefielddialog.cpp
  obprocess.cpp
  openbabel.cpp
)

set(openbabel_uis
  obforcefielddialog.ui
)

avogadro_plugin(OpenBabel
  "OpenBabel extension"
  ExtensionPlugin
  openbabel.h
  OpenBabel
  "${openbabel_srcs}"
  "${openbabel_uis}"
)

target_link_libraries(OpenBabel PRIVATE AvogadroIO)
