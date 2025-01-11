set(openbabel_srcs
  conformersearchdialog.cpp
  obcharges.cpp
  obfileformat.cpp
  obforcefielddialog.cpp
  obprocess.cpp
  openbabel.cpp
)

set(openbabel_uis
  conformersearchdialog.ui
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

target_link_libraries(OpenBabel PRIVATE Avogadro::IO Avogadro::Calc nlohmann_json::nlohmann_json)
