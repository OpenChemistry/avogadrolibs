set(apbs_srcs
  apbs.cpp
  apbsdialog.cpp
  apbsoutputdialog.cpp
  opendxreader.cpp
)

set(apbs_uis
  apbsdialog.ui
  apbsoutputdialog.ui
)

avogadro_plugin(apbs
  "APBS Extension"
  ExtensionPlugin
  apbs.h
  Apbs
  "${apbs_srcs}"
  "${apbs_uis}"
)

target_link_libraries(apbs
  PRIVATE AvogadroIO AvogadroMoleQueue)
