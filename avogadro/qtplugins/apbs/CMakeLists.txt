# Pull in MoleQueue (needed for QtJson)
find_package(MoleQueue REQUIRED NO_MODULE)
include_directories(${MoleQueue_INCLUDE_DIRS})

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
  LINK_PRIVATE AvogadroIO AvogadroMoleQueue MoleQueueClient)
