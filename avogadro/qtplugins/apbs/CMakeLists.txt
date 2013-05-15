set(apbs_srcs
  apbs.cpp
  opendxreader.cpp
  pdb2pqr.cpp
)

avogadro_plugin(apbs
  "APBS Extension"
  ExtensionPlugin
  apbs.h
  Apbs
  "${apbs_srcs}"
  pdb2pqr.ui
)

target_link_libraries(apbs LINK_PRIVATE AvogadroIO)
