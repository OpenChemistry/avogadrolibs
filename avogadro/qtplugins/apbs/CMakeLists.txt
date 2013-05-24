set(apbs_srcs
  apbs.cpp
  opendxreader.cpp
)

avogadro_plugin(apbs
  "APBS Extension"
  ExtensionPlugin
  apbs.h
  Apbs
  "${apbs_srcs}"
)

target_link_libraries(apbs LINK_PRIVATE AvogadroIO)
