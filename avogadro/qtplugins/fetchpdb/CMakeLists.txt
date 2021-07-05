set(srcs
  fetchpdb.cpp
)

avogadro_plugin(FetchPDB
  "Fetch PDB"
  ExtensionPlugin
  fetchpdb.h
  FetchPDB
  "${srcs}"
  ""
)

target_link_libraries(FetchPDB
  PRIVATE AvogadroIO ${Qt5Network_LIBRARIES})
