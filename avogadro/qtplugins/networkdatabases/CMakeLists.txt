set(srcs
  networkdatabases.cpp
)

avogadro_plugin(NetworkDatabases
  "Network databases"
  ExtensionPlugin
  networkdatabases.h
  NetworkDatabases
  "${srcs}"
  ""
)

target_link_libraries(NetworkDatabases
  PRIVATE AvogadroIO ${Qt5Network_LIBRARIES})
