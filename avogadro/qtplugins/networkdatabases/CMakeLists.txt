find_package(Qt4 COMPONENTS QtNetwork)
include(${QT_USE_FILE})

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

target_link_libraries(NetworkDatabases LINK_PRIVATE AvogadroIO ${QT_LIBRARIES})
