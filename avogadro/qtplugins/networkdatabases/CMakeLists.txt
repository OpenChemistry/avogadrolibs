find_package(Qt5Network REQUIRED)
include_directories(SYSTEM ${Qt5Network_INCLUDE_DIRS})
add_definitions(${Qt5Network_DEFINITIONS})

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
  LINK_PRIVATE AvogadroIO ${Qt5Network_LIBRARIES})
