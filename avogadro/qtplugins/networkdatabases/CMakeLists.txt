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
  PRIVATE Avogadro::IO Qt::Network)

if(WIN32)
  # for https support
  target_link_libraries(NetworkDatabases PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
