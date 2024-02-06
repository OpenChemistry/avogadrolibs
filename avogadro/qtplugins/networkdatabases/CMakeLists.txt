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
  install(FILES ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} DESTINATION ${INSTALL_RUNTIME_DIR})
endif()
