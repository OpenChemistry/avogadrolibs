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

  message(WARNING "FindSSL found: ${OPENSSL_FOUND}")
  message(WARNING "FindSSL include dir: ${OPENSSL_INCLUDE_DIR}")
  message(WARNING "FindSSL library dir: ${OPENSSL_LIBRARY_DIR}")
  message(WARNING "FindSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
  message(WARNING "FindSSL Crypto dependencies: ${OPENSSL_CRYPTO_LIBRARIES}")
  message(WARNING "FindSSL SSL lib: ${OPENSSL_SSL_LIBRARY}")
  message(WARNING "FindSSL SSL dependencies: ${OPENSSL_SSL_LIBRARIES}")
  message(WARNING "FindSSL ALL : ${OPENSSL_LIBRARIES}")

  # install libcrypto*.dll and libssl*.dll
  # install(FILES ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} DESTINATION ${INSTALL_RUNTIME_DIR})
endif()
