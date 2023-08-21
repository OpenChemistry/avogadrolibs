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
  PRIVATE Avogadro::IO Qt::Network)

if(WIN32)
  # for https support
  target_link_libraries(FetchPDB PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
