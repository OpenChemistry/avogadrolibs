# Extension
set(importpqr_srcs
  importpqr.cpp
  pqrwidget.cpp
  pqrrequest.cpp
)

avogadro_plugin(ImportPQR
  "Download molecules from the Pitt Quantum Repository"
  ExtensionPlugin
  importpqr.h
  ImportPQR
  "${importpqr_srcs}"
  pqrwidget.ui
  ""
)

target_link_libraries(ImportPQR PRIVATE Qt::Network nlohmann_json::nlohmann_json)

if(WIN32)
  # for https support
  target_link_libraries(ImportPQR PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
