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
