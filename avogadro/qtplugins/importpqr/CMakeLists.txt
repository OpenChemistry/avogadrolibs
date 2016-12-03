find_package(MoleQueue)
find_package(Qt5WebEngineWidgets REQUIRED)
# find_package(Qt5 COMPONENTS Network WebView REQUIRED)

include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty/jsoncpp")

# Extension
set(importpqr_srcs
  ImportPQR.cpp
  PQRWidget.cpp
  PQRRequest.cpp
)

avogadro_plugin(ImportPQR
  "Download molecules from the Pitt Quantum Repository"
  ExtensionPlugin
  ImportPQR.h
  ImportPQR
  "${importpqr_srcs}"
  PQRWidget.ui
  ""
)
# qt5_use_modules(ImportPQR Network WebView)
target_link_libraries(ImportPQR LINK_PRIVATE AvogadroMoleQueue ${Qt5Network_LIBRARIES} ${Qt5WebEngineWidgets_LIBRARIES})
