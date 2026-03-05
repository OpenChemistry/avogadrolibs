find_package(LibArchive REQUIRED)

set(packageinstaller_srcs
  packageinstaller.cpp
  packagemanagerdialog.cpp
  packagemodel.cpp
  zipextracter.cpp
)

avogadro_plugin(PackageInstaller
  "Install, update, and remove Avogadro packages"
  ExtensionPlugin
  packageinstaller.h
  PackageInstaller
  "${packageinstaller_srcs}"
  packagemanagerdialog.ui
  ""
)

target_link_libraries(PackageInstaller PRIVATE
  Qt::Network
  LibArchive::LibArchive
  nlohmann_json::nlohmann_json
)

if(WIN32)
  # for https support
  target_link_libraries(PackageInstaller PRIVATE
    OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
