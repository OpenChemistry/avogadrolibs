find_package(LibArchive REQUIRED)

# Extension
set(plugindownloader_srcs
  plugindownloader.cpp
  downloaderwidget.cpp
  zipextracter.cpp
)

avogadro_plugin(PluginDownloader
  "Download plugins from Github repositories"
  ExtensionPlugin
  plugindownloader.h
  PluginDownloader
  "${plugindownloader_srcs}"
  downloaderwidget.ui
  ""
)

target_link_libraries(PluginDownloader PRIVATE Qt::Network
  LibArchive::LibArchive
  nlohmann_json::nlohmann_json
)

if(WIN32)
  # for https support
  target_link_libraries(PluginDownloader PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
