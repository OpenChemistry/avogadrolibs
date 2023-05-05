include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty")

find_package(LIBARCHIVE REQUIRED)
include_directories(SYSTEM ${LIBARCHIVE_INCLUDE_DIRS})
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

target_link_libraries(PluginDownloader PRIVATE Qt::Network ${LIBARCHIVE_LIBRARIES})

if(WIN32)
  # for https support
  target_link_libraries(PluginDownloader PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
