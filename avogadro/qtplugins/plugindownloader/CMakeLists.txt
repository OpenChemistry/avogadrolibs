include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty/jsoncpp")

# Extension
set(plugindownloader_srcs
  plugindownloader.cpp
)

avogadro_plugin(PluginDownloader
  "Download plugins from Github repositories"
  ExtensionPlugin
	plugindownloader.h
  PluginDownloader
  "${plugindownloader_srcs}"
  plugindownloader.ui
  ""
)

target_link_libraries(PluginDownloader LINK_PRIVATE ${Qt5Network_LIBRARIES})
