include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty/jsoncpp")

find_package(libarchive REQUIRED)
include_directories(SYSTEM ${LIBARCHIVE_INCLUDE_DIR})
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

target_link_libraries(PluginDownloader LINK_PRIVATE ${Qt5Network_LIBRARIES} ${LIBARCHIVE_LIBRARY})
