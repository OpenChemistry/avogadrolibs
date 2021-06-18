include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty")

find_package(LibArchive REQUIRED)
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

target_link_libraries(PluginDownloader PRIVATE ${Qt5Network_LIBRARIES}
  ${LIBARCHIVE_LIBRARIES})
