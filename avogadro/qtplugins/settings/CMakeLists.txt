include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty")

find_package(LIBARCHIVE REQUIRED)
include_directories(SYSTEM ${LIBARCHIVE_INCLUDE_DIRS})
# Extension
set(settings_srcs
  settings.cpp
)

avogadro_plugin(SettingsPlugin
  "General settings for avogadro"
  ExtensionPlugin
  settings.h
  SettingsPlugin
  "${settings_srcs}"
  ""
  ""
)

target_link_libraries(SettingsPlugin PRIVATE ${Qt5Network_LIBRARIES}
  ${LIBARCHIVE_LIBRARIES})
