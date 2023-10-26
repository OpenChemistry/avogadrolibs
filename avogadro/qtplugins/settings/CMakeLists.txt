include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty")

find_package(LIBARCHIVE REQUIRED)
include_directories(SYSTEM ${LIBARCHIVE_INCLUDE_DIRS})
# Extension
set(settings_srcs
  settings.cpp
)

avogadro_plugin(Settings
  "General settings for avogadro"
  ExtensionPlugin
  settings.h
  Settings
  "${settings_srcs}"
  ""
  ""
)

target_link_libraries(Settings PRIVATE ${Qt5Network_LIBRARIES}
  ${LIBARCHIVE_LIBRARIES})
