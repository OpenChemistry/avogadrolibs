include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty")

# Extension
set(srcs
  mongochem.cpp
)

avogadro_plugin(MongoChem
  "HTTP interface with mongochemserver"
  ExtensionPlugin
  mongochem.h
  MongoChem
  "${srcs}"
  ""#  mongochem.ui
  ""
)

target_link_libraries(MongoChem LINK_PRIVATE ${Qt5Network_LIBRARIES})
