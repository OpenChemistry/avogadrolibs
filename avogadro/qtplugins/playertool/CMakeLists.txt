include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty/libgwavi"
  "${AvogadroLibs_SOURCE_DIR}/thirdparty/gif-h")

avogadro_plugin(PlayerTool
  "Player tool"
  ToolPlugin
  playertool.h
  PlayerTool
  "playertool.cpp"
  ""
  playertool.qrc
)

target_link_libraries(PlayerTool PRIVATE gwavi)
