avogadro_plugin(PlayerTool
  "Player tool"
  ToolPlugin
  playertool.h
  PlayerTool
  "playertool.cpp"
  ""
  playertool.qrc
)

target_link_libraries(PlayerTool
  PRIVATE
    gwavi
    gif-h
    Avogadro::QtOpenGL)
