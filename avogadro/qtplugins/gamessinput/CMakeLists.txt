# Extension
set(gamessinput_srcs
  gamessinputdialog.cpp
  gamesshighlighter.cpp
  gamessinput.cpp
)

avogadro_plugin(GamessInput
  "GAMESS input file generation"
  ExtensionPlugin
  gamessinput.h
  GamessInput
  "${gamessinput_srcs}"
  gamessinputdialog.ui
)

target_link_libraries(GamessInput PRIVATE AvogadroMoleQueue)
