set(editor_srcs
  editor.cpp
  editortoolwidget.cpp
)

set(editor_uis
  editortoolwidget.ui
)

set(editor_rcs
  editor.qrc
)

avogadro_plugin(Editor
  "Editor tool"
  ToolPlugin
  editor.h
  Editor
  "${editor_srcs}"
  "${editor_uis}"
  "${editor_rcs}"
)

target_link_libraries(Editor PRIVATE AvogadroRendering)
