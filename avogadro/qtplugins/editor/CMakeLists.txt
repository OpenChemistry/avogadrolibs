set(editor_srcs
  editor.cpp
  editortoolwidget.cpp
)

set(editor_uis
  editortoolwidget.ui
)

avogadro_plugin(Editor
  "Editor tool"
  ToolPlugin
  editor.h
  Editor
  "${editor_srcs}"
  "${editor_uis}"
)
