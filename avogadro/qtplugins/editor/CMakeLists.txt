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

target_link_libraries(Editor PRIVATE Avogadro::Rendering Avogadro::QtOpenGL)

target_include_directories(Editor
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../rendering
    ${CMAKE_CURRENT_BINARY_DIR}/../../qtopengl)
