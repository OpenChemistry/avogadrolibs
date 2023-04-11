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

find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(Editor PRIVATE AvogadroRendering)
