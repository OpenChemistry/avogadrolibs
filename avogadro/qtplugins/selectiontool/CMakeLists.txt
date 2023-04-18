set(tool_srcs
  selectiontool.cpp
  selectiontoolwidget.cpp
)

set(tool_uis
  selectiontoolwidget.ui
)

set(tool_rcs selectiontool.qrc)

avogadro_plugin(Selection
  "Selection tool"
  ToolPlugin
  selectiontool.h
  SelectionTool
  "${tool_srcs}"
  "${tool_uis}"
  "${tool_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(Selection PRIVATE Avogadro::QtOpenGL)
