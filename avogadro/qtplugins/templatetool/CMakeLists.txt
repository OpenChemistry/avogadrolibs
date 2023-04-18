set(template_srcs
  templatetool.cpp
  templatetoolwidget.cpp
)

set(template_uis
  templatetoolwidget.ui
)

set(template_rcs
  template.qrc
)

avogadro_plugin(TemplateTool
  "Template tool"
  ToolPlugin
  templatetool.h
  TemplateTool
  "${template_srcs}"
  "${template_uis}"
  "${template_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(TemplateTool LINK_PRIVATE Avogadro::QtOpenGL)
