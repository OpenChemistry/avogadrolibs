set(measuretool_srcs
  measuretool.cpp
)

set(measuretool_uis
)

set(measuretool_rcs
  measuretool.qrc
)

avogadro_plugin(MeasureTool
  "Measure tool"
  ToolPlugin
  measuretool.h
  MeasureTool
  "${measuretool_srcs}"
  "${measuretool_uis}"
  "${measuretool_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(MeasureTool PRIVATE AvogadroQtOpenGL)
