
avogadro_plugin(Label
  "Labels rendering scheme"
  ScenePlugin
  label.h
  Label
  label.cpp
  "")

set(label_rcs
  label.qrc
)

set(label_srcs
  labeleditor.cpp
)

avogadro_plugin(LabelEditor
  "Labels rendering scheme"
  ToolPlugin
  labeleditor.h
  LabelEditor
  "${label_srcs}"
  ""
  "${label_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(Label LINK_PRIVATE Avogadro::Rendering)
target_link_libraries(LabelEditor LINK_PRIVATE Avogadro::QtOpenGL)