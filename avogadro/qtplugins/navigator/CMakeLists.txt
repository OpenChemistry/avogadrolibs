set(navigator_srcs
  navigator.cpp
)

set(navigator_uis
)

set(navigator_rcs
  navigator.qrc
)

avogadro_plugin(Navigator
  "Navigation tool"
  ToolPlugin
  navigator.h
  Navigator
  "${navigator_srcs}"
  "${navigator_uis}"
  "${navigator_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(Navigator PRIVATE AvogadroQtOpenGL)
