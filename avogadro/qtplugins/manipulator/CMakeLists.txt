set(manipulator_srcs
  manipulator.cpp
)

set(manipulator_uis
)

set(manipulator_rcs
  manipulator.qrc
)

avogadro_plugin(Manipulator
  "Manipulator"
  ToolPlugin
  manipulator.h
  Manipulator
  "${manipulator_srcs}"
  "${manipulator_uis}"
  "${manipulator_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(Manipulator PRIVATE AvogadroQtOpenGL)
