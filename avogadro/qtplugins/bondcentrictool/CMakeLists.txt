set(bondcentrictool_srcs
  bondcentrictool.cpp
)

set(bondcentrictool_uis
)

set(bondcentrictool_rcs
  bondcentrictool.qrc
)

avogadro_plugin(BondCentric
  "Bond-centric"
  ToolPlugin
  bondcentrictool.h
  BondCentricTool
  "${bondcentrictool_srcs}"
  "${bondcentrictool_uis}"
  "${bondcentrictool_rcs}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(BondCentric PRIVATE Avogadro::QtOpenGL)
