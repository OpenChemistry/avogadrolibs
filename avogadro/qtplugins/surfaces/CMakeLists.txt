include_directories(SYSTEM "${AvogadroLibs_SOURCE_DIR}/thirdparty/libgwavi"
  "${AvogadroLibs_SOURCE_DIR}/thirdparty/gif-h"
  "${AvogadroLibs_SOURCE_DIR}/thirdparty/tinycolormap/include")

set(surfaces_srcs
  gaussiansetconcurrent.cpp
  slatersetconcurrent.cpp
  surfacedialog.cpp
  surfaces.cpp
)

avogadro_plugin(Surfaces
  "Surfaces"
  ExtensionPlugin
  surfaces.h
  Surfaces
  "${surfaces_srcs}"
  "surfacedialog.ui"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(Surfaces
  PRIVATE
    Avogadro::Calc
    Avogadro::QuantumIO
    Avogadro::QtOpenGL
    Qt::Concurrent
    gwavi)
