include_directories(${CMAKE_CURRENT_BINARY_DIR})
find_package(Qt${QT_VERSION} COMPONENTS Svg REQUIRED)

avogadro_plugin(SVG
  "Project the screen in a SVG image."
  ExtensionPlugin
  svg.h
  SVG
  "svg.cpp"
  ""
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(SVG PRIVATE AvogadroRendering Qt::Svg)
