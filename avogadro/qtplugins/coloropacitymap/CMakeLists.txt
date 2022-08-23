include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(_srcs
  coloropacitymap.cpp
  histogramwidget.cpp
  qvtkwidget.cpp
  vtkChartHistogram.cpp
  vtkChartHistogramColorOpacityEditor.cpp
  vtkCustomPiecewiseControlPointsItem.cpp
  comdialog.cpp
)

set(_uis
  comdialog.ui
)

avogadro_plugin(ColorOpacityMap
  "Edit the color opacity map."
  ExtensionPlugin
  coloropacitymap.h
  ColorOpacityMap
  "${_srcs}"
  "${_uis}"
)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})
if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

target_link_libraries(ColorOpacityMap
  PRIVATE
    AvogadroQtOpenGL
    AvogadroVtk)
