set(_srcs
  coloropacitymap.cpp
  histogramwidget.cpp
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

target_link_libraries(ColorOpacityMap
  PRIVATE
    Avogadro::QtOpenGL
    Avogadro::Vtk)
