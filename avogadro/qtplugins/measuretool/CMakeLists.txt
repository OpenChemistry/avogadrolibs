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

target_link_libraries(MeasureTool PRIVATE AvogadroQtOpenGL)
