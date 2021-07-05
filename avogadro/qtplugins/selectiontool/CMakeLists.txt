set(tool_srcs
  selectiontool.cpp
  selectiontoolwidget.cpp
)

set(tool_uis
  selectiontoolwidget.ui
)

set(tool_rcs selectiontool.qrc)

avogadro_plugin(Selection
  "Selection tool"
  ToolPlugin
  selectiontool.h
  SelectionTool
  "${tool_srcs}"
  "${tool_uis}"
  "${tool_rcs}"
)

target_link_libraries(Selection PRIVATE AvogadroQtOpenGL)
