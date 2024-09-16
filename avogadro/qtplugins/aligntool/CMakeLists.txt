if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS Gui REQUIRED)
else()
  find_package(Qt5 COMPONENTS Widgets REQUIRED)
endif()

set(aligntool_srcs
  aligntool.cpp
)

set(aligntool_uis
)

set(aligntool_rcs
  aligntool.qrc
)

avogadro_plugin(AlignTool
  "AlignTool"
  ToolPlugin
  aligntool.h
  AlignTool
  "${aligntool_srcs}"
  "${aligntool_uis}"
  "${aligntool_rcs}"
)

target_link_libraries(AlignTool PRIVATE Avogadro::QtOpenGL)

if(QT_VERSION EQUAL 6)
  target_link_libraries(AlignTool PRIVATE Qt6::Gui)
else()
  target_link_libraries(AlignTool PRIVATE Qt5::Widgets)
endif()
