set(template_srcs
  templatetool.cpp
  templatetoolwidget.cpp
)

set(template_uis
  templatetoolwidget.ui
)

set(template_rcs
  template.qrc
)

avogadro_plugin(TemplateTool
  "Template tool"
  ToolPlugin
  templatetool.h
  TemplateTool
  "${template_srcs}"
  "${template_uis}"
  "${template_rcs}"
)

target_link_libraries(TemplateTool LINK_PRIVATE AvogadroRendering)
