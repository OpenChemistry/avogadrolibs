set(navigator_srcs
  navigator.cpp
)

set(navigator_uis
)

avogadro_plugin(Navigator
  "Navigation tool"
  ToolPlugin
  navigator.h
  Navigator
  "${navigator_srcs}"
  "${navigator_uis}"
)

target_link_libraries(Navigator LINK_PRIVATE AvogadroQtOpenGL)
