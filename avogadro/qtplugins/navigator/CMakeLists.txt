set(navigator_srcs
  navigator.cpp
)

set(navigator_uis
)

set(navigator_rcs
  navigator.qrc
)

avogadro_plugin(Navigator
  "Navigation tool"
  ToolPlugin
  navigator.h
  Navigator
  "${navigator_srcs}"
  "${navigator_uis}"
  "${navigator_rcs}"
)

target_link_libraries(Navigator PRIVATE AvogadroQtOpenGL)
