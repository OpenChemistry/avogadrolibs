set(bondcentrictool_srcs
  bondcentrictool.cpp
)

set(bondcentrictool_uis
)

set(bondcentrictool_rcs
  bondcentrictool.qrc
)

avogadro_plugin(BondCentricTool
  "Bond-centric manipulation tool"
  ToolPlugin
  bondcentrictool.h
  BondCentricTool
  "${bondcentrictool_srcs}"
  "${bondcentrictool_uis}"
  "${bondcentrictool_rcs}"
)

target_link_libraries(BondCentricTool LINK_PRIVATE AvogadroQtOpenGL)
