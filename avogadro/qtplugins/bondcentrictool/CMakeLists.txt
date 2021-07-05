set(bondcentrictool_srcs
  bondcentrictool.cpp
)

set(bondcentrictool_uis
)

set(bondcentrictool_rcs
  bondcentrictool.qrc
)

avogadro_plugin(BondCentric
  "Bond-centric"
  ToolPlugin
  bondcentrictool.h
  BondCentricTool
  "${bondcentrictool_srcs}"
  "${bondcentrictool_uis}"
  "${bondcentrictool_rcs}"
)

target_link_libraries(BondCentric PRIVATE AvogadroQtOpenGL)
