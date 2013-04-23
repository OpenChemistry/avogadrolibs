set(manipulator_srcs
  manipulator.cpp
)

set(manipulator_uis
)

set(manipulator_rcs
  manipulator.qrc
)

avogadro_plugin(Manipulator
  "Manipulator tool"
  ToolPlugin
  manipulator.h
  Manipulator
  "${manipulator_srcs}"
  "${manipulator_uis}"
  "${manipulator_rcs}"
)
