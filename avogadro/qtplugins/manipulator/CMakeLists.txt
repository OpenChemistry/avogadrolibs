set(manipulator_srcs
  manipulator.cpp
)

set(manipulator_uis
)

avogadro_plugin(Manipulator
  "Manipulator tool"
  ToolPlugin
  manipulator.h
  Manipulator
  "${manipulator_srcs}"
  "${manipulator_uis}"
)
