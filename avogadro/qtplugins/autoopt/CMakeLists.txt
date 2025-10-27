set(autoopt_srcs
  autoopt.cpp
)

set(autoopt_rcs
  autoopt.qrc
)

avogadro_plugin(AutoOpt
  "AutoOpt"
  ToolPlugin
  autoopt.h
  AutoOpt
  "${autoopt_srcs}"
  "${autoopt_uis}"
  "${autoopt_rcs}"
)

target_link_libraries(AutoOpt PRIVATE Avogadro::QtOpenGL Avogadro::Calc)
