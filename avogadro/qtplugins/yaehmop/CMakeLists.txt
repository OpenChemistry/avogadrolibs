
set(yaehmop_srcs
  banddialog.cpp
  specialkpoints.cpp
  yaehmop.cpp
  yaehmopout.cpp
)

set(yaehmop_uis
  banddialog.ui
)

avogadro_plugin(Yaehmop
  "Use yaehmop to perform extended Hückel calculations."
  ExtensionPlugin
  yaehmop.h
  Yaehmop
  "${yaehmop_srcs}"
  "${yaehmop_uis}"
)

target_link_libraries(Yaehmop PRIVATE AvogadroVtk)
