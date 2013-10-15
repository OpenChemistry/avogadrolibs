set(crystal_srcs
  crystal.cpp
  unitcelldialog.cpp
  volumescalingdialog.cpp
)

set(crystal_uis
  unitcelldialog.ui
  volumescalingdialog.ui
)

avogadro_plugin(Crystal
  "Provide crystal-specific editing/analysis."
  ExtensionPlugin
  crystal.h
  Crystal
  "${crystal_srcs}"
  "${crystal_uis}"
)
