set(crystal_srcs
  crystal.cpp
  importcrystaldialog.cpp
  supercelldialog.cpp
  unitcelldialog.cpp
  volumescalingdialog.cpp
)

set(crystal_uis
  importcrystaldialog.ui
  supercelldialog.ui
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

avogadro_plugin(CrystalScene
  "Render unit cell lattice."
  ScenePlugin
  crystalscene.h
  CrystalScene
  crystalscene.cpp)

target_link_libraries(CrystalScene PRIVATE AvogadroRendering)
