set(crystal_srcs
  crystal.cpp
  unitcelldialog.cpp
  volumescalingdialog.cpp
  spacegroupdialog.cpp
  spacegroupmodel.cpp
)

set(crystal_uis
  unitcelldialog.ui
  volumescalingdialog.ui
  spacegroupdialog.ui
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

target_link_libraries(CrystalScene LINK_PRIVATE AvogadroRendering)
