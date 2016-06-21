set(spacegroup_srcs
  spacegroup.cpp
)

set(spacegroup_uis

)

avogadro_plugin(SpaceGroup
  "Space group features for crystals."
  ExtensionPlugin
  spacegroup.h
  SpaceGroup
  "${spacegroup_srcs}"
  "${spacegroup_uis}"
)

