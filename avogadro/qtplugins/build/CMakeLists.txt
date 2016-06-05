set(build_srcs
  build.cpp
  supercelldialog.cpp
  slabdialog.cpp
)

set(build_uis
  supercelldialog.ui
  slabdialog.ui
)

avogadro_plugin(Build
  "Provide molecule editing/analysis."
  ExtensionPlugin
  build.h
  Build
  "${build_srcs}"
  "${build_uis}"
)

