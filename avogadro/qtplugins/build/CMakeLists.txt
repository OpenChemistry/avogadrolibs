set(build_srcs
  build.cpp
  supercelldialog.cpp
)

set(build_uis
  supercelldialog.ui
)

avogadro_plugin(Build
  "Provide molecule editing/analysis."
  ExtensionPlugin
  build.h
  Build
  "${build_srcs}"
  "${build_uis}"
)

