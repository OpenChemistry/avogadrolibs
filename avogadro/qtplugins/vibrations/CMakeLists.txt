set(plugin_srcs
  displacementdialog.cpp
  vibrationdialog.cpp
  vibrationmodel.cpp
  vibrations.cpp
)

set(plugin_uis
  displacementdialog.ui
  vibrationdialog.ui
)

avogadro_plugin(Vibrations
  "Vibrations"
  ExtensionPlugin
  vibrations.h
  Vibrations
  "${plugin_srcs}"
  "${plugin_uis}"
)
