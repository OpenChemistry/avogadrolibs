set(plugin_srcs
  vibrationdialog.cpp
  vibrationmodel.cpp
  vibrations.cpp
)

avogadro_plugin(Vibrations
  "Vibrations"
  ExtensionPlugin
  vibrations.h
  Vibrations
  "${plugin_srcs}"
  "vibrationdialog.ui"
)
