set(plugin_srcs
  vibrationdialog.cpp
  vibrationmodel.cpp
  spectra.cpp
)

avogadro_plugin(Spectra
  "Spectra and Vibrations"
  ExtensionPlugin
  spectra.h
  Spectra
  "${plugin_srcs}"
  "vibrationdialog.ui"
)
