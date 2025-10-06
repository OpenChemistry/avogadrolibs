set(plugin_srcs
  spectradialog.cpp
  spectra.cpp
)

avogadro_plugin(Spectra
  "Spectra Plots"
  ExtensionPlugin
  spectra.h
  Spectra
  "${plugin_srcs}"
  "spectradialog.ui"
)

# target_link_libraries(Spectra PRIVATE JKQtPlotter6::JKQtPlotter6)
