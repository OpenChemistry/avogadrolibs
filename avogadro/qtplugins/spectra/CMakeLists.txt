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

if (USE_VTK)
  add_definitions(-DUSE_VTK)
  target_link_libraries(Spectra PRIVATE Avogadro::Vtk)
endif()
