avogadro_plugin(ResetView
  "Manipulate the view camera."
  ExtensionPlugin
  resetview.h
  ResetView
  "resetview.cpp"
  ""
)

target_link_libraries(ResetView PRIVATE Avogadro::QtOpenGL)
