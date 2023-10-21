avogadro_plugin(Focus
  "Focus the view on specific features."
  ExtensionPlugin
  focus.h
  Focus
  "focus.cpp"
  ""
)

target_link_libraries(Focus PRIVATE Avogadro::QtOpenGL)
