include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(Focus
  "Focus the view on specific features."
  ExtensionPlugin
  focus.h
  Focus
  "focus.cpp"
  ""
)

target_link_libraries(Focus PRIVATE AvogadroRendering AvogadroQtOpenGL)
