avogadro_plugin(Focus
  "Focus the view on specific features."
  ExtensionPlugin
  focus.h
  Focus
  "focus.cpp"
  ""
)

target_link_libraries(Focus PRIVATE Avogadro::Rendering Avogadro::QtOpenGL)

target_include_directories(Focus
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../rendering
    ${CMAKE_CURRENT_BINARY_DIR}/../../qtopengl)
