find_package(Qt${QT_VERSION} COMPONENTS Svg REQUIRED)

avogadro_plugin(SVG
  "Project the screen in a SVG image."
  ExtensionPlugin
  svg.h
  SVG
  "svg.cpp"
  ""
)

target_link_libraries(SVG PRIVATE Avogadro::QtOpenGL Qt::Svg)
