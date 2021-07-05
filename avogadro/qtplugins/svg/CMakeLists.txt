include_directories(${CMAKE_CURRENT_BINARY_DIR})
find_package(Qt5 COMPONENTS Svg REQUIRED)


avogadro_plugin(SVG
  "Project the screen in a SVG image."
  ExtensionPlugin
  svg.h
  SVG
  "svg.cpp"
  ""
)

target_link_libraries(SVG PRIVATE AvogadroRendering Qt5::Svg)
