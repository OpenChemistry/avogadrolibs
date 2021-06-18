include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(ResetView
  "Manipulate the view camera."
  ExtensionPlugin
  resetview.h
  ResetView
  "resetview.cpp"
  ""
)

target_link_libraries(ResetView PRIVATE AvogadroRendering)
