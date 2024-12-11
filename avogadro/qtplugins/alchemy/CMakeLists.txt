include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(Alchemy
  "Change elements"
  ExtensionPlugin
  alchemy.h
  Alchemy
  "alchemy.cpp"
  ""
)
