include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(Select
  "Extension that modifies selections."
  ExtensionPlugin
  select.h
  Select
  "select.cpp"
  ""
)
