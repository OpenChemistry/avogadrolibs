include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(Centroid
  "Add centroid and center-of-mass."
  ExtensionPlugin
  centroid.h
  Centroid
  "centroid.cpp"
  ""
)
