include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(PropertyTables
  "Atom, Bond, Angle, Dihedral property tables."
  ExtensionPlugin
  propertytables.h
  PropertyTables
  "propertytables.cpp;propertymodel.cpp;propertyview.cpp"
)
