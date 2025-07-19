avogadro_plugin(PropertyTables
  "Atom, Bond, Angle, Dihedral property tables."
  ExtensionPlugin
  propertytables.h
  PropertyTables
  "propertytables.cpp;propertymodel.cpp;propertyview.cpp"
)

target_link_libraries(PropertyTables PRIVATE Avogadro::Calc)