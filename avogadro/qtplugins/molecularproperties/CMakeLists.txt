set(molecularproperties_srcs
  molecularproperties.cpp
  molecularmodel.cpp
  molecularview.cpp
)

avogadro_plugin(MolecularProperties
  "Show a window with basic molecular properties."
  ExtensionPlugin
  molecularproperties.h
  MolecularProperties
  "${molecularproperties_srcs}"
)

# to fetch the molecule name from PubChem
target_link_libraries(MolecularProperties PRIVATE Qt::Network)

if(WIN32)
  # for https support
  target_link_libraries(MolecularProperties PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink)
endif()
