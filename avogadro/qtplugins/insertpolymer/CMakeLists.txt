avogadro_plugin(InsertPolymer
  "Build polymers from monomer repeat units."
  ExtensionPlugin
  insertpolymer.h
  InsertPolymer
  "insertpolymer.cpp;insertpolymerdialog.cpp"
  "insertpolymerdialog.ui"
)

target_link_libraries(InsertPolymer PRIVATE Avogadro::QtGui)

# Install polymer monomer data (SMILES + images)
install(DIRECTORY "${AvogadroLibs_SOURCEDATA_DIR}/fragments/polymers"
  DESTINATION "${INSTALL_DATA_DIR}/avogadro2/fragments"
  PATTERN ".git" EXCLUDE
  PATTERN ".gitignore" EXCLUDE
  PATTERN "README.md" EXCLUDE
  PATTERN "LICENSE" EXCLUDE
)
