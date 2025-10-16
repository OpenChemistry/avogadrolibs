#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Avogadro::gwavi" for configuration "Release"
set_property(TARGET Avogadro::gwavi APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::gwavi PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/libgwavi.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::gwavi )
list(APPEND _cmake_import_check_files_for_Avogadro::gwavi "${_IMPORT_PREFIX}/lib/avogadro2/libgwavi.a" )

# Import target "Avogadro::Core" for configuration "Release"
set_property(TARGET Avogadro::Core APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Core PROPERTIES
  IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE "Spglib::symspg"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroCore.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroCore.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::Core )
list(APPEND _cmake_import_check_files_for_Avogadro::Core "${_IMPORT_PREFIX}/lib/libAvogadroCore.1.101.0.dylib" )

# Import target "Avogadro::Calc" for configuration "Release"
set_property(TARGET Avogadro::Calc APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Calc PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroCalc.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroCalc.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::Calc )
list(APPEND _cmake_import_check_files_for_Avogadro::Calc "${_IMPORT_PREFIX}/lib/libAvogadroCalc.1.101.0.dylib" )

# Import target "Avogadro::IO" for configuration "Release"
set_property(TARGET Avogadro::IO APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::IO PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroIO.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroIO.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::IO )
list(APPEND _cmake_import_check_files_for_Avogadro::IO "${_IMPORT_PREFIX}/lib/libAvogadroIO.1.101.0.dylib" )

# Import target "Avogadro::QuantumIO" for configuration "Release"
set_property(TARGET Avogadro::QuantumIO APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::QuantumIO PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroQuantumIO.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroQuantumIO.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::QuantumIO )
list(APPEND _cmake_import_check_files_for_Avogadro::QuantumIO "${_IMPORT_PREFIX}/lib/libAvogadroQuantumIO.1.101.0.dylib" )

# Import target "Avogadro::Rendering" for configuration "Release"
set_property(TARGET Avogadro::Rendering APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Rendering PROPERTIES
  IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE "Avogadro::Core;GLEW::GLEW"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroRendering.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroRendering.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::Rendering )
list(APPEND _cmake_import_check_files_for_Avogadro::Rendering "${_IMPORT_PREFIX}/lib/libAvogadroRendering.1.101.0.dylib" )

# Import target "Avogadro::QtGui" for configuration "Release"
set_property(TARGET Avogadro::QtGui APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::QtGui PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroQtGui.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroQtGui.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::QtGui )
list(APPEND _cmake_import_check_files_for_Avogadro::QtGui "${_IMPORT_PREFIX}/lib/libAvogadroQtGui.1.101.0.dylib" )

# Import target "Avogadro::QtOpenGL" for configuration "Release"
set_property(TARGET Avogadro::QtOpenGL APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::QtOpenGL PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroQtOpenGL.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroQtOpenGL.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::QtOpenGL )
list(APPEND _cmake_import_check_files_for_Avogadro::QtOpenGL "${_IMPORT_PREFIX}/lib/libAvogadroQtOpenGL.1.101.0.dylib" )

# Import target "Avogadro::MoleQueue" for configuration "Release"
set_property(TARGET Avogadro::MoleQueue APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::MoleQueue PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroMoleQueue.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroMoleQueue.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::MoleQueue )
list(APPEND _cmake_import_check_files_for_Avogadro::MoleQueue "${_IMPORT_PREFIX}/lib/libAvogadroMoleQueue.1.101.0.dylib" )

# Import target "Avogadro::ThreeDMol" for configuration "Release"
set_property(TARGET Avogadro::ThreeDMol APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ThreeDMol PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ThreeDMol.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ThreeDMol )
list(APPEND _cmake_import_check_files_for_Avogadro::ThreeDMol "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ThreeDMol.a" )

# Import target "Avogadro::Alchemy" for configuration "Release"
set_property(TARGET Avogadro::Alchemy APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Alchemy PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Alchemy.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Alchemy )
list(APPEND _cmake_import_check_files_for_Avogadro::Alchemy "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Alchemy.a" )

# Import target "Avogadro::AlignTool" for configuration "Release"
set_property(TARGET Avogadro::AlignTool APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::AlignTool PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/AlignTool.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::AlignTool )
list(APPEND _cmake_import_check_files_for_Avogadro::AlignTool "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/AlignTool.a" )

# Import target "Avogadro::apbs" for configuration "Release"
set_property(TARGET Avogadro::apbs APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::apbs PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/apbs.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::apbs )
list(APPEND _cmake_import_check_files_for_Avogadro::apbs "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/apbs.a" )

# Import target "Avogadro::ApplyColors" for configuration "Release"
set_property(TARGET Avogadro::ApplyColors APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ApplyColors PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ApplyColors.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ApplyColors )
list(APPEND _cmake_import_check_files_for_Avogadro::ApplyColors "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ApplyColors.a" )

# Import target "Avogadro::AutoOpt" for configuration "Release"
set_property(TARGET Avogadro::AutoOpt APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::AutoOpt PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/AutoOpt.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::AutoOpt )
list(APPEND _cmake_import_check_files_for_Avogadro::AutoOpt "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/AutoOpt.a" )

# Import target "Avogadro::BondCentric" for configuration "Release"
set_property(TARGET Avogadro::BondCentric APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::BondCentric PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/BondCentric.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::BondCentric )
list(APPEND _cmake_import_check_files_for_Avogadro::BondCentric "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/BondCentric.a" )

# Import target "Avogadro::Bonding" for configuration "Release"
set_property(TARGET Avogadro::Bonding APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Bonding PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Bonding.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Bonding )
list(APPEND _cmake_import_check_files_for_Avogadro::Bonding "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Bonding.a" )

# Import target "Avogadro::Centroid" for configuration "Release"
set_property(TARGET Avogadro::Centroid APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Centroid PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Centroid.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Centroid )
list(APPEND _cmake_import_check_files_for_Avogadro::Centroid "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Centroid.a" )

# Import target "Avogadro::ConfigurePython" for configuration "Release"
set_property(TARGET Avogadro::ConfigurePython APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ConfigurePython PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ConfigurePython.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ConfigurePython )
list(APPEND _cmake_import_check_files_for_Avogadro::ConfigurePython "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ConfigurePython.a" )

# Import target "Avogadro::ConstraintsExtension" for configuration "Release"
set_property(TARGET Avogadro::ConstraintsExtension APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ConstraintsExtension PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ConstraintsExtension.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ConstraintsExtension )
list(APPEND _cmake_import_check_files_for_Avogadro::ConstraintsExtension "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ConstraintsExtension.a" )

# Import target "Avogadro::CoordinateEditor" for configuration "Release"
set_property(TARGET Avogadro::CoordinateEditor APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::CoordinateEditor PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CoordinateEditor.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::CoordinateEditor )
list(APPEND _cmake_import_check_files_for_Avogadro::CoordinateEditor "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CoordinateEditor.a" )

# Import target "Avogadro::CopyPaste" for configuration "Release"
set_property(TARGET Avogadro::CopyPaste APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::CopyPaste PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CopyPaste.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::CopyPaste )
list(APPEND _cmake_import_check_files_for_Avogadro::CopyPaste "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CopyPaste.a" )

# Import target "Avogadro::Cp2kInput" for configuration "Release"
set_property(TARGET Avogadro::Cp2kInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Cp2kInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Cp2kInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Cp2kInput )
list(APPEND _cmake_import_check_files_for_Avogadro::Cp2kInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Cp2kInput.a" )

# Import target "Avogadro::Crystal" for configuration "Release"
set_property(TARGET Avogadro::Crystal APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Crystal PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Crystal.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Crystal )
list(APPEND _cmake_import_check_files_for_Avogadro::Crystal "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Crystal.a" )

# Import target "Avogadro::CrystalScene" for configuration "Release"
set_property(TARGET Avogadro::CrystalScene APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::CrystalScene PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CrystalScene.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::CrystalScene )
list(APPEND _cmake_import_check_files_for_Avogadro::CrystalScene "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CrystalScene.a" )

# Import target "Avogadro::CustomElements" for configuration "Release"
set_property(TARGET Avogadro::CustomElements APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::CustomElements PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CustomElements.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::CustomElements )
list(APPEND _cmake_import_check_files_for_Avogadro::CustomElements "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CustomElements.a" )

# Import target "Avogadro::Dipole" for configuration "Release"
set_property(TARGET Avogadro::Dipole APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Dipole PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Dipole.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Dipole )
list(APPEND _cmake_import_check_files_for_Avogadro::Dipole "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Dipole.a" )

# Import target "Avogadro::Editor" for configuration "Release"
set_property(TARGET Avogadro::Editor APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Editor PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Editor.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Editor )
list(APPEND _cmake_import_check_files_for_Avogadro::Editor "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Editor.a" )

# Import target "Avogadro::FetchPDB" for configuration "Release"
set_property(TARGET Avogadro::FetchPDB APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::FetchPDB PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/FetchPDB.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::FetchPDB )
list(APPEND _cmake_import_check_files_for_Avogadro::FetchPDB "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/FetchPDB.a" )

# Import target "Avogadro::Focus" for configuration "Release"
set_property(TARGET Avogadro::Focus APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Focus PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Focus.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Focus )
list(APPEND _cmake_import_check_files_for_Avogadro::Focus "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Focus.a" )

# Import target "Avogadro::Forcefield" for configuration "Release"
set_property(TARGET Avogadro::Forcefield APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Forcefield PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Forcefield.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Forcefield )
list(APPEND _cmake_import_check_files_for_Avogadro::Forcefield "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Forcefield.a" )

# Import target "Avogadro::GamessInput" for configuration "Release"
set_property(TARGET Avogadro::GamessInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::GamessInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/GamessInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::GamessInput )
list(APPEND _cmake_import_check_files_for_Avogadro::GamessInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/GamessInput.a" )

# Import target "Avogadro::Hydrogens" for configuration "Release"
set_property(TARGET Avogadro::Hydrogens APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Hydrogens PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Hydrogens.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Hydrogens )
list(APPEND _cmake_import_check_files_for_Avogadro::Hydrogens "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Hydrogens.a" )

# Import target "Avogadro::ImportPQR" for configuration "Release"
set_property(TARGET Avogadro::ImportPQR APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ImportPQR PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ImportPQR.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ImportPQR )
list(APPEND _cmake_import_check_files_for_Avogadro::ImportPQR "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ImportPQR.a" )

# Import target "Avogadro::NucleicInput" for configuration "Release"
set_property(TARGET Avogadro::NucleicInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::NucleicInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/NucleicInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::NucleicInput )
list(APPEND _cmake_import_check_files_for_Avogadro::NucleicInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/NucleicInput.a" )

# Import target "Avogadro::InsertFragment" for configuration "Release"
set_property(TARGET Avogadro::InsertFragment APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::InsertFragment PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/InsertFragment.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::InsertFragment )
list(APPEND _cmake_import_check_files_for_Avogadro::InsertFragment "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/InsertFragment.a" )

# Import target "Avogadro::Label" for configuration "Release"
set_property(TARGET Avogadro::Label APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Label PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Label.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Label )
list(APPEND _cmake_import_check_files_for_Avogadro::Label "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Label.a" )

# Import target "Avogadro::LabelEditor" for configuration "Release"
set_property(TARGET Avogadro::LabelEditor APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::LabelEditor PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/LabelEditor.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::LabelEditor )
list(APPEND _cmake_import_check_files_for_Avogadro::LabelEditor "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/LabelEditor.a" )

# Import target "Avogadro::LammpsInput" for configuration "Release"
set_property(TARGET Avogadro::LammpsInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::LammpsInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/LammpsInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::LammpsInput )
list(APPEND _cmake_import_check_files_for_Avogadro::LammpsInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/LammpsInput.a" )

# Import target "Avogadro::LineFormatInput" for configuration "Release"
set_property(TARGET Avogadro::LineFormatInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::LineFormatInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/LineFormatInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::LineFormatInput )
list(APPEND _cmake_import_check_files_for_Avogadro::LineFormatInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/LineFormatInput.a" )

# Import target "Avogadro::Manipulator" for configuration "Release"
set_property(TARGET Avogadro::Manipulator APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Manipulator PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Manipulator.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Manipulator )
list(APPEND _cmake_import_check_files_for_Avogadro::Manipulator "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Manipulator.a" )

# Import target "Avogadro::MeasureTool" for configuration "Release"
set_property(TARGET Avogadro::MeasureTool APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::MeasureTool PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/MeasureTool.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::MeasureTool )
list(APPEND _cmake_import_check_files_for_Avogadro::MeasureTool "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/MeasureTool.a" )

# Import target "Avogadro::MolecularProperties" for configuration "Release"
set_property(TARGET Avogadro::MolecularProperties APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::MolecularProperties PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/MolecularProperties.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::MolecularProperties )
list(APPEND _cmake_import_check_files_for_Avogadro::MolecularProperties "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/MolecularProperties.a" )

# Import target "Avogadro::Navigator" for configuration "Release"
set_property(TARGET Avogadro::Navigator APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Navigator PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Navigator.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Navigator )
list(APPEND _cmake_import_check_files_for_Avogadro::Navigator "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Navigator.a" )

# Import target "Avogadro::NetworkDatabases" for configuration "Release"
set_property(TARGET Avogadro::NetworkDatabases APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::NetworkDatabases PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/NetworkDatabases.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::NetworkDatabases )
list(APPEND _cmake_import_check_files_for_Avogadro::NetworkDatabases "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/NetworkDatabases.a" )

# Import target "Avogadro::OpenBabel" for configuration "Release"
set_property(TARGET Avogadro::OpenBabel APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::OpenBabel PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/OpenBabel.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::OpenBabel )
list(APPEND _cmake_import_check_files_for_Avogadro::OpenBabel "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/OpenBabel.a" )

# Import target "Avogadro::OpenMMInput" for configuration "Release"
set_property(TARGET Avogadro::OpenMMInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::OpenMMInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/OpenMMInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::OpenMMInput )
list(APPEND _cmake_import_check_files_for_Avogadro::OpenMMInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/OpenMMInput.a" )

# Import target "Avogadro::PlayerTool" for configuration "Release"
set_property(TARGET Avogadro::PlayerTool APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PlayerTool PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlayerTool.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PlayerTool )
list(APPEND _cmake_import_check_files_for_Avogadro::PlayerTool "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlayerTool.a" )

# Import target "Avogadro::PLY" for configuration "Release"
set_property(TARGET Avogadro::PLY APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PLY PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PLY.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PLY )
list(APPEND _cmake_import_check_files_for_Avogadro::PLY "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PLY.a" )

# Import target "Avogadro::POVRay" for configuration "Release"
set_property(TARGET Avogadro::POVRay APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::POVRay PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/POVRay.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::POVRay )
list(APPEND _cmake_import_check_files_for_Avogadro::POVRay "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/POVRay.a" )

# Import target "Avogadro::PropertyTables" for configuration "Release"
set_property(TARGET Avogadro::PropertyTables APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PropertyTables PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PropertyTables.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PropertyTables )
list(APPEND _cmake_import_check_files_for_Avogadro::PropertyTables "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PropertyTables.a" )

# Import target "Avogadro::ResetView" for configuration "Release"
set_property(TARGET Avogadro::ResetView APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ResetView PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ResetView.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ResetView )
list(APPEND _cmake_import_check_files_for_Avogadro::ResetView "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ResetView.a" )

# Import target "Avogadro::Select" for configuration "Release"
set_property(TARGET Avogadro::Select APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Select PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Select.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Select )
list(APPEND _cmake_import_check_files_for_Avogadro::Select "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Select.a" )

# Import target "Avogadro::Selection" for configuration "Release"
set_property(TARGET Avogadro::Selection APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Selection PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Selection.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Selection )
list(APPEND _cmake_import_check_files_for_Avogadro::Selection "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Selection.a" )

# Import target "Avogadro::SpaceGroup" for configuration "Release"
set_property(TARGET Avogadro::SpaceGroup APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::SpaceGroup PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SpaceGroup.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::SpaceGroup )
list(APPEND _cmake_import_check_files_for_Avogadro::SpaceGroup "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SpaceGroup.a" )

# Import target "Avogadro::Surfaces" for configuration "Release"
set_property(TARGET Avogadro::Surfaces APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Surfaces PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Surfaces.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Surfaces )
list(APPEND _cmake_import_check_files_for_Avogadro::Surfaces "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Surfaces.a" )

# Import target "Avogadro::Orbitals" for configuration "Release"
set_property(TARGET Avogadro::Orbitals APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Orbitals PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Orbitals.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Orbitals )
list(APPEND _cmake_import_check_files_for_Avogadro::Orbitals "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Orbitals.a" )

# Import target "Avogadro::SVG" for configuration "Release"
set_property(TARGET Avogadro::SVG APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::SVG PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SVG.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::SVG )
list(APPEND _cmake_import_check_files_for_Avogadro::SVG "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SVG.a" )

# Import target "Avogadro::TemplateTool" for configuration "Release"
set_property(TARGET Avogadro::TemplateTool APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::TemplateTool PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/TemplateTool.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::TemplateTool )
list(APPEND _cmake_import_check_files_for_Avogadro::TemplateTool "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/TemplateTool.a" )

# Import target "Avogadro::Vibrations" for configuration "Release"
set_property(TARGET Avogadro::Vibrations APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Vibrations PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Vibrations.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Vibrations )
list(APPEND _cmake_import_check_files_for_Avogadro::Vibrations "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Vibrations.a" )

# Import target "Avogadro::VRML" for configuration "Release"
set_property(TARGET Avogadro::VRML APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::VRML PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/VRML.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::VRML )
list(APPEND _cmake_import_check_files_for_Avogadro::VRML "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/VRML.a" )

# Import target "Avogadro::Spectra" for configuration "Release"
set_property(TARGET Avogadro::Spectra APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Spectra PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Spectra.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Spectra )
list(APPEND _cmake_import_check_files_for_Avogadro::Spectra "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Spectra.a" )

# Import target "Avogadro::PlotPdf" for configuration "Release"
set_property(TARGET Avogadro::PlotPdf APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PlotPdf PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlotPdf.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PlotPdf )
list(APPEND _cmake_import_check_files_for_Avogadro::PlotPdf "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlotPdf.a" )

# Import target "Avogadro::PlotRmsd" for configuration "Release"
set_property(TARGET Avogadro::PlotRmsd APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PlotRmsd PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlotRmsd.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PlotRmsd )
list(APPEND _cmake_import_check_files_for_Avogadro::PlotRmsd "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlotRmsd.a" )

# Import target "Avogadro::PlotXrd" for configuration "Release"
set_property(TARGET Avogadro::PlotXrd APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PlotXrd PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlotXrd.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PlotXrd )
list(APPEND _cmake_import_check_files_for_Avogadro::PlotXrd "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PlotXrd.a" )

# Import target "Avogadro::Yaehmop" for configuration "Release"
set_property(TARGET Avogadro::Yaehmop APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Yaehmop PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Yaehmop.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Yaehmop )
list(APPEND _cmake_import_check_files_for_Avogadro::Yaehmop "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Yaehmop.a" )

# Import target "Avogadro::commands" for configuration "Release"
set_property(TARGET Avogadro::commands APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::commands PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/commands.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::commands )
list(APPEND _cmake_import_check_files_for_Avogadro::commands "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/commands.a" )

# Import target "Avogadro::QuantumInput" for configuration "Release"
set_property(TARGET Avogadro::QuantumInput APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::QuantumInput PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/QuantumInput.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::QuantumInput )
list(APPEND _cmake_import_check_files_for_Avogadro::QuantumInput "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/QuantumInput.a" )

# Import target "Avogadro::ScriptCharges" for configuration "Release"
set_property(TARGET Avogadro::ScriptCharges APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ScriptCharges PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ScriptCharges.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ScriptCharges )
list(APPEND _cmake_import_check_files_for_Avogadro::ScriptCharges "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ScriptCharges.a" )

# Import target "Avogadro::ScriptFileFormats" for configuration "Release"
set_property(TARGET Avogadro::ScriptFileFormats APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::ScriptFileFormats PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ScriptFileFormats.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::ScriptFileFormats )
list(APPEND _cmake_import_check_files_for_Avogadro::ScriptFileFormats "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/ScriptFileFormats.a" )

# Import target "Avogadro::PluginDownloader" for configuration "Release"
set_property(TARGET Avogadro::PluginDownloader APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::PluginDownloader PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PluginDownloader.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::PluginDownloader )
list(APPEND _cmake_import_check_files_for_Avogadro::PluginDownloader "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/PluginDownloader.a" )

# Import target "Avogadro::Symmetry" for configuration "Release"
set_property(TARGET Avogadro::Symmetry APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Symmetry PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Symmetry.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Symmetry )
list(APPEND _cmake_import_check_files_for_Avogadro::Symmetry "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Symmetry.a" )

# Import target "Avogadro::SymmetryScene" for configuration "Release"
set_property(TARGET Avogadro::SymmetryScene APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::SymmetryScene PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SymmetryScene.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::SymmetryScene )
list(APPEND _cmake_import_check_files_for_Avogadro::SymmetryScene "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SymmetryScene.a" )

# Import target "Avogadro::BallStick" for configuration "Release"
set_property(TARGET Avogadro::BallStick APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::BallStick PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/BallStick.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::BallStick )
list(APPEND _cmake_import_check_files_for_Avogadro::BallStick "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/BallStick.a" )

# Import target "Avogadro::Cartoons" for configuration "Release"
set_property(TARGET Avogadro::Cartoons APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Cartoons PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Cartoons.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Cartoons )
list(APPEND _cmake_import_check_files_for_Avogadro::Cartoons "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Cartoons.a" )

# Import target "Avogadro::CloseContacts" for configuration "Release"
set_property(TARGET Avogadro::CloseContacts APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::CloseContacts PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CloseContacts.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::CloseContacts )
list(APPEND _cmake_import_check_files_for_Avogadro::CloseContacts "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/CloseContacts.a" )

# Import target "Avogadro::Force" for configuration "Release"
set_property(TARGET Avogadro::Force APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Force PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Force.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Force )
list(APPEND _cmake_import_check_files_for_Avogadro::Force "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Force.a" )

# Import target "Avogadro::Licorice" for configuration "Release"
set_property(TARGET Avogadro::Licorice APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Licorice PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Licorice.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Licorice )
list(APPEND _cmake_import_check_files_for_Avogadro::Licorice "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Licorice.a" )

# Import target "Avogadro::SurfaceRender" for configuration "Release"
set_property(TARGET Avogadro::SurfaceRender APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::SurfaceRender PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SurfaceRender.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::SurfaceRender )
list(APPEND _cmake_import_check_files_for_Avogadro::SurfaceRender "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/SurfaceRender.a" )

# Import target "Avogadro::NonCovalent" for configuration "Release"
set_property(TARGET Avogadro::NonCovalent APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::NonCovalent PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/NonCovalent.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::NonCovalent )
list(APPEND _cmake_import_check_files_for_Avogadro::NonCovalent "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/NonCovalent.a" )

# Import target "Avogadro::VanDerWaals" for configuration "Release"
set_property(TARGET Avogadro::VanDerWaals APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::VanDerWaals PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/VanDerWaals.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::VanDerWaals )
list(APPEND _cmake_import_check_files_for_Avogadro::VanDerWaals "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/VanDerWaals.a" )

# Import target "Avogadro::Wireframe" for configuration "Release"
set_property(TARGET Avogadro::Wireframe APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::Wireframe PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Wireframe.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::Wireframe )
list(APPEND _cmake_import_check_files_for_Avogadro::Wireframe "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/Wireframe.a" )

# Import target "Avogadro::OverlayAxes" for configuration "Release"
set_property(TARGET Avogadro::OverlayAxes APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::OverlayAxes PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/OverlayAxes.a"
  )

list(APPEND _cmake_import_check_targets Avogadro::OverlayAxes )
list(APPEND _cmake_import_check_files_for_Avogadro::OverlayAxes "${_IMPORT_PREFIX}/lib/avogadro2/staticplugins/OverlayAxes.a" )

# Import target "Avogadro::QtPlugins" for configuration "Release"
set_property(TARGET Avogadro::QtPlugins APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Avogadro::QtPlugins PROPERTIES
  IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE "Avogadro::QtGui;Avogadro::Calc"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libAvogadroQtPlugins.1.101.0.dylib"
  IMPORTED_SONAME_RELEASE "/Users/daguila/avogadro/prefix/lib/libAvogadroQtPlugins.1.dylib"
  )

list(APPEND _cmake_import_check_targets Avogadro::QtPlugins )
list(APPEND _cmake_import_check_files_for_Avogadro::QtPlugins "${_IMPORT_PREFIX}/lib/libAvogadroQtPlugins.1.101.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
