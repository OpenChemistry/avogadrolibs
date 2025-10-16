# AvogadroLibs CMake configuration file - http://www.openchemistry.org/

# If this file was found, then OpenQube has been found
set(AvogadroLibs_FOUND 1)

set(AvogadroLibs_VERSION_MAJOR   "1")
set(AvogadroLibs_VERSION_MINOR   "101")
set(AvogadroLibs_VERSION_PATCH   "0")
set(AvogadroLibs_VERSION         "${AvogadroLibs_VERSION_MAJOR}.${AvogadroLibs_VERSION_MINOR}.${AvogadroLibs_VERSION_PATCH}")

set(AvogadroLibs_INSTALL_PREFIX  "/Users/daguila/avogadro/prefix")
set(AvogadroLibs_INCLUDE_DIRS    "${AvogadroLibs_INSTALL_PREFIX}/include")
set(AvogadroLibs_LIBRARY_DIR     "${AvogadroLibs_INSTALL_PREFIX}/lib")
set(AvogadroLibs_RUNTIME_DIR     "${AvogadroLibs_INSTALL_PREFIX}/bin")
set(AvogadroLibs_DATA_DIR        "${AvogadroLibs_INSTALL_PREFIX}/share")
set(AvogadroLibs_CMAKE_DIR       "${AvogadroLibs_LIBRARY_DIR}/cmake/avogadrolibs")

# List of target names that are plugins:
set(AvogadroLibs_PLUGINS         "")
set(AvogadroLibs_STATIC_PLUGINS  "ThreeDMol;Alchemy;AlignTool;apbs;ApplyColors;AutoOpt;BondCentric;Bonding;Centroid;ConfigurePython;ConstraintsExtension;CoordinateEditor;CopyPaste;Cp2kInput;Crystal;CrystalScene;CustomElements;Dipole;Editor;FetchPDB;Focus;Forcefield;GamessInput;Hydrogens;ImportPQR;NucleicInput;InsertFragment;Label;LabelEditor;LammpsInput;LineFormatInput;Manipulator;MeasureTool;MolecularProperties;Navigator;NetworkDatabases;OpenBabel;OpenMMInput;PlayerTool;PLY;POVRay;PropertyTables;ResetView;Select;Selection;SpaceGroup;Surfaces;Orbitals;SVG;TemplateTool;Vibrations;VRML;Spectra;PlotPdf;PlotRmsd;PlotXrd;Yaehmop;commands;QuantumInput;ScriptCharges;ScriptFileFormats;PluginDownloader;Symmetry;SymmetryScene;BallStick;Cartoons;CloseContacts;Force;Licorice;SurfaceRender;NonCovalent;VanDerWaals;Wireframe;OverlayAxes")

include(CMakeFindDependencyMacro)

if (5 EQUAL 6)
  find_dependency(Qt6OpenGLWidgets)
  find_dependency(Qt6Widgets)
  find_dependency(Qt6Core)
  find_dependency(Qt6Gui)
  find_dependency(Qt6Network)
  find_dependency(Qt6Concurrent)
endif()

if(NOT TARGET AvogadroCore)
  include("${AvogadroLibs_CMAKE_DIR}/AvogadroLibsTargets.cmake")
endif()
