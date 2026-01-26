# Download the executable if we are not to use the system one
if(APPLE OR WIN32 OR INSTALL_BUNDLE_FILES)
  option(USE_SYSTEM_GENXRDPATTERN "Use the system genxrdpattern" OFF)
else()
  option(USE_SYSTEM_GENXRDPATTERN "Use the system genxrdpattern" ON)
endif()
mark_as_advanced(USE_SYSTEM_GENXRDPATTERN)

if(NOT USE_SYSTEM_GENXRDPATTERN)
  include(DownloadGenXrdPattern)
  DownloadGenXrdPattern()
endif()

set(plotxrd_srcs
  plotxrd.cpp
  xrdoptionsdialog.cpp
)

set(plotxrd_uis
  xrdoptionsdialog.ui
)

avogadro_plugin(PlotXrd
  "Use ObjCryst++ to create an XRD plot."
  ExtensionPlugin
  plotxrd.h
  PlotXrd
  "${plotxrd_srcs}"
  "${plotxrd_uis}"
)

# target_link_libraries(PlotXrd PRIVATE Avogadro::Vtk)
