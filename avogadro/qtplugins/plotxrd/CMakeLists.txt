find_package(VTK REQUIRED)
include(${VTK_USE_FILE})

include_directories(SYSTEM ${VTK_INCLUDE_DIRS})

# Download the executable if we are not to use the system one
if(NOT USE_SYSTEM_GENXRDPATTERN)
  include(DownloadGenXrdPattern)
  DownloadGenXrdPattern()
endif(NOT USE_SYSTEM_GENXRDPATTERN)

set(plotxrd_srcs
  plotxrd.cpp
  xrdoptionsdialog.cpp
  xrdvtkplot.cpp
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

target_link_libraries(PlotXrd LINK_PRIVATE ${VTK_LIBRARIES})
