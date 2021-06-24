set(plotrmsd_srcs
  plotrmsd.cpp
)

avogadro_plugin(PlotRmsd
  "Create an RMSD plot."
  ExtensionPlugin
  plotrmsd.h
  PlotRmsd
  "${plotrmsd_srcs}"
  ""
)

target_link_libraries(PlotRmsd PRIVATE AvogadroVtk)
