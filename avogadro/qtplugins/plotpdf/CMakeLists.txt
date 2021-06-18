set(plotpdf_srcs
  plotpdf.cpp
  pdfoptionsdialog.cpp
)

set(plotpdf_uis
  pdfoptionsdialog.ui
)

avogadro_plugin(PlotPdf
  "Create a pair distribution plot."
  ExtensionPlugin
  plotpdf.h
  PlotPdf
  "${plotpdf_srcs}"
  "${plotpdf_uis}"
)

target_link_libraries(PlotPdf PRIVATE AvogadroVtk)
