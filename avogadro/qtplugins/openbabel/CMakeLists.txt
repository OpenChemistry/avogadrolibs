set(openbabel_srcs
  obprocess.cpp
  openbabel.cpp
)

avogadro_plugin(OpenBabel
  "OpenBabel extension"
  ExtensionPlugin
  openbabel.h
  OpenBabel
  "${openbabel_srcs}"
  ""
)

target_link_libraries(OpenBabel LINK_PRIVATE AvogadroIO)
