# Extension
set(cp2kinput_srcs
  cp2kinputdialog.cpp
  cp2kinput.cpp
)

avogadro_plugin(Cp2kInput
  "CP2K input file generation"
  ExtensionPlugin
  cp2kinput.h
  Cp2kInput
  "${cp2kinput_srcs}"
  cp2kinputdialog.ui
)

target_link_libraries(Cp2kInput PRIVATE AvogadroMoleQueue)
