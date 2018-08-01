# Extension
set(openmminput_srcs
  openmminputdialog.cpp
  openmminput.cpp
)

avogadro_plugin(OpenMMInput
  "OpenMM input script generation"
  ExtensionPlugin
  openmminput.h
  OpenMMInput
  "${openmminput_srcs}"
  openmminputdialog.ui
)

target_link_libraries(OpenMMInput)
