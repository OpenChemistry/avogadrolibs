# Extension
set(gamessinput_srcs
  lammpsinputdialog.cpp
  lammpsinput.cpp
)

avogadro_plugin(LammpsInput
  "LAMMPS input file generation"
  ExtensionPlugin
  lammpsinput.h
  LammpsInput
  "${gamessinput_srcs}"
  lammpsinputdialog.ui
)

target_link_libraries(LammpsInput)
