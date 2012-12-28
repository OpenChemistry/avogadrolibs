find_package(MoleQueue)
include_directories(${MoleQueue_INCLUDE_DIRS})

# Extension
set(quantuminput_srcs
  gamessinputdialog.cpp
  gamesshighlighter.cpp
  quantuminput.cpp
)

avogadro_plugin(QuantumInput
  "Quantum input file generation"
  ExtensionPlugin
  quantuminput.h
  QuantumInput
  "${quantuminput_srcs}"
  gamessinputdialog.ui
)

target_link_libraries(QuantumInput LINK_PRIVATE MoleQueueClient)
