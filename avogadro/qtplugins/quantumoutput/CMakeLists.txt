find_package(Qt5Concurrent REQUIRED)
include_directories(SYSTEM ${Qt5Concurrent_INCLUDE_DIRS})
add_definitions(${Qt5Concurrent_DEFINITIONS})

set(quantumoutput_srcs
  gaussiansetconcurrent.cpp
  slatersetconcurrent.cpp
  surfacedialog.cpp
  quantumoutput.cpp
)

set(quantumoutput_hs
  quantumoutput.h
)

set(quantumoutput_uis
  surfacedialog.ui
)

avogadro_plugin(QuantumOutput
  "Quantum output"
  ExtensionPlugin
  "${quantumoutput_hs}"
  QuantumOutput
  "${quantumoutput_srcs}"
  "${quantumoutput_uis}"
)

target_link_libraries(QuantumOutput
  LINK_PRIVATE AvogadroQuantumIO ${Qt5Concurrent_LIBRARIES})

# NewQuantumOutput Plugin
set(newquantumoutput_srcs
  newsurfacedialog.cpp
  newquantumoutput.cpp
)

set(newquantumoutput_hs
  newquantumoutput.h
)

set(newquantumoutput_uis
  newsurfacedialog.ui
)

avogadro_plugin(NewQuantumOutput
  "NEW Quantum output"
  ExtensionPlugin
  "${newquantumoutput_hs}"
  NewQuantumOutput
  "${newquantumoutput_srcs}"
  "${newquantumoutput_uis}"
)

target_link_libraries(NewQuantumOutput
  LINK_PRIVATE AvogadroQuantumIO ${Qt5Concurrent_LIBRARIES})
