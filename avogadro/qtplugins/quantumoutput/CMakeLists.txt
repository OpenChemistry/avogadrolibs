find_package(Qt5Concurrent REQUIRED)
include_directories(SYSTEM ${Qt5Concurrent_INCLUDE_DIRS})
add_definitions(${Qt5Concurrent_DEFINITIONS})

set(quantumoutput_srcs
  gaussiansetconcurrent.cpp
  slatersetconcurrent.cpp
  surfacedialog.cpp
  quantumoutput.cpp
)

avogadro_plugin(QuantumOutput
  "Quantum output"
  ExtensionPlugin
  quantumoutput.h
  QuantumOutput
  "${quantumoutput_srcs}"
  "surfacedialog.ui"
)

target_link_libraries(QuantumOutput
  LINK_PRIVATE AvogadroQuantumIO ${Qt5Concurrent_LIBRARIES})
