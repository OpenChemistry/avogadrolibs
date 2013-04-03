set(quantumoutput_srcs
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

target_link_libraries(QuantumOutput LINK_PRIVATE AvogadroQuantumIO)
