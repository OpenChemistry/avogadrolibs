set(quantumoutput_srcs
  quantumoutput.cpp
)

avogadro_plugin(QuantumOutput
  "Quantum output"
  ExtensionPlugin
  quantumoutput.h
  QuantumOutput
  "${quantumoutput_srcs}"
  ""
)

target_link_libraries(QuantumOutput LINK_PRIVATE AvogadroQuantumIO)
