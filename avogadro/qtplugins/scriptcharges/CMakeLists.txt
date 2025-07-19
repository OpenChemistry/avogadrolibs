set(scriptcharges_srcs
  scriptchargemodel.cpp
  scriptcharges.cpp
)

avogadro_plugin(ScriptCharges
  "Scriptable electrostatics models"
  ExtensionPlugin
  scriptcharges.h
  ScriptCharges
  "${scriptcharges_srcs}"
  ""
)

target_link_libraries(ScriptCharges PRIVATE Avogadro::Calc )

# charge scripts are now download only
