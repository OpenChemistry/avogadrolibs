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

target_link_libraries(ScriptCharges PRIVATE AvogadroCalc )

# Bundled format scripts:
set(charge_scripts
  chargeScripts/xtb.py
  chargeScripts/antechamber.py
)

install(PROGRAMS ${charge_scripts}
  DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/charges/")
