add_library(Calc)

avogadro_headers(Calc
  chargemodel.h
  chargemanager.h
  defaultmodel.h
  energycalculator.h
  energymanager.h
  gradients.h
  lennardjones.h
  uff.h
  uffdata.h
)

target_sources(Calc PRIVATE
  chargemodel.cpp
  chargemanager.cpp
  defaultmodel.cpp
  energycalculator.cpp
  energymanager.cpp
  lennardjones.cpp
  uff.cpp
)

avogadro_add_library(Calc)

target_link_libraries(Calc
  PUBLIC Avogadro::Core cppoptlib)
