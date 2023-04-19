add_library(Calc)

avogadro_headers(Calc
  chargemodel.h
  chargemanager.h
  defaultmodel.h
)

target_sources(Calc PRIVATE
  chargemodel.cpp
  chargemanager.cpp
  defaultmodel.cpp
)

avogadro_add_library(Calc)

target_link_libraries(Calc
  PUBLIC Avogadro::Core)
