add_library(QuantumIO)

avogadro_headers(QuantumIO
  gamessus.h
  gaussianfchk.h
  gaussiancube.h
  genericoutput.h
  molden.h
  mopacaux.h
  nwchemjson.h
  nwchemlog.h
  orca.h
)

# Source files for our data.
target_sources(QuantumIO PRIVATE
  gamessus.cpp
  gaussianfchk.cpp
  gaussiancube.cpp
  genericoutput.cpp
  molden.cpp
  mopacaux.cpp
  nwchemjson.cpp
  nwchemlog.cpp
  orca.cpp
)

avogadro_add_library(QuantumIO)
target_link_libraries(QuantumIO
  PUBLIC Avogadro::IO
  PRIVATE nlohmann_json::nlohmann_json
)
