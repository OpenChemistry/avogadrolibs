set(HEADERS
  atom.h
  bond.h
  graph.h
  molcore.h
  molecule.h
  ringperceiver.h
  variant.h
  variant-inline.h
  variantmap.h
)

set(SOURCES
  atom.cpp
  bond.cpp
  graph.cpp
  molecule.cpp
  ringperceiver.cpp
  variantmap.cpp
)

add_library(MolCore SHARED ${SOURCES})
