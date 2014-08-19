cmake_minimum_required(VERSION 2.8)

set(spglib_SRCS
  cell.c
  debug.c
  hall_symbol.c
  lattice.c
  mathfunc.c
  pointgroup.c
  primitive.c
  refinement.c
  spacegroup.c
  spg_database.c
  spglib.c
  symmetry.c
  kpoint.c
  site_symmetry.c
  sitesym_database.c
  spglib_f.c
  spin.c
  tetrahedron_method.c
)

add_library(spglib ${spglib_SRCS})
target_link_libraries(spglib m)

# Suppress spglib warnings
set_target_properties(spglib PROPERTIES
  COMPILE_FLAGS "-w"
  OUTPUT_NAME avogadro_spglib
  LABELS spglib)

#include_directories(${CMAKE_CURRENT_SOURCE_DIR})
