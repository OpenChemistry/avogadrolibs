find_package(Eigen3 REQUIRED)

# configure the version header
configure_file("${PROJECT_SOURCE_DIR}/cmake/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/version.h")

# Separate out header only components into an interface library.
add_library(Headers INTERFACE)
add_library(Avogadro::Headers ALIAS Headers)
target_include_directories(Headers
  INTERFACE
    "$<INSTALL_INTERFACE:${INSTALL_INCLUDE_DIR}>")

target_sources(Headers PUBLIC
  FILE_SET HEADERS
  BASE_DIRS ${PROJECT_SOURCE_DIR}
  FILES
    angletools.h
    angleiterator.h
    array.h
    avogadrocore.h
    color3f.h
    constraint.h
    contrastcolor.h
    coordinateset.h
    matrix.h
    types.h
    utilities.h
    vector.h
)
target_link_libraries(Headers INTERFACE Eigen3::Eigen)
install(TARGETS Headers
  EXPORT "AvogadroLibsTargets"
  FILE_SET HEADERS DESTINATION "${INSTALL_INCLUDE_DIR}")

# Now add the main core library for Avogadro.
add_library(Core)

avogadro_headers(Core
  atom.h
  atomtyper.h
  atomtyper-inline.h
  atomutilities.h
  basisset.h
  bond.h
  coordinateblockgenerator.h
  crystaltools.h
  cube.h
  dihedraliterator.h
  elements.h
  gaussianset.h
  gaussiansettools.h
  graph.h
  layer.h
  layermanager.h
  mesh.h
  molecule.h
  mutex.h
  nameatomtyper.h
  neighborperceiver.h
  residue.h
  ringperceiver.h
  secondarystructure.h
  slaterset.h
  slatersettools.h
  spacegroups.h
  symbolatomtyper.h
  unitcell.h
  variant.h
  variant-inline.h
  variantmap.h
  "${CMAKE_CURRENT_BINARY_DIR}/version.h"
)

target_sources(Core PRIVATE
  angleiterator.cpp
  atomutilities.cpp
  coordinateblockgenerator.cpp
  crystaltools.cpp
  cube.cpp
  elements.cpp
  dihedraliterator.cpp
  gaussianset.cpp
  gaussiansettools.cpp
  graph.cpp
  layer.cpp
  layermanager.cpp
  mesh.cpp
  mdlvalence_p.h
  molecule.cpp
  mutex.cpp
  nameatomtyper.cpp
  neighborperceiver.cpp
  residue.cpp
  ringperceiver.cpp
  secondarystructure.cpp
  slaterset.cpp
  slatersettools.cpp
  spacegroups.cpp
  symbolatomtyper.cpp
  unitcell.cpp
  variantmap.cpp
  version.cpp
)

# We currently build core without shared_mutex for Python wheels.
if(NOT PYTHON_WHEEL_BUILD)
  avogadro_headers(Core sharedmutex.h)
  target_sources(Core PRIVATE sharedmutex.cpp)
endif()

if(USE_SPGLIB)
  find_package(Spglib REQUIRED)
  avogadro_headers(Core avospglib.h)
  target_sources(Core PRIVATE avospglib.cpp)
  target_link_libraries(Core PRIVATE Spglib::symspg)
endif()

# The std::shared_mutex class needs pthreads on Linux.
if(UNIX AND NOT APPLE AND NOT PYTHON_WHEEL_BUILD)
  find_package(Threads)
  target_link_libraries(Core PRIVATE ${CMAKE_THREAD_LIBS_INIT})
endif()

avogadro_add_library(Core)
target_link_libraries(Core
  PUBLIC Avogadro::Headers)
