add_library(IO)

avogadro_headers(IO
  cjsonformat.h
  cmlformat.h
  cmsgpackformat.h
  dcdformat.h
  fileformat.h
  fileformatmanager.h
  gromacsformat.h
  mdlformat.h
  lammpsformat.h
  pdbformat.h
  sdfformat.h
  trrformat.h
  turbomoleformat.h
  vaspformat.h
  xyzformat.h
)

target_sources(IO PRIVATE
  cjsonformat.cpp
  cmlformat.cpp
  cmsgpackformat.cpp
  dcdformat.cpp
  fileformat.cpp
  fileformatmanager.cpp
  gromacsformat.cpp
  lammpsformat.cpp
  mdlformat.cpp
  pdbformat.cpp
  sdfformat.cpp
  trrformat.cpp
  turbomoleformat.cpp
  vaspformat.cpp
  xyzformat.cpp
)

if(USE_HDF5)
  find_package(HDF5 REQUIRED COMPONENTS C)
  target_compile_definitions(IO PRIVATE AVO_USE_HDF5 H5_USE_110_API)
  avogadro_headers(IO hdf5dataformat.h)
  target_sources(IO PRIVATE hdf5dataformat.cpp)
  target_link_libraries(IO PRIVATE hdf5::hdf5)
endif()

if(USE_MMTF)
  find_package(MMTF REQUIRED)
  target_compile_definitions(IO PRIVATE AVO_USE_MMTF)
  avogadro_headers(IO mmtfformat.h)
  target_sources(IO PRIVATE mmtfformat.cpp)
  target_link_libraries(IO PRIVATE mmtf::mmtf)
endif()

avogadro_add_library(IO)

target_link_libraries(IO
  PUBLIC Avogadro::Core
  PRIVATE struct pugixml::pugixml nlohmann_json::nlohmann_json)
if(WIN32)
  target_link_libraries(IO PRIVATE ws2_32)
endif()
