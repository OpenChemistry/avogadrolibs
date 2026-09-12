add_library(IO)

avogadro_headers(IO
  cjsonformat.h
  cmlformat.h
  compressedstream.h
  compression.h
  dcdformat.h
  fileformat.h
  fileformatmanager.h
  gromacsformat.h
  mdlformat.h
  lammpsformat.h
  pdbformat.h
  sdfformat.h
  smilesformat.h
  smilesparser.h
  smileswriter.h
  trrformat.h
  turbomoleformat.h
  vaspformat.h
  xyzformat.h
)

target_sources(IO PRIVATE
  binaryblock_p.h
  cjsonformat.cpp
  cmlformat.cpp
  compressedstream.cpp
  compression.cpp
  dcdformat.cpp
  fileformat.cpp
  fileformatmanager.cpp
  gromacsformat.cpp
  lammpsformat.cpp
  mdlformat.cpp
  pdbformat.cpp
  sdfformat.cpp
  atomequivalence_p.h
  smilesformat.cpp
  smilesparser.cpp
  smilesvalence_p.h
  smileswriter.cpp
  trrformat.cpp
  turbomoleformat.cpp
  vaspformat.cpp
  xyzformat.cpp
)

# Transparent decompression of .gz/.bz2/.xz/.zst input, and the matching
# compressed output. zlib handles gzip because libarchive does not verify gzip
# checksums; libarchive handles the rest.
#
# Note that gzip alone needs only zlib, so a build with zlib but no libarchive
# could in principle still read the commonest case (.pdb.gz, .cif.gz). Both are
# deliberately gated together on the one existing USE_LIBARCHIVE option, which
# the package installer plugin already uses, rather than introducing a second
# switch; decoupling gzip would be a worthwhile follow-up for minimal builds
# and the Python wheels, which set USE_LIBARCHIVE=OFF.
if(USE_LIBARCHIVE)
  find_package(LibArchive)
  find_package(ZLIB)
  if(LibArchive_FOUND AND ZLIB_FOUND)
    target_compile_definitions(IO PRIVATE AVO_USE_LIBARCHIVE)
    target_link_libraries(IO PRIVATE LibArchive::LibArchive ${ZLIB_LIBRARIES})

    # Do not inherit zlib's include directory blindly. On Unix it is the
    # platform's own header directory, and adding that to the search path
    # reorders the standard headers. With both Xcode and the Command Line
    # Tools installed, FindZLIB picks the Command Line Tools SDK while the
    # compiler's sysroot is Xcode's, and mixing the two breaks libc++'s
    # <complex> on the math.h isnan/isinf macros. CMake drops include
    # directories it knows are implicit, but a second SDK's path is not one of
    # them. So add it only when zlib.h cannot be found without it, which is
    # exactly the case that needs it (vcpkg, Conda, a custom prefix).
    include(CheckIncludeFile)
    check_include_file(zlib.h AvogadroLibs_ZLIB_H_IN_DEFAULT_PATH)
    if(NOT AvogadroLibs_ZLIB_H_IN_DEFAULT_PATH)
      target_include_directories(IO SYSTEM PRIVATE ${ZLIB_INCLUDE_DIRS})
    endif()
  else()
    message(STATUS
      "libarchive or zlib not found: compressed file support disabled")
  endif()
endif()

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
