# Install script for directory: /Users/daguila/OSS/avogadrolibs/avogadro/core

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/Users/daguila/avogadro/prefix")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/core" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/angletools.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/angleiterator.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/array.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/avogadrocore.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/color3f.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/constraint.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/contrastcolor.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/coordinateset.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/matrix.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/types.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/utilities.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/vector.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroCore.1.101.0.dylib"
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroCore.1.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroCore.1.101.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroCore.1.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND "/usr/bin/install_name_tool"
        -id "/Users/daguila/avogadro/prefix/lib/libAvogadroCore.1.dylib"
        "${file}")
      execute_process(COMMAND /usr/bin/install_name_tool
        -add_rpath "/Users/daguila/avogadro/prefix/lib"
        "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" -x "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroCore.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/core" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/atom.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/atomtyper.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/atomtyper-inline.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/atomutilities.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/basisset.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/bond.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/coordinateblockgenerator.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/crystaltools.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/cube.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/dihedraliterator.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/elements.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/gaussianset.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/gaussiansettools.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/graph.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/layer.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/layermanager.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/mesh.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/molecule.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/mutex.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/nameatomtyper.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/neighborperceiver.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/residue.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/ringperceiver.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/secondarystructure.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/slaterset.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/slatersettools.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/spacegroups.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/symbolatomtyper.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/unitcell.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/variant.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/variant-inline.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/variantmap.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/core/version.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/sharedmutex.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/core/avospglib.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/core/avogadrocoreexport.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/daguila/OSS/avogadrolibs/build/avogadro/core/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
