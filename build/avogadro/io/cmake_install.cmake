# Install script for directory: /Users/daguila/OSS/avogadrolibs/avogadro/io

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroIO.1.101.0.dylib"
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroIO.1.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroIO.1.101.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroIO.1.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND "/usr/bin/install_name_tool"
        -id "/Users/daguila/avogadro/prefix/lib/libAvogadroIO.1.dylib"
        -change "@rpath/libAvogadroCore.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroCore.1.dylib"
        "${file}")
      execute_process(COMMAND /usr/bin/install_name_tool
        -delete_rpath "/Users/daguila/OSS/avogadrolibs/build/lib"
        -add_rpath "/Users/daguila/avogadro/prefix/lib"
        "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" -x "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroIO.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/io" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/cjsonformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/cmlformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/cmsgpackformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/dcdformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/fileformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/fileformatmanager.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/gromacsformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/mdlformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/lammpsformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/pdbformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/sdfformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/trrformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/turbomoleformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/vaspformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/io/xyzformat.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/io/avogadroioexport.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/daguila/OSS/avogadrolibs/build/avogadro/io/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
