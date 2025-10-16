# Install script for directory: /Users/daguila/OSS/avogadrolibs/avogadro/molequeue

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
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroMoleQueue.1.101.0.dylib"
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroMoleQueue.1.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroMoleQueue.1.101.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroMoleQueue.1.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND "/usr/bin/install_name_tool"
        -id "/Users/daguila/avogadro/prefix/lib/libAvogadroMoleQueue.1.dylib"
        -change "@rpath/libAvogadroCore.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroCore.1.dylib"
        -change "@rpath/libAvogadroIO.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroIO.1.dylib"
        -change "@rpath/libAvogadroQtGui.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroQtGui.1.dylib"
        "${file}")
      execute_process(COMMAND /usr/bin/install_name_tool
        -delete_rpath "/Users/daguila/OSS/avogadrolibs/build/lib"
        "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" -x "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroMoleQueue.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/molequeue" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/batchjob.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/inputgenerator.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/inputgeneratordialog.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/inputgeneratorwidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/molequeuedialog.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/molequeuemanager.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/molequeuequeuelistmodel.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/molequeue/molequeuewidget.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/molequeue/avogadromolequeueexport.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/daguila/OSS/avogadrolibs/build/avogadro/molequeue/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
