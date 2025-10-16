# Install script for directory: /Users/daguila/OSS/avogadrolibs/avogadro/qtgui

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
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroQtGui.1.101.0.dylib"
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroQtGui.1.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroQtGui.1.101.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroQtGui.1.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND "/usr/bin/install_name_tool"
        -id "/Users/daguila/avogadro/prefix/lib/libAvogadroQtGui.1.dylib"
        -change "@rpath/libAvogadroCore.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroCore.1.dylib"
        -change "@rpath/libAvogadroIO.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroIO.1.dylib"
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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroQtGui.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/qtgui" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/backgroundfileformat.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/chartdialog.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/chartwidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/colorbutton.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/containerwidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/customelementdialog.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/elementtranslator.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/extensionplugin.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/filebrowsewidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/fileformatdialog.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/gaussiansetconcurrent.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/generichighlighter.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/hydrogentools.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/insertfragmentdialog.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/interfacescript.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/interfacewidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/jsonwidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/layermodel.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/rwlayermanager.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/meshgenerator.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/molecule.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/moleculemodel.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/multiviewwidget.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/periodictableview.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/persistentatom.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/persistentbond.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/pluginlayermanager.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/pythonscript.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/richtextdelegate.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/rwmolecule.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/sceneplugin.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/scenepluginmodel.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/scriptloader.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/slatersetconcurrent.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/sortfiltertreeproxymodel.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/toolplugin.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/utilities.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtgui/viewfactory.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/qtgui/avogadroqtguiexport.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/daguila/OSS/avogadrolibs/build/avogadro/qtgui/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
