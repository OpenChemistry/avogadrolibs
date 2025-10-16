# Install script for directory: /Users/daguila/OSS/avogadrolibs/avogadro/qtplugins

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

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/3dmol/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/alchemy/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/aligntool/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/apbs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/applycolors/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/autoopt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/bondcentrictool/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/bonding/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/centroid/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/configurepython/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/constraints/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/coordinateeditor/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/copypaste/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/cp2kinput/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/crystal/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/customelements/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/dipole/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/editor/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/fetchpdb/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/focus/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/forcefield/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/gamessinput/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/hydrogens/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/importpqr/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/insertdna/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/insertfragment/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/label/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/lammpsinput/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/lineformatinput/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/manipulator/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/measuretool/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/molecularproperties/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/navigator/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/networkdatabases/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/openbabel/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/openmminput/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/playertool/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/ply/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/povray/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/propertytables/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/resetview/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/select/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/selectiontool/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/spacegroup/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/surfaces/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/svg/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/templatetool/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/vibrations/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/vrml/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/spectra/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/plotpdf/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/plotrmsd/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/plotxrd/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/yaehmop/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/commandscripts/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/quantuminput/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/scriptcharges/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/scriptfileformats/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/plugindownloader/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/symmetry/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/ballandstick/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/cartoons/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/closecontacts/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/force/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/licorice/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/surfacerender/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/noncovalent/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/vanderwaals/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/wireframe/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/overlayaxes/cmake_install.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroQtPlugins.1.101.0.dylib"
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroQtPlugins.1.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroQtPlugins.1.101.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroQtPlugins.1.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND "/usr/bin/install_name_tool"
        -id "/Users/daguila/avogadro/prefix/lib/libAvogadroQtPlugins.1.dylib"
        -change "@rpath/libAvogadroCalc.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroCalc.1.dylib"
        -change "@rpath/libAvogadroCore.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroCore.1.dylib"
        -change "@rpath/libAvogadroIO.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroIO.1.dylib"
        -change "@rpath/libAvogadroMoleQueue.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroMoleQueue.1.dylib"
        -change "@rpath/libAvogadroQtGui.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroQtGui.1.dylib"
        -change "@rpath/libAvogadroQtOpenGL.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroQtOpenGL.1.dylib"
        -change "@rpath/libAvogadroQuantumIO.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroQuantumIO.1.dylib"
        -change "@rpath/libAvogadroRendering.1.dylib" "/Users/daguila/avogadro/prefix/lib/libAvogadroRendering.1.dylib"
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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroQtPlugins.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/qtplugins" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/pluginmanager.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/pluginfactory.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/avogadrostaticqtplugins.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/avogadroqtpluginsexport.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/daguila/OSS/avogadrolibs/build/avogadro/qtplugins/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
