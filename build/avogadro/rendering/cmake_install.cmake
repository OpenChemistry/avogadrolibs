# Install script for directory: /Users/daguila/OSS/avogadrolibs/avogadro/rendering

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
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroRendering.1.101.0.dylib"
    "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroRendering.1.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroRendering.1.101.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libAvogadroRendering.1.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND "/usr/bin/install_name_tool"
        -id "/Users/daguila/avogadro/prefix/lib/libAvogadroRendering.1.dylib"
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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/daguila/OSS/avogadrolibs/build/lib/libAvogadroRendering.dylib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/avogadro/rendering" TYPE FILE FILES
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/arcsector.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/arcstrip.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/arrowgeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/avogadrogl.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/avogadrorendering.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/beziergeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/bsplinegeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/bufferobject.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/camera.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/cartoongeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/curvegeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/cylindergeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/dashedlinegeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/drawable.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/geometrynode.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/geometryvisitor.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/groupnode.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/glrenderer.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/glrendervisitor.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/linestripgeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/meshgeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/node.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/plyvisitor.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/povrayvisitor.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/primitive.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/quad.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/quadoutline.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/scene.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/shader.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/shaderprogram.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/solidpipeline.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/spheregeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/textlabel2d.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/textlabel3d.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/textlabelbase.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/textproperties.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/textrenderstrategy.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/texture2d.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/transformnode.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/visitor.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/volumegeometry.h"
    "/Users/daguila/OSS/avogadrolibs/avogadro/rendering/vrmlvisitor.h"
    "/Users/daguila/OSS/avogadrolibs/build/avogadro/rendering/avogadrorenderingexport.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/daguila/OSS/avogadrolibs/build/avogadro/rendering/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
