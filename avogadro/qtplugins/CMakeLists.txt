find_package(Eigen3 REQUIRED)
include_directories(SYSTEM ${EIGEN3_INCLUDE_DIR})

find_package(Qt5 COMPONENTS Widgets Network Concurrent REQUIRED)
include_directories(SYSTEM ${Qt5Widgets_INCLUDE_DIRS})
add_definitions(${Qt5Widgets_DEFINITIONS})

# Modify the output directory for the build tree.
set(original_library_output_dir "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  "${original_library_output_dir}/avogadro2/plugins")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  "${original_library_output_dir}/avogadro2/staticplugins")

# Optionally build all plugins statically.
option(BUILD_STATIC_PLUGINS "Build static plugins by default" ON)

# Allow GPL plugins to be disabled.
option(BUILD_GPL_PLUGINS
  "Build plugins that are licensed under the GNU Public License." OFF)

# Create a plugin for Avogadro.
# name is the name of the plugin, this will be the name of the target created.
# description Free text description of the plugin.
# type The base class of the plugin.
# header is the header(s) for the class to be instantiated for the plugin.
# pluginClass is the class to be instantiated for the plugin.
# sources is the list of source files for the plugin.
# uis is the list of UI files that need to be compiled (optional).
# rcs is the list of qrc files that need to be compiled (optional).
function(avogadro_plugin name description type header pluginClass sources)
  set(uis "")
  set(rcs "")
  if(${ARGC} GREATER 6)
    set(uis ${ARGV6})
  endif()
  if(${ARGC} GREATER 7)
    set(rcs ${ARGV7})
  endif()
  qt5_wrap_ui(ui_srcs ${uis})
  qt5_add_resources(rc_srcs ${rcs})
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
  unset(PluginIncludes)
  foreach(_header ${header})
    set(PluginIncludes
      "${PluginIncludes}#include \"${CMAKE_CURRENT_SOURCE_DIR}/${_header}\"\n")
  endforeach()
  set(PluginName "${name}")
  set(PluginDescription "${description}")
  set(PluginType "${type}")
  set(PluginClass "${pluginClass}")
  configure_file("${AvogadroLibs_SOURCE_DIR}/cmake/avogadroplugin.cpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${name}Plugin.cpp")

  # Figure out which type of plugin is being added, and put it in the right list
  if(BUILD_STATIC_PLUGINS)
    set(_plugin_object "STATIC")
    set_property(GLOBAL APPEND PROPERTY AvogadroLibs_STATIC_PLUGINS ${name})
    if(rcs)
      get_filename_component(_name_we ${rcs} NAME_WE)
      set_property(GLOBAL APPEND PROPERTY AvogadroLibs_STATIC_RCS ${_name_we})
    endif()
  else()
    set(_plugin_object "MODULE")
    set_property(GLOBAL APPEND PROPERTY AvogadroLibs_PLUGINS ${name})
  endif()

  add_library(${name}
    ${_plugin_object}
    ${sources}
    ${ui_srcs}
    ${rc_srcs}
    ${name}Plugin.cpp
  )
  target_link_libraries(${name} PRIVATE AvogadroCore AvogadroQtGui)

  if("${_plugin_object}" STREQUAL "STATIC")
    set_target_properties(${name} PROPERTIES COMPILE_DEFINITIONS
      "QT_STATICPLUGIN")
    if(UNIX) # Need -fPIC for static plugins linked to shared libs on Unix.
      set_target_properties(${name} PROPERTIES COMPILE_FLAGS "-fPIC")
    endif()
  endif()

  set_target_properties(${name} PROPERTIES AUTOMOC TRUE PREFIX "")
  install(TARGETS ${name}
    EXPORT "AvogadroLibsTargets"
    RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/plugins"
    ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}/avogadro2/staticplugins")
endfunction()

# Now to make the plugins.
add_subdirectory(3dmol)
add_subdirectory(applycolors)
add_subdirectory(bondcentrictool)
add_subdirectory(bonding)
add_subdirectory(cartoons)
add_subdirectory(commandscripts)
add_subdirectory(coordinateeditor)
add_subdirectory(copypaste)
add_subdirectory(crystal)
add_subdirectory(customelements)
add_subdirectory(editor)
add_subdirectory(fetchpdb)
add_subdirectory(hydrogens)
add_subdirectory(importpqr)
add_subdirectory(insertfragment)
add_subdirectory(label)
add_subdirectory(lammpsinput)
add_subdirectory(lineformatinput)
add_subdirectory(manipulator)
add_subdirectory(measuretool)
add_subdirectory(molecularproperties)
add_subdirectory(mongochem)
add_subdirectory(navigator)
add_subdirectory(networkdatabases)
add_subdirectory(openbabel)
add_subdirectory(openmminput)
add_subdirectory(playertool)
add_subdirectory(propertytables)
add_subdirectory(povray)
add_subdirectory(resetview)
add_subdirectory(select)
add_subdirectory(selectiontool)
if(USE_SPGLIB)
  add_subdirectory(spacegroup)
endif()
add_subdirectory(surfaces)
add_subdirectory(svg)
add_subdirectory(spectra)
add_subdirectory(vrml)

# Plugins that require VTK
if(USE_VTK)
  add_subdirectory(plotpdf)
  add_subdirectory(plotrmsd)
  add_subdirectory(plotxrd)
  if(BUILD_YAEHMOP_PLUGIN)
    add_subdirectory(yaehmop)
  endif()
  add_subdirectory(coloropacitymap)
endif()

add_subdirectory(apbs)
add_subdirectory(cp2kinput)
add_subdirectory(gamessinput)
add_subdirectory(quantuminput)
add_subdirectory(scriptfileformats)

if(USE_LIBARCHIVE)
  add_subdirectory(plugindownloader)
endif()

if(USE_LIBMSYM)
  add_subdirectory(symmetry)
endif()

# The scene plugins
add_subdirectory(ballandstick)
add_subdirectory(licorice)
add_subdirectory(vanderwaals)
add_subdirectory(wireframe)
add_subdirectory(force)
add_subdirectory(meshes)
add_subdirectory(overlayaxes)
add_subdirectory(vanderwaalsao)
if (USE_PROTOCALL)
  add_subdirectory(clientserver)
endif()

if(BUILD_GPL_PLUGINS)
  # qtaimcurvature.h/cpp contains GPL licensed code:
  add_subdirectory(qtaim)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${original_library_output_dir}")

# Add all of the static plugins to the initialization file.
get_property(AvogadroLibs_STATIC_PLUGINS GLOBAL
  PROPERTY AvogadroLibs_STATIC_PLUGINS)
get_property(AvogadroLibs_STATIC_RCS GLOBAL
  PROPERTY AvogadroLibs_STATIC_RCS)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
  "// Automatically generated file. Do not edit.
#ifndef AVOGADRO_STATIC_QTPLUGINS_H
#define AVOGADRO_STATIC_QTPLUGINS_H

#include <QtCore/QtPlugin>\n\n")

foreach(_plugin ${AvogadroLibs_STATIC_PLUGINS})
  file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
    "Q_IMPORT_PLUGIN(${_plugin}Factory)\n")
endforeach()
file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
  "\nvoid initAvogadroPluginResources() {\n")
foreach(_rcs ${AvogadroLibs_STATIC_RCS})
  file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
    "  Q_INIT_RESOURCE(${_rcs});\n")
endforeach()
file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
  "}\n\n")

file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
  "\n#endif // AVOGADRO_STATIC_QTPLUGINS_H\n")

# Configure the static plugin header, ensuring it only changes if the contents
# are modified - otherwise the original timestamp will be maintained.
configure_file("${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h")

# Now to build the plugin library, which can also statically link plugins
# and initialize them for the application. If Avogadro is built statically
# then the static plugin header must be included by the application.
set(HEADERS
  pluginmanager.h
  pluginfactory.h
  "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h"
)

set(SOURCES
  pluginmanager.cpp
)

avogadro_add_library(AvogadroQtPlugins ${HEADERS} ${SOURCES})
target_link_libraries(AvogadroQtPlugins PUBLIC ${Qt5Core_LIBRARIES}
  PRIVATE ${AvogadroLibs_STATIC_PLUGINS} AvogadroQtGui)
