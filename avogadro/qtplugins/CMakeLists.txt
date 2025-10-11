find_package(Qt${QT_VERSION} COMPONENTS Widgets Network Concurrent REQUIRED)
if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS OpenGLWidgets REQUIRED)
endif()

if(WIN32)
  # used for HTTPS (e.g., PQR, downloads, etc.)
  find_package(OpenSSL REQUIRED)
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)

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
  qt_wrap_ui(ui_srcs ${uis})
  qt_add_resources(rc_srcs ${rcs})
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
  target_link_libraries(${name} PRIVATE Avogadro::QtGui)

  if("${_plugin_object}" STREQUAL "STATIC")
    set_target_properties(${name} PROPERTIES COMPILE_DEFINITIONS
      "QT_STATICPLUGIN")
    if(UNIX)
      set_target_properties(${name} PROPERTIES POSITION_INDEPENDENT_CODE ON)
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
add_subdirectory(alchemy)
add_subdirectory(aligntool)
add_subdirectory(apbs)
add_subdirectory(applycolors)
add_subdirectory(autoopt)
add_subdirectory(bondcentrictool)
add_subdirectory(bonding)
add_subdirectory(centroid)
add_subdirectory(configurepython)
add_subdirectory(constraints)
add_subdirectory(coordinateeditor)
add_subdirectory(copypaste)
add_subdirectory(cp2kinput)
add_subdirectory(crystal)
add_subdirectory(customelements)
add_subdirectory(dipole)
add_subdirectory(editor)
add_subdirectory(fetchpdb)
add_subdirectory(focus)
add_subdirectory(forcefield)
add_subdirectory(gamessinput)
add_subdirectory(hydrogens)
add_subdirectory(importpqr)
add_subdirectory(insertdna)
add_subdirectory(insertfragment)
add_subdirectory(label)
add_subdirectory(lammpsinput)
add_subdirectory(lineformatinput)
add_subdirectory(manipulator)
add_subdirectory(measuretool)
add_subdirectory(molecularproperties)
add_subdirectory(navigator)
add_subdirectory(networkdatabases)
add_subdirectory(openbabel)
add_subdirectory(openmminput)
add_subdirectory(playertool)
add_subdirectory(ply)
add_subdirectory(povray)
add_subdirectory(propertytables)
add_subdirectory(resetview)
add_subdirectory(select)
add_subdirectory(selectiontool)
if(USE_SPGLIB)
  add_subdirectory(spacegroup)
endif()
add_subdirectory(surfaces)
add_subdirectory(svg)
add_subdirectory(templatetool)
add_subdirectory(vibrations)
add_subdirectory(vrml)

# Plugins that require plotting
add_subdirectory(spectra)
add_subdirectory(plotpdf)
add_subdirectory(plotrmsd)
add_subdirectory(plotxrd)
if(USE_SPGLIB)
  add_subdirectory(yaehmop)
endif()

# script plugins (input generators, etc.)
add_subdirectory(commandscripts)
add_subdirectory(quantuminput)
add_subdirectory(scriptcharges)
add_subdirectory(scriptfileformats)

if(USE_LIBARCHIVE)
  add_subdirectory(plugindownloader)
endif()

if(USE_LIBMSYM)
  add_subdirectory(symmetry)
endif()

# The scene plugins
add_subdirectory(ballandstick)
add_subdirectory(cartoons)
add_subdirectory(closecontacts)
add_subdirectory(force)
add_subdirectory(licorice)
add_subdirectory(surfacerender)
add_subdirectory(noncovalent)
add_subdirectory(vanderwaals)
add_subdirectory(wireframe)
if (USE_OPENGL)
  # needs some raw OpenGL code
  add_subdirectory(overlayaxes)
endif()

# other optional plugins
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
add_library(QtPlugins)
avogadro_headers(QtPlugins
  pluginmanager.h
  pluginfactory.h
  "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h"
)

target_sources(QtPlugins PRIVATE
  pluginmanager.cpp
)

avogadro_add_library(QtPlugins ${HEADERS} ${SOURCES})
target_link_libraries(QtPlugins PUBLIC Qt::Core
  PRIVATE ${AvogadroLibs_STATIC_PLUGINS} Avogadro::QtGui Avogadro::Calc)

if(QT_VERSION EQUAL 6)
  target_link_libraries(QtPlugins PRIVATE Qt6::OpenGLWidgets Qt6::Network)
endif()
