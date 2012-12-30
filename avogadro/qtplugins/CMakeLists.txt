find_package(Eigen3 REQUIRED)
find_package(Qt4 COMPONENTS QtCore REQUIRED)
include_directories(SYSTEM ${QT_INCLUDES} ${EIGEN3_INCLUDE_DIR})
add_definitions(${QT_DEFINITIONS})

# Modify the output directory for the build tree.
set(original_library_output_dir "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  "${original_library_output_dir}/avogadro2/plugins")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  "${original_library_output_dir}/avogadro2/staticplugins")

# Optionally build all plugins statically.
option(BUILD_STATIC_PLUGINS "Build plugins statically by default" OFF)

# Create a plugin for Avogadro.
# name is the name of the plugin, this will be the name of the target created.
# description Free text description of the plugin.
# type The base class of the plugin.
# header is the header(s) for the class to be instantiated for the plugin.
# pluginClass is the class to be instantiated for the plugin.
# sources is the list of source files for the plugin.
# uis is the list of UI files that need to be compiled (optional).
function(avogadro_plugin name description type header pluginClass sources uis)
  qt4_wrap_ui(ui_srcs ${uis})
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
  else()
    set(_plugin_object "MODULE")
    set_property(GLOBAL APPEND PROPERTY AvogadroLibs_PLUGINS ${name})
  endif()

  add_library(${name} ${_plugin_object} ${sources} ${ui_srcs} ${name}Plugin.cpp)
  target_link_libraries(${name} AvogadroCore AvogadroQtGui)

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
add_subdirectory(ballandstick)
add_subdirectory(molecularproperties)
add_subdirectory(quantuminput)
add_subdirectory(quantumoutput)
add_subdirectory(vanderwaals)
add_subdirectory(meshes)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${original_library_output_dir}")

# Add all of the static plugins to the initialization file.
get_property(AvogadroLibs_STATIC_PLUGINS GLOBAL
  PROPERTY AvogadroLibs_STATIC_PLUGINS)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h"
  "// Automatically generated file. Do not edit.
#ifndef AVOGADRO_STATIC_QTPLUGINS_H
#define AVOGADRO_STATIC_QTPLUGINS_H

#include <QtCore/QtPlugin>\n\n")

foreach(_plugin ${AvogadroLibs_STATIC_PLUGINS})
  file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h"
    "Q_IMPORT_PLUGIN(${_plugin})\n")
endforeach()

file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h"
  "\n#endif // AVOGADRO_STATIC_QTPLUGINS_H\n")

# Now to build the plugin library, which can also statically link plugins
# and initialize them for the application. If Avogadro is built statically
# then the static plugin header must be included by the application.
set(HEADERS
  pluginmanager.h
  "${CMAKE_CURRENT_BINARY_DIR}/avogadrostaticqtplugins.h"
)

set(SOURCES
  pluginmanager.cpp
)

avogadro_add_library(AvogadroQtPlugins ${HEADERS} ${SOURCES})
target_link_libraries(AvogadroQtPlugins LINK_PUBLIC ${QT_QTCORE_LIBRARY}
  LINK_PRIVATE ${AvogadroLibs_STATIC_PLUGINS})
