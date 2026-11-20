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

include(pluginlist.cmake)

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
