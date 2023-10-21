include(GenerateExportHeader)

# May want to adjust the name, this more performs boilerplate library stuff now.
function(avogadro_add_library name)
  # Add an alias target to expose to other targets.
  add_library(Avogadro::${name} ALIAS ${name})
  # Use the new AUTOMOC support for Qt libraries (CMake 2.8.6).
  if(${name} MATCHES "^Qt")
    set_target_properties(${name} PROPERTIES AUTOMOC TRUE)
  endif()
  if(BUILD_SHARED_LIBS)
  set_target_properties(${name}
    PROPERTIES
      OUTPUT_NAME Avogadro${name}
      VERSION "${AvogadroLibs_VERSION_MAJOR}.${AvogadroLibs_VERSION_MINOR}.${AvogadroLibs_VERSION_PATCH}"
      SOVERSION ${AvogadroLibs_VERSION_MAJOR})
  endif()
  string(TOLOWER ${name} _lower_name)
  string(TOUPPER ${name} _upper_name)
  # Generate the necessary export headers.
  generate_export_header(${name}
    BASE_NAME AVOGADRO${_upper_name}
    EXPORT_FILE_NAME avogadro${_lower_name}export.h)
  target_sources(${name} PUBLIC FILE_SET HEADERS
    FILES "${CMAKE_CURRENT_BINARY_DIR}/avogadro${_lower_name}export.h")
  # Set up the build and install include directories for the target.
  target_include_directories(${name}
    PUBLIC
      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
      "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>"
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
      "$<INSTALL_INTERFACE:${INSTALL_INCLUDE_DIR}>")

  # Install the target and its headers.
  install(TARGETS ${name}
    EXPORT "AvogadroLibsTargets"
    FILE_SET HEADERS DESTINATION "${INSTALL_INCLUDE_DIR}/avogadro"
    RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}"
    ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}"
    INCLUDES DESTINATION "${INSTALL_INCLUDE_DIR}")
endfunction()

# Simple wrapper to collect boilerplate for adding headers to targets.
function(avogadro_headers _name)
  target_sources(${_name} PUBLIC
    FILE_SET HEADERS
    BASE_DIRS
      ${AvogadroLibs_SOURCE_DIR}/avogadro
      ${AvogadroLibs_BINARY_DIR}/avogadro
    FILES ${ARGN})
endfunction()

add_subdirectory(core)
add_subdirectory(calc)
add_subdirectory(io)
add_subdirectory(quantumio)
# SKBUILD is set for binary wheel
if(NOT SKBUILD)
  add_subdirectory(command)
endif()
if(USE_OPENGL)
  add_subdirectory(rendering)
endif()

if(USE_QT)
  if (NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
  endif()

  add_subdirectory(qtgui)
  if(USE_OPENGL)
    add_subdirectory(qtopengl)
  endif()
  # Add unconditionally as this talks to MoleQueue, but doesn't depend on it.
  add_subdirectory(molequeue)
  if(USE_VTK)
    add_subdirectory(vtk)
  endif()
  add_subdirectory(qtplugins)
endif()
