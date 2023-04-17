include(GenerateExportHeader)

function(avogadro_add_library name)
  add_library(${name} ${ARGN})
  # Use the new AUTOMOC support for Qt libraries (CMake 2.8.6).
  if(${name} MATCHES "^AvogadroQt")
    set_target_properties(${name} PROPERTIES AUTOMOC TRUE)
  endif()
  if(BUILD_SHARED_LIBS)
  set_target_properties(${name} PROPERTIES VERSION "${AvogadroLibs_VERSION_MAJOR}.${AvogadroLibs_VERSION_MINOR}.${AvogadroLibs_VERSION_PATCH}"
   					   SOVERSION ${AvogadroLibs_VERSION_MAJOR})
  endif()
  string(TOLOWER ${name} lowerName)
  # Generate the necessary export headers.
  generate_export_header(${name} EXPORT_FILE_NAME ${lowerName}export.h)
  list(APPEND HEADERS "${CMAKE_CURRENT_BINARY_DIR}/${lowerName}export.h")
  target_include_directories(${name}
                             PUBLIC
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
                               "$<INSTALL_INTERFACE:${INSTALL_INCLUDE_DIR}>")
  # Now install everything.
  string(REGEX REPLACE "^avogadro" "" module ${lowerName})

  # SKBUILD is set for binary wheel
  if (NOT SKBUILD)
    install(FILES ${HEADERS}
      DESTINATION "${INSTALL_INCLUDE_DIR}/avogadro/${module}")
  else()
    # For MACOSX
    set_target_properties(${name} PROPERTIES INSTALL_NAME_DIR "@rpath")
    set(INSTALL_RUNTIME_DIR avogadro)
    set(INSTALL_LIBRARY_DIR avogadro)
    set(INSTALL_ARCHIVE_DIR avogadro)
  endif()

  install(TARGETS ${name}
    EXPORT "AvogadroLibsTargets"
    RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}"
    ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}"
    INCLUDES DESTINATION "${INSTALL_INCLUDE_DIR}")
endfunction()

add_subdirectory(core)
add_subdirectory(calc)
add_subdirectory(io)
add_subdirectory(quantumio)
# SKBUILD is set for binary wheel
if (NOT SKBUILD)
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
