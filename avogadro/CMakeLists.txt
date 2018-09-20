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
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
  # Now install everything.
  string(REGEX REPLACE "^avogadro" "" module ${lowerName})

  if (NOT BUILD_BINARY_WHEEL)
    install(FILES ${HEADERS}
      DESTINATION "${INSTALL_INCLUDE_DIR}/avogadro/${module}")
  else()
    set(INSTALL_RUNTIME_DIR avogadro)
    set(INSTALL_LIBRARY_DIR avogadro)
    set(INSTALL_ARCHIVE_DIR avogadro)
  endif()

  install(TARGETS ${name}
    EXPORT "AvogadroLibsTargets"
    RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}"
    ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}")
endfunction()

add_subdirectory(core)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/core)

add_subdirectory(io)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/io)
add_subdirectory(quantumio)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/quantumio)
if (NOT BUILD_BINARY_WHEEL)
  add_subdirectory(command)
endif()
if(USE_OPENGL)
  add_subdirectory(rendering)
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/rendering)
endif()

if(USE_QT)
  add_subdirectory(qtgui)
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/qtgui)
  if(USE_OPENGL)
    add_subdirectory(qtopengl)
    include_directories(${CMAKE_CURRENT_BINARY_DIR}/qtopengl)
  endif()
  if(USE_MOLEQUEUE)
    add_subdirectory(molequeue)
    include_directories(${CMAKE_CURRENT_BINARY_DIR}/molequeue)
  endif()
  if(USE_VTK)
    add_subdirectory(vtk)
    include_directories(${CMAKE_CURRENT_BINARY_DIR}/vtk)
  endif()
  add_subdirectory(qtplugins)
endif()

if(USE_PROTOCALL)
  add_subdirectory(protocall)
endif()
