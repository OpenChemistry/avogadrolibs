include(GenerateExportHeader)

function(avogadro_add_library name)
  add_library(${name} ${ARGN})
  # Use the new AUTOMOC support for Qt libraries (CMake 2.8.6).
  if(${name} MATCHES "^AvogadroQt")
    set_target_properties(${name} PROPERTIES AUTOMOC TRUE)
    message("Using automoc for Qt library")
  endif()
  string(TOLOWER ${name} lowerName)
  # Generate the necessary export headers.
  generate_export_header(${name} EXPORT_FILE_NAME ${lowerName}export.h)
  list(APPEND HEADERS "${CMAKE_CURRENT_BINARY_DIR}/${lowerName}export.h")
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
  add_compiler_export_flags(avogadro_export_flags)
  # Use visibility support where available.
  add_compiler_export_flags(avogadro_export_flags)
  set_property(TARGET ${name} APPEND
    PROPERTY COMPILE_FLAGS ${avogadro_export_flags})
  # Now install everything.
  string(REGEX REPLACE "^avogadro" "" module ${lowerName})
  install(FILES ${HEADERS}
    DESTINATION "${INSTALL_INCLUDE_DIR}/avogadro/${module}")
  install(TARGETS ${name}
    EXPORT "AvogadroLibsTargets"
    RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}"
    ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}")
endfunction()

option(USE_OPENGL "Enable libraries that use OpenGL" ON)
option(USE_QT "Enable libraries that use Qt 4" ON)
option(USE_VTK "Enable libraries that use VTK" ON)
option(USE_PROTOCALL "Enable libraries that use ProtoCall" OFF)

add_subdirectory(stl)
add_subdirectory(core)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/core)

add_subdirectory(io)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/io)
add_subdirectory(quantumio)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/quantumio)

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
  add_subdirectory(qtplugins)
endif()

if(USE_VTK)
  add_subdirectory(vtk)
endif()
if(USE_PROTOCALL)
  add_subdirectory(protocall)
endif()
