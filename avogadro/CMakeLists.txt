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

add_subdirectory(core)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/core)
add_subdirectory(io)
add_subdirectory(rendering)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/rendering)
add_subdirectory(qtgui)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/qtgui)
add_subdirectory(qtopengl)
add_subdirectory(qtplugins)
