add_library(gwavi STATIC gwavi.c fileio.c avi-utils.c)
set_target_properties(gwavi PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
target_include_directories(gwavi PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
install(TARGETS gwavi
  EXPORT "AvogadroLibsTargets"
  RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}/avogadro2"
  LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2"
  ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}/avogadro2")
