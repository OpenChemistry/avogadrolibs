add_library(gwavi STATIC gwavi.c fileio.c avi-utils.c)
set_target_properties(gwavi PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

install(TARGETS gwavi
  EXPORT "AvogadroLibsTargets"
  RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}/avogadro2"
  LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2"
  ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}/avogadro2")
