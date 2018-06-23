add_library(libgwavi STATIC gwavi.c fileio.c avi-utils.c)
set_target_properties(libgwavi PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

install(TARGETS libgwavi
  EXPORT "AvogadroLibsTargets"
  RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
  LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}"
  ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}")