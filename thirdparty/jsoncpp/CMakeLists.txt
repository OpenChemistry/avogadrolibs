add_library(jsoncpp STATIC jsoncpp.cpp)
set_target_properties(jsoncpp PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
# The code below is necessary for Windows if building a DLL for JsonCpp
#if(WIN32)
#  target_compile_definitions(jsoncpp
#    PRIVATE JSON_DLL_BUILD
#    INTERFACE JSON_DLL)
#endif()
install(TARGETS jsoncpp
  EXPORT "AvogadroLibsTargets"
  RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
  LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}"
  ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}")
