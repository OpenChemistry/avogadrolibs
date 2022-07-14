include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(InsertFragment
  "Insert oligopeptide chains"
  ExtensionPlugin
  insertpeptide.h
  InsertFragment
  insertpeptide.cpp
  insertpeptidedialog.ui
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fragments"
DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
PATTERN ".git" EXCLUDE
)
