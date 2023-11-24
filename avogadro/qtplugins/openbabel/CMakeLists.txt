if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS Core5Compat REQUIRED)
endif()

set(openbabel_srcs
  obcharges.cpp
  obfileformat.cpp
  obforcefielddialog.cpp
  obprocess.cpp
  openbabel.cpp
)

set(openbabel_uis
  obforcefielddialog.ui
)

avogadro_plugin(OpenBabel
  "OpenBabel extension"
  ExtensionPlugin
  openbabel.h
  OpenBabel
  "${openbabel_srcs}"
  "${openbabel_uis}"
)

target_link_libraries(OpenBabel PRIVATE Avogadro::IO Avogadro::Calc nlohmann_json::nlohmann_json)
if(QT_VERSION EQUAL 6)
  target_link_libraries(OpenBabel PRIVATE Qt6::Core5Compat)
endif()
