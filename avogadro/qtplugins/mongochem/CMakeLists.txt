include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Extension
set(srcs
  mongochem.cpp
  mongochemwidget.cpp
  girderrequest.cpp
  configdialog.cpp
  listmoleculesmodel.cpp
  calculationsubmitter.cpp
  calculationwatcher.cpp
  submitcalculationdialog.cpp
)

set(uis
  mongochemwidget.ui
  configdialog.ui
  submitcalculationdialog.ui
)

avogadro_plugin(MongoChem
  "HTTP interface with mongochemserver"
  ExtensionPlugin
  mongochem.h
  MongoChem
  "${srcs}"
  "${uis}"
)

target_link_libraries(MongoChem PRIVATE ${Qt5Network_LIBRARIES})
