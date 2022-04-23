find_package(Qt5 COMPONENTS Widgets Network REQUIRED)

set(HEADERS
  batchjob.h
  inputgenerator.h
  inputgeneratordialog.h
  inputgeneratorwidget.h
  molequeuedialog.h
  molequeuemanager.h
  molequeuequeuelistmodel.h
  molequeuewidget.h
)

set(SOURCES
  batchjob.cpp
  inputgenerator.cpp
  inputgeneratordialog.cpp
  inputgeneratorwidget.cpp
  molequeuedialog.cpp
  molequeuemanager.cpp
  molequeuequeuelistmodel.cpp
  molequeuewidget.cpp
  client/client.cpp
  client/jobobject.cpp
  client/jsonrpcclient.cpp
)

set(UIS
  inputgeneratordialog.ui
  inputgeneratorwidget.ui
  molequeuedialog.ui
  molequeuewidget.ui
)
qt5_wrap_ui(UI_SOURCES ${UIS})
list(APPEND SOURCES ${UI_SOURCES})

avogadro_add_library(AvogadroMoleQueue ${HEADERS} ${SOURCES})
set_target_properties(AvogadroMoleQueue PROPERTIES AUTOMOC TRUE)
target_link_libraries(AvogadroMoleQueue AvogadroQtGui Qt5::Widgets Qt5::Network)
