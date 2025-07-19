if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS Widgets Network REQUIRED)
else()
  find_package(Qt5 COMPONENTS Widgets Network REQUIRED)
endif()

add_library(MoleQueue)

avogadro_headers(MoleQueue
  batchjob.h
  inputgenerator.h
  inputgeneratordialog.h
  inputgeneratorwidget.h
  molequeuedialog.h
  molequeuemanager.h
  molequeuequeuelistmodel.h
  molequeuewidget.h
)

target_sources(MoleQueue PRIVATE
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
qt_wrap_ui(UI_SOURCES ${UIS})
target_sources(MoleQueue PRIVATE ${UI_SOURCES})

avogadro_add_library(MoleQueue ${HEADERS} ${SOURCES})
set_target_properties(MoleQueue PROPERTIES AUTOMOC TRUE)
target_link_libraries(MoleQueue PUBLIC Avogadro::QtGui Qt::Widgets Qt::Network)
