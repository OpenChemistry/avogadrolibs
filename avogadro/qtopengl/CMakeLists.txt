find_package(Qt5 COMPONENTS Widgets REQUIRED)

set(HEADERS
  activeobjects.h
  glwidget.h
  qttextrenderstrategy.h
)

set(SOURCES
  activeobjects.cpp
  glwidget.cpp
  qttextrenderstrategy.cpp
)

avogadro_add_library(AvogadroQtOpenGL ${HEADERS} ${SOURCES})
target_link_libraries(AvogadroQtOpenGL AvogadroRendering AvogadroQtGui Qt5::Widgets)
