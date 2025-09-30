if(QT_VERSION EQUAL 6)
  find_package(Qt6 REQUIRED COMPONENTS Widgets OpenGLWidgets)
else()
  find_package(Qt5 COMPONENTS Widgets REQUIRED)
endif()

add_library(QtOpenGL)

avogadro_headers(QtOpenGL
  activeobjects.h
  glwidget.h
  qttextrenderstrategy.h
)

target_sources(QtOpenGL PRIVATE
  activeobjects.cpp
  glwidget.cpp
  qttextrenderstrategy.cpp
)

avogadro_add_library(QtOpenGL)
target_link_libraries(QtOpenGL PUBLIC Avogadro::Rendering Avogadro::QtGui Qt::Widgets)
if(QT_VERSION EQUAL 6)
  target_link_libraries(QtOpenGL PUBLIC Qt6::OpenGLWidgets)
endif()
