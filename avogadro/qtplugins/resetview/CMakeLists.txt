if(QT_VERSION EQUAL 6)
  find_package(Qt6 REQUIRED COMPONENTS OpenGLWidgets)
endif()

avogadro_plugin(ResetView
  "Manipulate the view camera."
  ExtensionPlugin
  resetview.h
  ResetView
  "resetview.cpp"
  ""
)

target_link_libraries(ResetView PRIVATE Avogadro::QtOpenGL)

if(QT_VERSION EQUAL 6)
  target_link_libraries(ResetView
    PRIVATE
      Qt6::OpenGLWidgets)
endif()
