if(QT_VERSION EQUAL 6)
  find_package(Qt6
    REQUIRED COMPONENTS
      OpenGL
      OpenGLWidgets)
endif()

avogadro_plugin(PlayerTool
  "Player tool"
  ToolPlugin
  playertool.h
  PlayerTool
  "playertool.cpp"
  ""
  playertool.qrc
)

target_link_libraries(PlayerTool
  PRIVATE
    gwavi
    gif-h
    Avogadro::Rendering
    Avogadro::QtOpenGL)

if(QT_VERSION EQUAL 6)
  target_link_libraries(PlayerTool
    PRIVATE
      Qt6::OpenGL
      Qt6::OpenGLWidgets)
endif()

target_include_directories(PlayerTool
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../rendering
    ${CMAKE_CURRENT_BINARY_DIR}/../../qtopengl)
