avogadro_plugin(Label
  "Labels rendering scheme"
  ScenePlugin
  label.h
  Label
  label.cpp
  "")

set(label_rcs
  label.qrc
)

set(label_srcs
  labeleditor.cpp
)

avogadro_plugin(LabelEditor
  "Labels rendering scheme"
  ToolPlugin
  labeleditor.h
  LabelEditor
  "${label_srcs}"
  ""
  "${label_rcs}"
)

target_link_libraries(Label LINK_PRIVATE Avogadro::Rendering)
target_link_libraries(Label PRIVATE Avogadro::Calc)

target_link_libraries(LabelEditor
  LINK_PRIVATE
    Avogadro::Rendering
    Avogadro::QtOpenGL)

target_include_directories(LabelEditor
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../rendering
    ${CMAKE_CURRENT_BINARY_DIR}/../../qtopengl)
