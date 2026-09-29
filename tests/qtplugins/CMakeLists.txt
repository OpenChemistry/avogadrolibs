find_package(Qt${QT_VERSION} REQUIRED COMPONENTS Test)
set(editor_source_dir "${AvogadroLibs_SOURCE_DIR}/avogadro/qtplugins/editor")
add_executable(AvogadroEditorTests
  editortest.cpp
  "${editor_source_dir}/editor.cpp"
  "${editor_source_dir}/editor.h"
  "${editor_source_dir}/editortoolwidget.cpp"
  "${editor_source_dir}/editortoolwidget.h"
  "${editor_source_dir}/editortoolwidget.ui")
set_target_properties(AvogadroEditorTests PROPERTIES AUTOMOC TRUE AUTOUIC TRUE)
target_include_directories(AvogadroEditorTests PRIVATE "${editor_source_dir}")
target_link_libraries(AvogadroEditorTests PRIVATE Avogadro::QtOpenGL
  Qt${QT_VERSION}::Test ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})
add_test(NAME QtPlugins-Editor COMMAND AvogadroEditorTests)
set_tests_properties(QtPlugins-Editor PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
