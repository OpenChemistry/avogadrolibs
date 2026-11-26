# Fail any registered test that runs no gtest cases (see tests/CMakeLists.txt).
cmake_language(DEFER CALL avogadro_fail_on_empty_gtest)

include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/qtgui"
  "${AvogadroLibs_BINARY_DIR}/avogadro/rendering"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtopengl"
  "${CMAKE_CURRENT_SOURCE_DIR}")

find_package(Qt${QT_VERSION} COMPONENTS Widgets REQUIRED)

# Specify the name of each test (the Test will be appended where needed).
set(tests
  GLWidget
  GLWidgetSettings
  RendererTeardown
  QtTextLabel
  QtTextRenderStrategy
)

set(testSrcs gltesthelpers.cpp)
foreach(TestName ${tests})
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()

# One executable for all of the suites.
add_executable(AvogadroQtOpenGLTests ${testSrcs})
target_link_libraries(AvogadroQtOpenGLTests
  Avogadro::QtOpenGL
  Qt${QT_VERSION}::Widgets
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Use gtest_filter so that only one suite runs in each test invocation. The GL
# suites skip when there is no usable OpenGL context; the text render strategy
# does not need one.
foreach(TestName ${tests})
  add_test(NAME "QtOpenGL-${TestName}"
    COMMAND AvogadroQtOpenGLTests "--gtest_filter=${TestName}Test.*")
endforeach()
