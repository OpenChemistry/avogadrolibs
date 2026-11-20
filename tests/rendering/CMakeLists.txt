# Specify the name of each test (the Test will be appended where needed).
set(tests
  BezierGeometry
  BSplineGeometry
  Camera
  CartoonDetail
  CartoonProteins
  CurveGeometry
  CurveTessellation
  CylinderGeometry
  GLRenderer
  GeometryVisitor
  GltfVisitor
  Node
  PLYVisitor
  SphereGeometry
  TessellatingVisitor
  )

find_package(OpenGL REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR})

include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/rendering")

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()
message(STATUS "Test source files: ${testSrcs}")

# Add a single executable for all of our tests.
add_executable(AvogadroRenderingTests ${testSrcs})
# cartoondetail.h is a Qt-free header of the Cartoons plugin.
target_include_directories(AvogadroRenderingTests PRIVATE
  "${AvogadroLibs_SOURCE_DIR}/avogadro/qtplugins/cartoons")
target_compile_definitions(AvogadroRenderingTests PRIVATE
  AVOGADRO_DATA="${AVOGADRO_DATA_ROOT}")
target_link_libraries(AvogadroRenderingTests Avogadro::Rendering Avogadro::IO
  nlohmann_json::nlohmann_json
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "Rendering-${TestName}"
    COMMAND AvogadroRenderingTests "--gtest_filter=${TestName}Test.*")
endforeach()

# Exercise the actual offscreen pipeline on Linux without requiring a display.
# EGL remains an optional test dependency; other platforms keep the pure tests.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(OpenGL QUIET COMPONENTS EGL)
  if(TARGET OpenGL::EGL)
    find_package(GLEW REQUIRED)
    add_executable(AvogadroSolidPipelineTests solidpipelinetest.cpp)
    target_link_libraries(AvogadroSolidPipelineTests PRIVATE Avogadro::Rendering
      OpenGL::EGL GLEW::GLEW ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})
    add_test(NAME Rendering-SolidPipeline COMMAND AvogadroSolidPipelineTests)

    add_executable(AvogadroShaderLinkTests shaderlinktest.cpp)
    target_link_libraries(AvogadroShaderLinkTests PRIVATE Avogadro::Rendering
      OpenGL::EGL GLEW::GLEW ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})
    add_test(NAME Rendering-ShaderLink COMMAND AvogadroShaderLinkTests)

    # Avoid Mesa software rasterizer and disk cache worker threads in EGL tests.
    set_tests_properties(Rendering-SolidPipeline Rendering-ShaderLink PROPERTIES
      ENVIRONMENT "LP_NUM_THREADS=0;MESA_SHADER_CACHE_DISABLE=true")
  endif()
endif()
