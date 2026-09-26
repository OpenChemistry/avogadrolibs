# Specify the name of each test (the Test will be appended where needed).
set(tests
  Camera
  Node
  SphereGeometry
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
target_link_libraries(AvogadroRenderingTests Avogadro::Rendering
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
    add_executable(AvogadroGLRendererTests glrenderertest.cpp)
    target_link_libraries(AvogadroGLRendererTests PRIVATE Avogadro::Rendering
      OpenGL::EGL GLEW::GLEW ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})
    add_test(NAME Rendering-GLRenderer COMMAND AvogadroGLRendererTests)
  endif()
endif()
