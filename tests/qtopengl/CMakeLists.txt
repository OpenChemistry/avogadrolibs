# Specify the name of each test (the Test will be appended where needed).
set(tests
  Camera
  Node
  SphereGeometry
  )

find_package(OpenGL REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR})

find_package(Qt4 COMPONENTS QtCore QtGui QtOpenGL REQUIRED)
include_directories(SYSTEM ${QT_INCLUDES})
add_definitions(${QT_DEFINITIONS})

# We want to find some parts of VTK in order to do image comparisons.
find_package(VTK COMPONENTS vtkImagingCore vtkRenderingQt NO_MODULE REQUIRED)
include_directories(SYSTEM ${VTK_INCLUDE_DIRS})

include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/rendering"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtopengl")

if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
else()
  message("No data root found, please set to run the tests.")
  return()
endif()

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()
message(STATUS "Test source files: ${testSrcs}")

# Add a single executable for all of our tests.
add_executable(AvogadroQtOpenGLTests ${testSrcs})
target_link_libraries(AvogadroQtOpenGLTests AvogadroQtOpenGL
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "${TestName}Test"
    COMMAND AvogadroQtOpenGLTests "--gtest_filter=${TestName}Test.*")
endforeach()

add_executable(AvogadroQtOpenGLCxx glwidgettest.cpp)

target_link_libraries(AvogadroQtOpenGLCxx
  AvogadroQtOpenGL
  vtkImagingCore
  vtkRenderingQt
  ${QT_QTGUI_LIBRARY})
