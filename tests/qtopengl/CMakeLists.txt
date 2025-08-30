include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/qtgui"
  "${AvogadroLibs_BINARY_DIR}/avogadro/rendering"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtopengl"
  "${CMAKE_CURRENT_BINARY_DIR}")

find_package(OpenGL REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR})

find_package(Qt${QT_VERSION} COMPONENTS Widgets REQUIRED)
include_directories(SYSTEM ${Qt${QT_VERSION}Widgets_INCLUDE_DIRS})
add_definitions(${Qt${QT_VERSION}Widgets_DEFINITIONS})

# We want to find some parts of VTK in order to do image comparisons.
# note: VTK 9 introduced breaking change—components are renamed and old names
# do not work any longer since VTK_INCLUDE_DIRS is empty; include path
# will be set via imported targets instead.
find_package(VTK 9
  COMPONENTS ImagingCore RenderingQt IOImage
  NO_MODULE)
if(NOT "${VTK_FOUND}")
  # try to find VTK 8 or prior
  find_package(VTK
    COMPONENTS vtkImagingCore vtkRenderingQt vtkIOImage
    NO_MODULE REQUIRED)
  include_directories(SYSTEM ${VTK_INCLUDE_DIRS})
endif()

if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
else()
  message("No data root found, please set to run the tests.")
  return()
endif()

# Setup config file with data location
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/qtopengltests.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/qtopengltests.h" @ONLY)

# List of tests to be added, the name will be changed to lower case with
# test.cpp appended. The main function of each test is expected to be lower
# cased version with test appended, e.g. GLWidget -> glwidgettest.
set(tests
  GLWidget
  QtTextLabel
  QtTextRenderStrategy
)

foreach(test ${tests})
  string(TOLOWER ${test} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()
create_test_sourcelist(testDriver qtopengltests.cpp ${testSrcs})

add_executable(AvogadroQtOpenGLTests ${testDriver})

if("${VTK_VERSION}" VERSION_GREATER_EQUAL 9)
  target_link_libraries(AvogadroQtOpenGLTests
    Avogadro::QtOpenGL
    VTK::ImagingCore
    VTK::IOImage
    VTK::RenderingQt)
else()
  target_link_libraries(AvogadroQtOpenGLTests
    Avogadro::QtOpenGL
    vtkImagingCore
    vtkIOImage
    vtkRenderingQt)
endif()

foreach(test ${tests})
  string(TOLOWER ${test} testname)
  add_test(NAME "QtOpenGL-${test}"
    COMMAND
      AvogadroQtOpenGLTests "${testname}test"
      "--baseline" "${AVOGADRO_DATA_ROOT}/baselines/avogadro/qtopengl"
      "--temporary" "${PROJECT_BINARY_DIR}/Testing/Temporary")
endforeach()
