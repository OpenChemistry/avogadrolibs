include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/qtgui"
  "${AvogadroLibs_BINARY_DIR}/avogadro/rendering"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtopengl"
  "${CMAKE_CURRENT_BINARY_DIR}")

find_package(OpenGL REQUIRED)
include_directories(SYSTEM ${OPENGL_INCLUDE_DIR})

find_package(Qt4 COMPONENTS QtCore QtGui QtOpenGL REQUIRED)
include_directories(SYSTEM ${QT_INCLUDES})
add_definitions(${QT_DEFINITIONS})

# We want to find some parts of VTK in order to do image comparisons.
find_package(VTK COMPONENTS vtkImagingCore vtkRenderingQt NO_MODULE REQUIRED)
include_directories(SYSTEM ${VTK_INCLUDE_DIRS})

if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
else()
  message("No data root found, please set to run the tests.")
  return()
endif()

add_executable(AvogadroQtOpenGLCxx glwidgettest.cpp)

target_link_libraries(AvogadroQtOpenGLCxx
  AvogadroQtOpenGL
  vtkImagingCore
  vtkRenderingQt
  ${QT_QTOPENGL_LIBRARY})
