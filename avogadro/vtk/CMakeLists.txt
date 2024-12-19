find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)

if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

find_package(Qt${QT_VERSION} COMPONENTS Widgets REQUIRED)

find_package(VTK
  COMPONENTS
  RenderingOpenGL2 GUISupportQt DomainsChemistry
  RenderingVolumeOpenGL2 ViewsCore RenderingFreeType
  ChartsCore ViewsContext2D RenderingContextOpenGL2
  REQUIRED)

add_library(Vtk)

avogadro_headers(Vtk
  chartdialog.h
  chartwidget.h
  qvtkwidget.h
  vtkAvogadroActor.h
  vtkglwidget.h
)

target_sources(Vtk PRIVATE
  chartdialog.cpp
  chartwidget.cpp
  qvtkwidget.cpp
  vtkAvogadroActor.cpp
  vtkglwidget.cpp
)

avogadro_add_library(Vtk ${HEADERS} ${SOURCES})
set_target_properties(Vtk PROPERTIES AUTOMOC TRUE)
target_link_libraries(Vtk PUBLIC Avogadro::Rendering Avogadro::QtGui
  VTK::RenderingOpenGL2 VTK::GUISupportQt VTK::RenderingVolumeOpenGL2
  VTK::RenderingFreeType VTK::InteractionStyle VTK::ChartsCore VTK::ViewsContext2D
  VTK::RenderingContextOpenGL2 VTK::DomainsChemistryOpenGL2 Qt::Widgets
  PRIVATE GLEW::GLEW OpenGL::GL)

vtk_module_autoinit(TARGETS Vtk MODULES
  VTK::RenderingOpenGL2 VTK::GUISupportQt VTK::RenderingVolumeOpenGL2
  VTK::RenderingFreeType VTK::InteractionStyle VTK::ChartsCore VTK::ViewsContext2D
  VTK::RenderingContextOpenGL2 VTK::DomainsChemistryOpenGL2)
