find_package(MoleQueue)
include_directories(${MoleQueue_INCLUDE_DIRS})

if(POLICY CMP0020)
  cmake_policy(SET CMP0020 NEW)
endif()

find_package(VTK REQUIRED)
include(${VTK_USE_FILE})

if(${VTK_VERSION} VERSION_GREATER "6" AND VTK_QT_VERSION VERSION_GREATER "4")
  # Instruct CMake to run moc automatically when needed.
  set(CMAKE_AUTOMOC ON)
  find_package(Qt5Widgets REQUIRED QUIET)
else()
  find_package(Qt4 REQUIRED)
  include(${QT_USE_FILE})
endif()

#find_package(VTK COMPONENTS
#  vtkCommonCore vtkFiltersCore vtkInfovisCore vtkInteractionStyle vtkViewsQt
#  vtkRenderingOpenGL vtkGUISupportQtOpenGL vtkDomainsChemistry
#  vtkRenderingVolumeOpenGL vtkViewsCore vtkRenderingFreeType
#  #vtkHybrid vtkWidgets
#  REQUIRED)

include_directories(SYSTEM ${VTK_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB UI_FILES *.ui)
file(GLOB QT_WRAP *.h)
file(GLOB CXX_FILES *.cpp)

set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS ${VTK_DEFINITIONS})

# Extension
set(plotbands_srcs
  plotbandsdialog.cpp
  #simuneanthighlighter.cpp
  #inputdialog.cpp
  plotbands.cpp
  ./Icons/icons.qrc
)

avogadro_plugin(PlotBands
#  "GAUSSIAN input file generation"
  "SIMUNE ANT.G output plot"
  ExtensionPlugin
  #plotbandsdialog.h
  plotbands.h
  PlotBands
  "${plotbands_srcs}"
  plotbandsdialog.ui
)

set(UIS
  plotbandsdialog.ui
)

if(${VTK_VERSION} VERSION_GREATER "6" AND VTK_QT_VERSION VERSION_GREATER "4")
  qt5_wrap_ui(UISrcs ${UI_FILES} )
  # CMAKE_AUTOMOC in ON so the MOC headers will be automatically wrapped.
  #add_executable(QtBarChart MACOSX_BUNDLE
  #  ${CXX_FILES} ${UISrcs} ${QT_WRAP})
  qt5_use_modules(PlotBands Core Gui)
  target_link_libraries(PlotBands ${VTK_LIBRARIES})
endif()

#qt5_wrap_ui(UI_SOURCES ${UIS})
#list(APPEND SOURCES ${UI_SOURCES})

##avogadro_add_library(PlotBands ${HEADERS} ${SOURCES})
#qt5_use_modules(PlotBands OpenGL)
##set_target_properties(PlotBands PROPERTIES AUTOMOC TRUE)
##target_link_libraries(PlotBands LINK_PRIVATE AvogadroMoleQueue)
#target_link_libraries(PlotBands LINK_PRIVATE AvogadroMoleQueue AvogadroVtk AvogadroRendering AvogadroQtGui
#  vtkCommonCore vtkFiltersCore vtkInfovisCore vtkInteractionStyle vtkViewsQt
#  vtkRenderingOpenGL vtkGUISupportQtOpenGL vtkRenderingVolumeOpenGL vtkRenderingFreeType)
##  vtkHybrid vtkWidgets)
