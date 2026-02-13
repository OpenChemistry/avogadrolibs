if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS Widgets Concurrent REQUIRED)
endif()

# Provide some simple API to find the plugins, scripts, etc.
if(APPLE)
  # It is a special case, the app bundle logic breaks the relative pathing.
  add_definitions(-DAvogadroLibs_LIB_DIR=\"lib\")
  add_definitions(-DAvogadroLibs_DATA_DIR=\"share\")
else()
  add_definitions(-DAvogadroLibs_LIB_DIR=\"${INSTALL_LIBRARY_DIR}\")
  add_definitions(-DAvogadroLibs_DATA_DIR=\"${INSTALL_DATA_DIR}\")
endif()

if(USE_SPGLIB)
  add_definitions(-DUSE_SPGLIB)
endif()

# Find python for input generator scripts:
find_package(Python3 COMPONENTS Interpreter)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/avogadropython.h.in"
"namespace Avogadro {
static const char *pythonInterpreterPath = \"${Python3_EXECUTABLE}\";
}
")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/avogadropython.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/avogadropython.h")

add_library(QtGui)

if(USE_PLOTTER)
  find_package(JKQTPlotter${QT_VERSION} REQUIRED)
endif()

avogadro_headers(QtGui
  backgroundfileformat.h
  colorbutton.h
  containerwidget.h
  customelementdialog.h
  elementtranslator.h
  extensionplugin.h
  filebrowsewidget.h
  fileformatdialog.h
  gaussiansetconcurrent.h
  generichighlighter.h
  hydrogentools.h
  insertfragmentdialog.h
  interfacescript.h
  interfacewidget.h
  jsonwidget.h
  layermodel.h
  rwlayermanager.h
  meshgenerator.h
  molecule.h
  moleculemodel.h
  multiviewwidget.h
  packagemanager.h
  periodictableview.h
  persistentatom.h
  persistentbond.h
  pluginlayermanager.h
  pythonscript.h
  richtextdelegate.h
  rwmolecule.h
  sceneplugin.h
  scenepluginmodel.h
  scriptloader.h
  slatersetconcurrent.h
  sortfiltertreeproxymodel.h
  timedprogressdialog.h
  toolplugin.h
  utilities.h
  viewfactory.h
)

target_sources(QtGui PRIVATE
  backgroundfileformat.cpp
  colorbutton.cpp
  containerwidget.cpp
  customelementdialog.cpp
  elementdetail_p.cpp
  elementitem_p.cpp
  elementtranslator.cpp
  extensionplugin.cpp
  filebrowsewidget.cpp
  fileformatdialog.cpp
  gaussiansetconcurrent.cpp
  generichighlighter.cpp
  hydrogentools.cpp
  insertfragmentdialog.cpp
  interfacescript.cpp
  interfacewidget.cpp
  jsonwidget.cpp
  layermodel.cpp
  richtextdelegate.cpp
  rwlayermanager.cpp
  meshgenerator.cpp
  molecule.cpp
  moleculemodel.cpp
  multiviewwidget.cpp
  packagemanager.cpp
  periodictablescene_p.cpp
  periodictableview.cpp
  pluginlayermanager.cpp
  pythonscript.cpp
  rwmolecule.cpp
  sceneplugin.cpp
  scenepluginmodel.cpp
  scriptloader.cpp
  slatersetconcurrent.cpp
  sortfiltertreeproxymodel.cpp
  timedprogressdialog.cpp
  toolplugin.cpp
  utilities.cpp
  viewfactory.cpp
)

set(UIS
  customelementdialog.ui
  insertfragmentdialog.ui
)
qt_wrap_ui(UI_SOURCES ${UIS})
target_sources(QtGui PRIVATE ${UI_SOURCES})

set(RCS
  qtgui.qrc
)
qt_add_resources(RC_SOURCES ${RCS})
target_sources(QtGui PRIVATE ${RC_SOURCES})

if(USE_PLOTTER)
  avogadro_headers(QtGui
    chartdialog.h
    chartwidget.h
  )
  target_sources(QtGui PRIVATE
    chartdialog.cpp
    chartwidget.cpp
  )
endif()

avogadro_add_library(QtGui)
target_link_libraries(QtGui PUBLIC Avogadro::IO Qt::Widgets Qt::Concurrent
  PRIVATE tomlplusplus::tomlplusplus)
if(USE_PLOTTER)
  target_link_libraries(QtGui PUBLIC JKQTPlotter${QT_VERSION}::JKQTPlotter${QT_VERSION})
  target_compile_definitions(QtGui PUBLIC USE_PLOTTER)
endif()
