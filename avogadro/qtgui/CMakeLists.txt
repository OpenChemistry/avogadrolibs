if(QT_VERSION EQUAL 6)
  find_package(Qt6 COMPONENTS Widgets Core5Compat REQUIRED)
else()
  find_package(Qt5 COMPONENTS Widgets REQUIRED)
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
find_package(PythonInterp 3)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/avogadropython.h.in"
"namespace Avogadro {
static const char *pythonInterpreterPath = \"${PYTHON_EXECUTABLE}\";
}
")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/avogadropython.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/avogadropython.h")

add_library(QtGui)

avogadro_headers(QtGui
  backgroundfileformat.h
  colorbutton.h
  containerwidget.h
  customelementdialog.h
  elementtranslator.h
  extensionplugin.h
  filebrowsewidget.h
  fileformatdialog.h
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
  periodictableview.h
  persistentatom.h
  persistentbond.h
  pluginlayermanager.h
  pythonscript.h
  rwmolecule.h
  sceneplugin.h
  scenepluginmodel.h
  scriptloader.h
  sortfiltertreeproxymodel.h
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
  generichighlighter.cpp
  hydrogentools.cpp
  insertfragmentdialog.cpp
  interfacescript.cpp
  interfacewidget.cpp
  jsonwidget.cpp
  layermodel.cpp
  rwlayermanager.cpp
  meshgenerator.cpp
  molecule.cpp
  moleculemodel.cpp
  multiviewwidget.cpp
  periodictablescene_p.cpp
  periodictableview.cpp
  pluginlayermanager.cpp
  pythonscript.cpp
  rwmolecule.cpp
  sceneplugin.cpp
  scenepluginmodel.cpp
  scriptloader.cpp
  sortfiltertreeproxymodel.cpp
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

avogadro_add_library(QtGui)
target_link_libraries(QtGui PUBLIC Avogadro::IO Qt::Widgets)
if(QT_VERSION EQUAL 6)
  target_link_libraries(QtGui PRIVATE Qt6::Core5Compat)
endif()
