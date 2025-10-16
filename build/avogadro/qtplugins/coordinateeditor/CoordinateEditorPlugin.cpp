/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/coordinateeditor/coordinateeditor.h"


namespace Avogadro::QtPlugins {

class CoordinateEditorFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit CoordinateEditorFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new CoordinateEditor(parent_);
    object->setObjectName("CoordinateEditor");
    return object;
  }

  QString identifier() const override { return "CoordinateEditor"; }

  QString description() const override { return "Show a window with a free-text coordinate editor."; }

};

} // namespace Avogadro::QtPlugins

#include "CoordinateEditorPlugin.moc"
