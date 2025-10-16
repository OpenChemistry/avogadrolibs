/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/editor/editor.h"


namespace Avogadro::QtPlugins {

class EditorFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit EditorFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Editor(parent_);
    object->setObjectName("Editor");
    return object;
  }

  QString identifier() const override { return "Editor"; }

  QString description() const override { return "Editor tool"; }

};

} // namespace Avogadro::QtPlugins

#include "EditorPlugin.moc"
