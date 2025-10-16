/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/label/labeleditor.h"


namespace Avogadro::QtPlugins {

class LabelEditorFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit LabelEditorFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new LabelEditor(parent_);
    object->setObjectName("LabelEditor");
    return object;
  }

  QString identifier() const override { return "LabelEditor"; }

  QString description() const override { return "Labels rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "LabelEditorPlugin.moc"
