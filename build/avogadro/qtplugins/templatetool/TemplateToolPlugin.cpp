/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/templatetool/templatetool.h"


namespace Avogadro::QtPlugins {

class TemplateToolFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit TemplateToolFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new TemplateTool(parent_);
    object->setObjectName("TemplateTool");
    return object;
  }

  QString identifier() const override { return "TemplateTool"; }

  QString description() const override { return "Template tool"; }

};

} // namespace Avogadro::QtPlugins

#include "TemplateToolPlugin.moc"
