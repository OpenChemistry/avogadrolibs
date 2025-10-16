/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/aligntool/aligntool.h"


namespace Avogadro::QtPlugins {

class AlignToolFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit AlignToolFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new AlignTool(parent_);
    object->setObjectName("AlignTool");
    return object;
  }

  QString identifier() const override { return "AlignTool"; }

  QString description() const override { return "AlignTool"; }

};

} // namespace Avogadro::QtPlugins

#include "AlignToolPlugin.moc"
