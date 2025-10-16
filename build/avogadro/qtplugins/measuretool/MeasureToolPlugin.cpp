/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/measuretool/measuretool.h"


namespace Avogadro::QtPlugins {

class MeasureToolFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit MeasureToolFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new MeasureTool(parent_);
    object->setObjectName("MeasureTool");
    return object;
  }

  QString identifier() const override { return "MeasureTool"; }

  QString description() const override { return "Measure tool"; }

};

} // namespace Avogadro::QtPlugins

#include "MeasureToolPlugin.moc"
